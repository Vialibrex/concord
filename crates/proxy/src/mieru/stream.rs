use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep, sleep_until};
use tokio_util::sync::PollSender;

use super::meta::{MAX_PDU, invalid};
use super::underlay::{Event, Out, Wire};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct Response {
    raw: Vec<u8>,
    done: bool,
}

impl Response {
    fn new() -> Self {
        Response {
            raw: Vec::new(),
            done: false,
        }
    }

    /// Takes the socks5 reply off the front of `data`; the rest is application data.
    fn feed(&mut self, data: &mut Bytes) -> io::Result<()> {
        while !self.done && !data.is_empty() {
            self.raw.push(data.get_u8());
            if self.raw.first().is_some_and(|version| *version != 5) {
                return Err(io::Error::other("invalid socks5 version in the reply"));
            }
            let Some(total) = self.total() else {
                continue;
            };
            if self.raw.len() < total {
                continue;
            }
            self.done = true;
            let code = self.raw.get(1).copied().unwrap_or(1);
            if code != 0 {
                return Err(CoreError::TargetRefused(format!(
                    "server returned socks5 error code {code}"
                ))
                .into());
            }
        }
        Ok(())
    }

    fn total(&self) -> Option<usize> {
        let atyp = self.raw.get(3).copied()?;
        match atyp {
            1 => Some(4 + 4 + 2),
            4 => Some(4 + 16 + 2),
            3 => Some(4 + 1 + usize::from(self.raw.get(4).copied()?) + 2),
            _ => Some(4),
        }
    }
}

struct Shared {
    id: u32,
    underlay: Arc<dyn Wire>,
    opened: AtomicBool,
    head: Mutex<Vec<u8>>,
    closed: AtomicBool,
    ended: AtomicBool,
    started: OnceLock<Instant>,
}

impl Shared {
    fn head(&self) -> MutexGuard<'_, Vec<u8>> {
        lock(&self.head)
    }

    fn open(&self) {
        self.opened.store(true, Ordering::Release);
        let _ = self.started.set(Instant::now());
    }

    fn send_close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.underlay.queue(self.id, Out::Close { id: self.id });
        }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        if *self.opened.get_mut() && !*self.ended.get_mut() {
            self.send_close();
        }
        self.underlay.forget(self.id);
    }
}

fn broken<T>(_: T) -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

struct ReadPart {
    shared: Arc<Shared>,
    events: mpsc::Receiver<Event>,
    pending: Bytes,
    sink: PollSender<Out>,
    response: Response,
    deadline: Option<Pin<Box<Sleep>>>,
    deadline_spent: bool,
}

struct WritePart {
    shared: Arc<Shared>,
    sink: PollSender<Out>,
    fragment: usize,
}

pub(super) struct MieruStream {
    read: ReadPart,
    write: WritePart,
}

impl MieruStream {
    pub(super) fn new(
        id: u32,
        underlay: Arc<dyn Wire>,
        events: mpsc::Receiver<Event>,
        fragment: usize,
    ) -> Self {
        let sink = PollSender::new(underlay.sender(id));
        let shared = Arc::new(Shared {
            id,
            underlay,
            opened: AtomicBool::new(false),
            head: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            started: OnceLock::new(),
        });
        MieruStream {
            read: ReadPart {
                shared: shared.clone(),
                events,
                pending: Bytes::new(),
                sink: sink.clone(),
                response: Response::new(),
                deadline: None,
                deadline_spent: false,
            },
            write: WritePart {
                shared,
                sink,
                fragment,
            },
        }
    }

    /// The request goes out in the session's first segment, together with the first write.
    pub(super) fn set_head(&mut self, request: Vec<u8>) {
        *self.read.shared.head() = request;
    }

    pub(super) async fn handshake(&mut self, request: Vec<u8>) -> io::Result<()> {
        let shared = self.read.shared.clone();
        shared.open();
        shared
            .underlay
            .sender(shared.id)
            .send(Out::First {
                id: shared.id,
                data: request,
            })
            .await
            .map_err(broken)?;
        let wait = poll_fn(|cx| self.read.poll_response(cx));
        tokio::time::timeout(RESPONSE_TIMEOUT, wait)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mieru handshake timed out"))?
    }
}

impl ReadPart {
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                self.response.feed(&mut self.pending)?;
            }
            if self.response.done {
                return Poll::Ready(Ok(()));
            }
            ready!(self.poll_event(cx))?;
        }
    }

    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.ended.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        match ready!(self.events.poll_recv(cx)) {
            Some(Event::Data(bytes)) => {
                self.pending = bytes;
                Poll::Ready(Ok(()))
            }
            Some(Event::Closed) => {
                self.shared.ended.store(true, Ordering::Release);
                Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
            }
            None => {
                self.shared.ended.store(true, Ordering::Release);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "mieru connection closed",
                )))
            }
        }
    }

    fn poll_open(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.sink.poll_reserve(cx)).map_err(broken)?;
        let shared = &self.shared;
        let mut head = shared.head();
        if shared.opened.load(Ordering::Acquire) {
            drop(head);
            self.sink.abort_send();
            return Poll::Ready(Ok(()));
        }
        let data = std::mem::take(&mut *head);
        self.sink
            .send_item(Out::First {
                id: shared.id,
                data,
            })
            .map_err(broken)?;
        shared.open();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for ReadPart {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shared.opened.load(Ordering::Acquire) {
            ready!(this.poll_open(cx))?;
        }
        loop {
            if !this.pending.is_empty() {
                if !this.response.done {
                    this.response.feed(&mut this.pending)?;
                    continue;
                }
                let take = this.pending.len().min(out.remaining());
                out.put_slice(&this.pending.split_to(take));
                return Poll::Ready(Ok(()));
            }
            if this.response.done {
                this.deadline = None;
                this.deadline_spent = true;
            }
            if this.deadline.is_none()
                && !this.deadline_spent
                && let Some(started) = this.shared.started.get()
            {
                this.deadline = Some(Box::pin(sleep_until(*started + RESPONSE_TIMEOUT)));
            }
            if let Some(deadline) = this.deadline.as_mut()
                && deadline.as_mut().poll(cx).is_ready()
            {
                this.deadline = None;
                this.deadline_spent = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mieru handshake timed out",
                )));
            }
            if this.shared.ended.load(Ordering::Acquire) {
                return if this.response.done {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            match ready!(this.events.poll_recv(cx)) {
                Some(Event::Data(bytes)) => this.pending = bytes,
                Some(Event::Closed) => this.shared.ended.store(true, Ordering::Release),
                None => {
                    this.shared.ended.store(true, Ordering::Release);
                    if this.shared.closed.load(Ordering::Acquire) {
                        continue;
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "mieru connection closed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for WritePart {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = &this.shared;
        if shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.sink.poll_reserve(cx)).map_err(broken)?;
        if !shared.opened.load(Ordering::Acquire) {
            let mut head = shared.head();
            if !shared.opened.load(Ordering::Acquire) {
                let take = data.len().min(MAX_PDU - head.len()).min(this.fragment);
                let mut first = std::mem::take(&mut *head);
                first.extend_from_slice(data.get(..take).unwrap_or_default());
                this.sink
                    .send_item(Out::First {
                        id: shared.id,
                        data: first,
                    })
                    .map_err(broken)?;
                shared.open();
                return Poll::Ready(Ok(take));
            }
        }
        let take = data.len().min(this.fragment);
        let body = data.get(..take).unwrap_or_default().to_vec();
        this.sink
            .send_item(Out::Data {
                id: shared.id,
                data: body,
            })
            .map_err(broken)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;
        if shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        if shared.opened.load(Ordering::Acquire) && !shared.ended.load(Ordering::Acquire) {
            ready!(this.sink.poll_reserve(cx)).map_err(broken)?;
            this.sink
                .send_item(Out::Close { id: shared.id })
                .map_err(|_| invalid("connection closed"))?;
        }
        shared.closed.store(true, Ordering::Release);
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, out)
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Stream for MieruStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let MieruStream { read, write } = *self;
        (Box::new(read), Box::new(write))
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn a_socks5_error_reply_is_a_target_refusal() {
        let mut response = Response::new();
        let mut data = Bytes::from_static(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        let err = response.feed(&mut data).unwrap_err();
        assert_eq!(err.to_string(), "server returned socks5 error code 4");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(matches!(
            CoreError::of(&err),
            Some(CoreError::TargetRefused(_))
        ));
        let err = Response::new()
            .feed(&mut Bytes::from_static(&[4]))
            .unwrap_err();
        assert!(CoreError::of(&err).is_none());
    }
}

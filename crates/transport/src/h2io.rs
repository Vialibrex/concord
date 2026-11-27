use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use concord_common::stream_buffer::StreamBuffer;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, Tasks};
use h2::client::ResponseFuture;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep};

use crate::ended::Ended;

mod checked;
mod slot;
pub use checked::checked_handshake;
pub(crate) use slot::{ClientSlot, SafeSender, StreamGuard, reserve_stream};
#[cfg(test)]
use slot::{Live, sender_max_streams};

const PING_TIMEOUT: Duration = Duration::from_secs(15);
const AT_RISK: Duration = Duration::from_secs(10);
const HUNG: Duration = Duration::from_secs(10);
/// How long a tunnel that ends with RST_STREAM waits for its queued DATA to go out first.
const RESET_DRAIN: Duration = HUNG;
pub(crate) const STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub(crate) const CONN_WINDOW: u32 = 65_535 + (1 << 30);
pub(crate) const MAX_FRAME_SIZE: u32 = 1 << 20;
pub(crate) const INITIAL_MAX_SEND_STREAMS: usize = 100;
pub(crate) const DEFAULT_MAX_SEND_STREAMS: usize = 1000;

pub fn h2_io_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        return err.into_io().unwrap_or_else(|| io::ErrorKind::Other.into());
    }
    let kind = if err.is_go_away() {
        io::ErrorKind::BrokenPipe
    } else if err.is_reset() {
        io::ErrorKind::ConnectionReset
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, err)
}

pub fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME_SIZE)
        .initial_max_send_streams(INITIAL_MAX_SEND_STREAMS)
        .enable_push(false);
    builder
}

/// Splits `io` into directional halves and runs a split-I/O HTTP/2 client handshake so
/// inbound frame reads stay on the connection task while `H2Writer` writes DATA frames
/// directly to the outbound write half under peer flow control.
pub async fn handshake_split(
    builder: &h2::client::Builder,
    io: BoxStream,
) -> io::Result<(
    h2::client::SendRequest<Bytes>,
    h2::client::SplitConnection<BoxRead, Bytes>,
)> {
    let (read, write) = io.into_split();
    builder
        .handshake_split(read, write)
        .await
        .map_err(h2_io_error)
}

/// Last time anything arrived on a connection, so a ping goes out only when it
/// has been quiet.
pub struct Activity {
    base: Instant,
    last_ms: AtomicU64,
    ended: AtomicBool,
    closing: AtomicBool,
    signal: tokio::sync::Notify,
}

impl Activity {
    pub fn new() -> Arc<Activity> {
        Arc::new(Activity {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
            ended: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            signal: tokio::sync::Notify::new(),
        })
    }

    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    /// For a connection from [`checked_handshake`]: a stream about to open on a
    /// connection quiet past Chromium's at-risk threshold sends a PING ahead of it.
    pub fn before_stream(&self) {
        if self.idle() >= AT_RISK {
            self.signal.notify_one();
        }
    }

    /// Drops a connection from [`checked_handshake`] and every stream on it.
    pub fn close(&self) {
        self.closing.store(true, Ordering::Relaxed);
        self.signal.notify_one();
    }

    pub fn touch(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        self.base.elapsed().saturating_sub(self.since_base())
    }

    fn last_read(&self) -> Instant {
        self.base + self.since_base()
    }

    fn since_base(&self) -> Duration {
        Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

struct EndOnDrop(Arc<Activity>);

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        self.0.ended.store(true, Ordering::Release);
    }
}

pub fn spawn_connection(
    tasks: &Tasks,
    conn: h2::client::SplitConnection<BoxRead, Bytes>,
    ping_interval: Option<Duration>,
    activity: Arc<Activity>,
) {
    tasks.spawn(async move {
        let _end = EndOnDrop(activity.clone());
        drive(conn, ping_interval, &activity).await;
    });
}

/// Chromium's liveness check in place of periodic PINGs: a PING goes out only ahead of a
/// stream (see [`Activity::before_stream`]), and the connection is dropped when nothing has
/// been read for the hung interval after it.
pub(crate) fn spawn_checked_connection(
    tasks: &Tasks,
    conn: h2::client::Connection<BoxStream, Bytes>,
    activity: Arc<Activity>,
) {
    activity.touch();
    tasks.spawn(async move {
        drive_checked(conn, &activity).await;
        activity.ended.store(true, Ordering::Relaxed);
    });
}

async fn drive_checked(conn: h2::client::Connection<BoxStream, Bytes>, activity: &Activity) {
    let mut conn = Box::pin(conn);
    let mut pings = conn.ping_pong();
    loop {
        tokio::select! {
            _ = conn.as_mut() => return,
            () = activity.signal.notified() => {}
        }
        if activity.closing.load(Ordering::Relaxed) {
            return;
        }
        let Some(pings) = pings.as_mut() else {
            continue;
        };
        let ping = pings.ping(h2::Ping::opaque());
        tokio::pin!(ping);
        // Chromium's CheckPingStatus: the session is dead once nothing has been read for the hung
        // interval, or since the previous check; streams opening meanwhile do not move the deadline.
        let mut last_check = Instant::now();
        let check = tokio::time::sleep_until(last_check + HUNG);
        tokio::pin!(check);
        loop {
            tokio::select! {
                _ = conn.as_mut() => return,
                answered = &mut ping => {
                    if answered.is_err() {
                        return;
                    }
                    activity.touch();
                    break;
                }
                () = &mut check => {
                    let (now, last_read) = (Instant::now(), activity.last_read());
                    if now >= last_read + HUNG || last_read < last_check {
                        return;
                    }
                    last_check = now;
                    check.as_mut().reset(last_read + HUNG);
                }
                () = activity.signal.notified() => if activity.closing.load(Ordering::Relaxed) {
                    return;
                },
            }
        }
    }
}

async fn drive(
    conn: h2::client::SplitConnection<BoxRead, Bytes>,
    ping_interval: Option<Duration>,
    activity: &Activity,
) {
    let mut conn = Box::pin(conn);
    let Some(interval) = ping_interval.filter(|d| !d.is_zero()) else {
        let _ = conn.await;
        return;
    };
    let Some(mut pings) = conn.ping_pong() else {
        let _ = conn.await;
        return;
    };
    loop {
        tokio::select! {
            _ = conn.as_mut() => return,
            () = tokio::time::sleep(interval) => {}
        }
        if activity.idle() < interval {
            continue;
        }
        let ping = tokio::time::timeout(PING_TIMEOUT, pings.ping(h2::Ping::opaque()));
        tokio::select! {
            _ = conn.as_mut() => return,
            answered = ping => match answered {
                Ok(Ok(_)) => activity.touch(),
                _ => return,
            },
        }
    }
}

pub enum Incoming {
    Response(ResponseFuture),
    Body(RecvStream),
    Done,
}

/// Judges a response's head in place of the default non-2xx rejection.
pub type ResponseCheck = Box<dyn FnOnce(&http::response::Parts) -> io::Result<()> + Send>;

/// The response side of a request stream: waits for the headers, rejects a non-2xx
/// status, then yields the body.
pub(crate) struct H2Reader {
    incoming: Incoming,
    pending: Bytes,
    pending_err: Option<io::Error>,
    activity: Option<Arc<Activity>>,
    check: Option<ResponseCheck>,
    ended: Option<Arc<Ended>>,
}

impl H2Reader {
    pub fn new(incoming: Incoming) -> Self {
        H2Reader {
            incoming,
            pending: Bytes::new(),
            pending_err: None,
            activity: None,
            check: None,
            ended: None,
        }
    }

    fn finish_read(&mut self, released: usize, saw_data: bool) {
        if released > 0
            && let Incoming::Body(recv) = &mut self.incoming
        {
            let _ = recv.flow_control().release_capacity(released);
        }
        if saw_data && let Some(activity) = &self.activity {
            activity.touch();
        }
    }
}

impl AsyncRead for H2Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(ended) = &this.ended
            && ended.poll_ended(cx)
        {
            this.incoming = Incoming::Done;
            this.pending = Bytes::new();
            this.pending_err = None;
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut copied = 0usize;
        if !this.pending.is_empty() {
            let take = this.pending.len().min(buf.remaining());
            let chunk = this.pending.get(..take).ok_or(io::ErrorKind::InvalidData)?;
            buf.put_slice(chunk);
            copied += take;
            if take == this.pending.len() {
                this.pending = Bytes::new();
            } else {
                this.pending.advance(take);
                return Poll::Ready(Ok(()));
            }
        }

        if let Some(err) = this.pending_err.take() {
            return Poll::Ready(Err(err));
        }

        let mut released = 0usize;
        let mut saw_data = false;
        while buf.remaining() > 0 {
            match &mut this.incoming {
                Incoming::Done => break,
                Incoming::Response(future) => {
                    let response = match Pin::new(future).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(res) => res.map_err(h2_io_error)?,
                    };
                    let (head, body) = response.into_parts();
                    let checked = match this.check.take() {
                        Some(check) => check(&head),
                        None if head.status.is_success() => Ok(()),
                        None => Err(io::Error::other(format!(
                            "unexpected HTTP status {}",
                            head.status
                        ))),
                    };
                    if let Err(err) = checked {
                        this.incoming = Incoming::Done;
                        return Poll::Ready(Err(err));
                    }
                    this.incoming = Incoming::Body(body);
                }
                Incoming::Body(recv) => match recv.poll_data(cx) {
                    Poll::Pending => {
                        if copied > 0 {
                            break;
                        }
                        this.finish_read(released, saw_data);
                        return Poll::Pending;
                    }
                    Poll::Ready(None) => {
                        this.finish_read(released, saw_data);
                        this.incoming = Incoming::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(Err(err))) => {
                        this.finish_read(released, saw_data);
                        this.incoming = Incoming::Done;
                        if let Some(ended) = &this.ended
                            && ended.poll_ended(cx)
                        {
                            return Poll::Ready(Ok(()));
                        }
                        let err = h2_io_error(err);
                        if copied > 0 {
                            this.pending_err = Some(err);
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Some(Ok(mut data))) => {
                        saw_data = true;
                        released += data.len();
                        if data.is_empty() {
                            continue;
                        }
                        let take = data.len().min(buf.remaining());
                        let chunk = data.get(..take).ok_or(io::ErrorKind::InvalidData)?;
                        buf.put_slice(chunk);
                        copied += take;
                        if take < data.len() {
                            data.advance(take);
                            this.pending = data;
                            break;
                        }
                    }
                },
            }
        }

        this.finish_read(released, saw_data);
        Poll::Ready(Ok(()))
    }
}

/// The request side: writes become DATA frames, shutdown ends the stream with END_STREAM, or
/// with RST_STREAM once its DATA is out when `end` takes the reader down with it.
pub(crate) struct H2Writer {
    send: SendStream<Bytes>,
    ending: bool,
    ended: bool,
    end: Option<Arc<Ended>>,
    drain: Option<Pin<Box<Sleep>>>,
}

struct OwnedData(StreamBuffer);

impl AsRef<[u8]> for OwnedData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl H2Writer {
    pub fn new(send: SendStream<Bytes>) -> Self {
        H2Writer {
            send,
            ending: false,
            ended: false,
            end: None,
            drain: None,
        }
    }

    fn poll_owned_data(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if self.ended || self.ending {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.send.has_direct_writer() {
            if !self.send.has_direct_in_flight() && buffer.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let length = buffer.len();
            let written = ready!(self.send.poll_write_direct(cx, length, false, |take| {
                if take == length {
                    Bytes::from_owner(OwnedData(buffer.take_owned()))
                } else {
                    let bytes =
                        Bytes::copy_from_slice(buffer.as_slice().get(..take).unwrap_or(&[]));
                    let _ = buffer.consume(take);
                    bytes
                }
            }))
            .map_err(h2_io_error)?;
            return Poll::Ready(Ok(written));
        }
        let length = buffer.len();
        if length == 0 {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(length);
        match ready!(self.send.poll_capacity(cx)) {
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Some(Err(error)) => Poll::Ready(Err(h2_io_error(error))),
            Some(Ok(capacity)) => {
                let take = capacity.min(length);
                let data = if take == length {
                    Bytes::from_owner(OwnedData(buffer.take_owned()))
                } else {
                    let Some(chunk) = buffer.as_slice().get(..take) else {
                        return Poll::Ready(Ok(0));
                    };
                    let bytes = Bytes::copy_from_slice(chunk);
                    buffer.consume(take)?;
                    bytes
                };
                self.send.send_data(data, false).map_err(h2_io_error)?;
                Poll::Ready(Ok(take))
            }
        }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended || this.ending {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.send.has_direct_writer() {
            if !this.send.has_direct_in_flight() && data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let written = ready!(this.send.poll_write_direct(cx, data.len(), false, |take| {
                Bytes::copy_from_slice(data.get(..take).unwrap_or(&[]))
            }))
            .map_err(h2_io_error)?;
            return Poll::Ready(Ok(written));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(data.len());
        match ready!(this.send.poll_capacity(cx)) {
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Some(Err(err)) => Poll::Ready(Err(h2_io_error(err))),
            Some(Ok(capacity)) => {
                let take = capacity.min(data.len());
                let Some(chunk) = data.get(..take) else {
                    return Poll::Ready(Ok(0));
                };
                this.send
                    .send_data(Bytes::copy_from_slice(chunk), false)
                    .map_err(h2_io_error)?;
                Poll::Ready(Ok(take))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.send.has_direct_writer() {
            ready!(this.send.poll_flush_direct(cx)).map_err(h2_io_error)?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Ok(()));
        }
        if let Some(end) = &this.end {
            if this.send.has_direct_writer() {
                ready!(this.send.poll_flush_direct(cx)).map_err(h2_io_error)?;
            }
            if this.send.poll_drained(cx).is_pending() {
                let deadline = this
                    .drain
                    .get_or_insert_with(|| Box::pin(sleep(RESET_DRAIN)));
                if deadline.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            // Ended before the reset, so a reader that sees the reset as an error also sees it ended.
            end.end();
            this.send.send_reset(h2::Reason::CANCEL);
            this.ended = true;
            return Poll::Ready(Ok(()));
        }
        if this.send.has_direct_writer() {
            if !this.ending {
                ready!(this.send.poll_flush_direct(cx)).map_err(h2_io_error)?;
                this.ending = true;
            }
            ready!(this.send.poll_write_direct(cx, 0, true, |_| Bytes::new()))
                .map_err(h2_io_error)?;
            this.ended = true;
            return Poll::Ready(Ok(()));
        }
        this.ended = true;
        this.send
            .send_data(Bytes::new(), true)
            .map_err(h2_io_error)?;
        Poll::Ready(Ok(()))
    }
}

struct DropHook(Mutex<Option<Box<dyn FnOnce() + Send>>>);

impl Drop for DropHook {
    fn drop(&mut self) {
        let slot = self.0.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(hook) = slot.take() {
            hook();
        }
    }
}

/// A request stream as a byte stream in both directions.
pub struct H2Body {
    reader: H2Reader,
    writer: H2Writer,
    hook: Arc<DropHook>,
}

impl H2Body {
    pub fn new(send: SendStream<Bytes>, incoming: Incoming) -> Self {
        H2Body {
            reader: H2Reader::new(incoming),
            writer: H2Writer::new(send),
            hook: Arc::new(DropHook(Mutex::new(None))),
        }
    }

    pub fn with_activity(mut self, activity: Arc<Activity>) -> Self {
        self.reader.activity = Some(activity);
        self
    }

    pub fn with_response_check(mut self, check: ResponseCheck) -> Self {
        self.reader.check = Some(check);
        self
    }

    /// Shutdown ends the whole stream rather than half of it, as a Chromium tunnel does: it waits
    /// up to `RESET_DRAIN` for the queued DATA, resets the stream, and reads end.
    pub fn without_half_close(mut self) -> Self {
        let ended = Arc::new(Ended::default());
        self.reader.ended = Some(ended.clone());
        self.writer.end = Some(ended);
        self
    }

    pub fn on_drop(mut self, hook: impl FnOnce() + Send + 'static) -> Self {
        self.hook = Arc::new(DropHook(Mutex::new(Some(Box::new(hook)))));
        self
    }
}

impl AsyncRead for H2Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Body {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl Stream for H2Body {
    concord_common::stream_policy!(own: into_split, poll_write_buffer;
        default: read_requirements, write_requirements, poll_read_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        self.writer.poll_owned_data(cx, buffer)
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let H2Body {
            reader,
            writer,
            hook,
        } = *self;
        (
            Box::new(Held {
                io: reader,
                _hook: Arc::clone(&hook),
            }),
            Box::new(Held {
                io: writer,
                _hook: hook,
            }),
        )
    }
}

/// A half that keeps the drop hook alive, so it runs once both halves are gone.
struct Held<T> {
    io: T,
    _hook: Arc<DropHook>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Held<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Held<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
pub(crate) mod tests;

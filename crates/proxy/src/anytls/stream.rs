use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, ready};

use concord_common::stream_buffer::{self, BufferRequirements, ReadBufferOptions, StreamBuffer};
use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::frame::{CMD_PSH, HEADER, MAX_FRAME, data_frames, frame, header};
use super::session::{Chunk, Flow, Out, Session};

struct Closer {
    sid: u32,
    session: Arc<Session>,
    flow: Arc<Flow>,
}

impl Closer {
    fn close(&self) {
        self.session.finish_local(self.sid, &self.flow);
    }
}

impl Drop for Closer {
    fn drop(&mut self) {
        self.close();
    }
}

struct Inbox {
    chunks: mpsc::Receiver<Chunk>,
    pending: StreamBuffer,
    ended: bool,
}

impl Inbox {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        closer: &Closer,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if ready!(self.poll_pending(cx, closer))? {
            let take = self.pending.len().min(out.remaining());
            out.put_slice(self.pending.as_slice().get(..take).unwrap_or_default());
            self.pending.consume(take)?;
        }
        Poll::Ready(Ok(()))
    }

    /// Hands over the received frame itself when it has the writer's room.
    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        closer: &Closer,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        if closer.flow.reads.get().is_none() {
            let _ = closer.flow.reads.set(options);
        }
        if !ready!(self.poll_pending(cx, closer))? {
            return Poll::Ready(Ok(StreamBuffer::default()));
        }
        if options.fits(&self.pending) {
            return Poll::Ready(Ok(self.pending.take_owned()));
        }
        let mut buffer = options.take();
        let filled = {
            let mut read = ReadBuf::new(buffer.spare_mut());
            ready!(self.poll_read(cx, closer, &mut read))?;
            read.filled().len()
        };
        buffer.advance(filled)?;
        Poll::Ready(Ok(buffer))
    }

    /// Ready(true) when bytes are pending, Ready(false) at the end of the stream.
    fn poll_pending(&mut self, cx: &mut Context<'_>, closer: &Closer) -> Poll<io::Result<bool>> {
        loop {
            if !self.pending.is_empty() {
                return Poll::Ready(Ok(true));
            }
            if self.ended {
                return Poll::Ready(Ok(false));
            }
            let Poll::Ready(chunk) = self.chunks.poll_recv(cx) else {
                let lent = closer.session.poll_lent(cx, closer.sid, &closer.flow);
                match ready!(lent) {
                    Some(buffer) => self.pending = buffer,
                    None => return Poll::Pending,
                }
                continue;
            };
            match chunk {
                Some(Chunk::Data(buffer)) => {
                    closer.flow.took();
                    self.pending = buffer;
                }
                Some(Chunk::Lent) => {}
                None => {
                    self.ended = true;
                    if let Some(message) = closer.flow.remote_err.get() {
                        return Poll::Ready(Err(CoreError::TargetRefused(message.clone()).into()));
                    }
                    if !closer.flow.done.load(Ordering::Acquire) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "anytls session closed",
                        )));
                    }
                }
            }
        }
    }
}

struct Outbox {
    sink: PollSender<Out>,
    wrote_since_read: bool,
}

impl Outbox {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        closer: &Closer,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if closer.flow.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.sink.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        closer.flow.wrote();
        self.wrote_since_read = false;
        if data.len() <= MAX_FRAME {
            self.sink
                .send_item(Out::Data(frame(CMD_PSH, closer.sid, data)))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            return Poll::Ready(Ok(data.len()));
        }
        let sender = closer.session.sender();
        let extra = (data.len().div_ceil(MAX_FRAME) - 1).min(sender.capacity());
        let reserved = sender.try_reserve_many(extra).ok();
        let frames = 1 + reserved.as_ref().map_or(0, ExactSizeIterator::len);
        let take = data.len().min(frames * MAX_FRAME);
        let body = data.get(..take).unwrap_or_default();
        self.sink
            .send_item(Out::Data(data_frames(closer.sid, body)))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if let Some(reserved) = reserved {
            for permit in reserved {
                permit.send(Out::FrameSlot);
            }
        }
        Poll::Ready(Ok(take))
    }

    fn poll_write_owned(
        &mut self,
        cx: &mut Context<'_>,
        closer: &Closer,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if closer.flow.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.sink.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        closer.flow.wrote();
        let length = buffer.len();
        buffer
            .prepend(HEADER)?
            .copy_from_slice(&header(CMD_PSH, closer.sid, length));
        let mut frame = buffer.take_owned();
        let continued = self.wrote_since_read;
        let inline = if continued {
            closer.session.try_write_owned(cx, &mut frame)
        } else {
            Ok(false)
        };
        match inline {
            Ok(true) => {
                self.sink.abort_send();
            }
            Ok(false) => self
                .sink
                .send_item(Out::Owned { frame, continued })
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?,
            Err(err) => {
                closer.session.close();
                self.sink.abort_send();
                return Poll::Ready(Err(err));
            }
        }
        self.wrote_since_read = true;
        Poll::Ready(Ok(length))
    }
}

pub(crate) struct AnyTlsStream {
    inbox: Inbox,
    outbox: Outbox,
    closer: Arc<Closer>,
}

#[cfg(feature = "server")]
impl AnyTlsStream {
    /// `HandshakeSuccess` (`session/stream.go:153-165`): a client from version 2 on waits
    /// for a SYNACK, sent here ahead of the stream's own data.
    pub(crate) async fn handshake_success(&self) -> io::Result<()> {
        let session = &self.closer.session;
        if session.peer_version() < 2 {
            return Ok(());
        }
        session
            .sender()
            .send(Out::Data(frame(
                super::frame::CMD_SYNACK,
                self.closer.sid,
                &[],
            )))
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

impl AnyTlsStream {
    pub(super) fn new(
        sid: u32,
        session: Arc<Session>,
        chunks: mpsc::Receiver<Chunk>,
        flow: Arc<Flow>,
    ) -> Self {
        let sink = PollSender::new(session.sender());
        AnyTlsStream {
            inbox: Inbox {
                chunks,
                pending: StreamBuffer::default(),
                ended: false,
            },
            outbox: Outbox {
                sink,
                wrote_since_read: false,
            },
            closer: Arc::new(Closer { sid, session, flow }),
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = this.inbox.poll_read(cx, &this.closer, out);
        if out.filled().len() != before {
            this.outbox.wrote_since_read = false;
        }
        result
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.outbox.poll_write(cx, &this.closer, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closer.close();
        Poll::Ready(Ok(()))
    }
}

struct ReadHalf {
    inbox: Inbox,
    closer: Arc<Closer>,
}

impl AsyncRead for ReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.inbox.poll_read(cx, &this.closer, out)
    }
}

impl Drop for ReadHalf {
    fn drop(&mut self) {
        self.closer.session.give_back();
    }
}

struct WriteHalf {
    outbox: Outbox,
    closer: Arc<Closer>,
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.outbox.poll_write(cx, &this.closer, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closer.close();
        Poll::Ready(Ok(()))
    }
}

impl Stream for AnyTlsStream {
    concord_common::stream_policy!(own: into_split, poll_read_buffer, write_requirements, poll_write_buffer;
        default: read_requirements, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        let buffer = ready!(self.inbox.poll_read_buffer(cx, &self.closer, options))?;
        if !buffer.is_empty() {
            self.outbox.wrote_since_read = false;
        }
        Poll::Ready(Ok(buffer))
    }

    fn write_requirements(&self) -> BufferRequirements {
        BufferRequirements {
            mtu: MAX_FRAME,
            front: HEADER,
            rear: 0,
        }
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() || buffer.len() > MAX_FRAME || buffer.headroom() < HEADER {
            return stream_buffer::poll_write_buffer(self, cx, buffer);
        }
        self.outbox.poll_write_owned(cx, &self.closer, buffer)
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let AnyTlsStream {
            inbox,
            outbox,
            closer,
        } = *self;
        (
            Box::new(ReadHalf {
                inbox,
                closer: closer.clone(),
            }),
            Box::new(WriteHalf { outbox, closer }),
        )
    }
}

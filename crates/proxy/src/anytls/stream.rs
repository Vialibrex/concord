use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use concord_common::stream_buffer::{self, BufferRequirements, StreamBuffer};
use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::frame::{CMD_PSH, HEADER, MAX_FRAME, data_frames, frame, header};
use super::session::{Chunk, Out, Session};

struct Closer {
    sid: u32,
    session: Arc<Session>,
    done: Arc<AtomicBool>,
}

impl Closer {
    fn close(&self) {
        self.session.finish_local(self.sid, &self.done);
    }
}

impl Drop for Closer {
    fn drop(&mut self) {
        self.close();
    }
}

struct Inbox {
    chunks: mpsc::Receiver<Chunk>,
    pending: Bytes,
    ended: bool,
}

impl Inbox {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        done: &AtomicBool,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(out.remaining());
                out.put_slice(&self.pending.split_to(take));
                return Poll::Ready(Ok(()));
            }
            if self.ended {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.chunks.poll_recv(cx)) {
                Some(Chunk::Data(bytes)) => self.pending = bytes,
                Some(Chunk::Fin) => self.ended = true,
                Some(Chunk::Error(message)) => {
                    self.ended = true;
                    return Poll::Ready(Err(CoreError::TargetRefused(message).into()));
                }
                None if done.load(Ordering::Acquire) => self.ended = true,
                None => {
                    self.ended = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "anytls session closed",
                    )));
                }
            }
        }
    }
}

struct Outbox {
    sink: PollSender<Out>,
}

impl Outbox {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        closer: &Closer,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if closer.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.sink.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
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
        if closer.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.sink.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let length = buffer.len();
        buffer
            .prepend(HEADER)?
            .copy_from_slice(&header(CMD_PSH, closer.sid, length));
        let mut frame = buffer.take_owned();
        match closer.session.try_write_owned(cx, &mut frame) {
            Ok(true) => {
                self.sink.abort_send();
            }
            Ok(false) => self
                .sink
                .send_item(Out::Owned(frame))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?,
            Err(err) => {
                closer.session.close();
                self.sink.abort_send();
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(length))
    }
}

pub(super) struct AnyTlsStream {
    inbox: Inbox,
    outbox: Outbox,
    closer: Arc<Closer>,
}

impl AnyTlsStream {
    pub(super) fn new(
        sid: u32,
        session: Arc<Session>,
        chunks: mpsc::Receiver<Chunk>,
        done: Arc<AtomicBool>,
    ) -> Self {
        let sink = PollSender::new(session.sender());
        AnyTlsStream {
            inbox: Inbox {
                chunks,
                pending: Bytes::new(),
                ended: false,
            },
            outbox: Outbox { sink },
            closer: Arc::new(Closer { sid, session, done }),
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
        this.inbox.poll_read(cx, &this.closer.done, out)
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
        this.inbox.poll_read(cx, &this.closer.done, out)
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
    concord_common::stream_policy!(own: into_split, write_requirements, poll_write_buffer;
        default: read_requirements, poll_read_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

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

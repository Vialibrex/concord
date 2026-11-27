use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxWrite, Stream};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{H3Reader, H3Writer, Keep, RecvStream, h3_io_error};
use crate::ended::Ended;
use crate::h2io::ResponseCheck;

enum Incoming {
    Response(BoxFuture<'static, io::Result<RecvStream>>),
    Body(Box<H3Reader>),
    Failed,
    Ended,
}

/// The response side of a request stream, its reads held until the answer passes the check.
pub struct H3Response {
    incoming: Incoming,
    ended: Option<Arc<Ended>>,
    _keep: Keep,
}

impl H3Response {
    pub fn new(mut recv: RecvStream, check: ResponseCheck, keep: Keep) -> Self {
        let response = Box::pin(async move {
            let response = recv.recv_response().await.map_err(h3_io_error)?;
            check(&response.into_parts().0)?;
            Ok(recv)
        });
        H3Response {
            incoming: Incoming::Response(response),
            ended: None,
            _keep: keep,
        }
    }
}

impl H3Response {
    /// A response whose head has already been read and judged.
    pub fn answered(recv: RecvStream, keep: Keep) -> Self {
        H3Response {
            incoming: Incoming::Body(Box::new(H3Reader::new(recv))),
            ended: None,
            _keep: keep,
        }
    }
}

impl AsyncRead for H3Response {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(ended) = &this.ended
            && ended.poll_ended(cx)
        {
            if let Incoming::Body(reader) = &mut this.incoming {
                reader.stop_sending();
            }
            this.incoming = Incoming::Ended;
            return Poll::Ready(Ok(()));
        }
        loop {
            match &mut this.incoming {
                Incoming::Response(response) => match ready!(response.as_mut().poll(cx)) {
                    Ok(recv) => this.incoming = Incoming::Body(Box::new(H3Reader::new(recv))),
                    Err(err) => {
                        this.incoming = Incoming::Failed;
                        return Poll::Ready(Err(err));
                    }
                },
                Incoming::Body(reader) => return reader.poll_read(cx, buf).map_err(h3_io_error),
                Incoming::Failed => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Incoming::Ended => return Poll::Ready(Ok(())),
            }
        }
    }
}

pub struct H3Body {
    read: H3Response,
    write: H3Writer,
}

impl H3Body {
    pub fn new(read: H3Response, write: H3Writer) -> Self {
        H3Body { read, write }
    }

    /// Shutdown ends the whole stream rather than half of it: after the FIN, which QUIC delivers
    /// with every byte before it, STOP_SENDING asks the server to drop its side, and reads end.
    pub fn without_half_close(self) -> Self {
        let ended = Arc::new(Ended::default());
        let mut read = self.read;
        read.ended = Some(ended.clone());
        H3Body {
            read,
            write: self.write.ending(ended),
        }
    }
}

impl AsyncRead for H3Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for H3Body {
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

impl Stream for H3Body {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        (Box::new(self.read), Box::new(self.write))
    }
}

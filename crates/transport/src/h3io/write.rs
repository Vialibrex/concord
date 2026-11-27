use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::io::AsyncWrite;

use super::h3_io_error;
use crate::ended::Ended;

pub type SendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

/// Whatever must outlive a stream half, such as the connection it runs on.
pub type Keep = Arc<dyn Send + Sync>;

/// The request side of a stream; one that is dropped unfinished is cancelled.
pub struct H3Upload {
    stream: SendStream,
    finished: bool,
}

impl H3Upload {
    pub fn new(stream: SendStream) -> Self {
        Self {
            stream,
            finished: false,
        }
    }

    pub async fn send(&mut self, body: Bytes) -> io::Result<()> {
        self.stream.send_data(body).await.map_err(h3_io_error)
    }

    pub async fn finish(&mut self) -> io::Result<()> {
        self.stream.finish().await.map_err(h3_io_error)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for H3Upload {
    fn drop(&mut self) {
        if !self.finished {
            self.stream
                .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

type Sending = BoxFuture<'static, (H3Upload, io::Result<()>)>;

/// The request side as a byte stream: writes become DATA frames, shutdown finishes the stream,
/// and then `end` takes the reader down with it.
pub struct H3Writer {
    send: Option<H3Upload>,
    pending: Option<Sending>,
    writing: Option<usize>,
    failure: Option<(io::ErrorKind, String)>,
    finished: bool,
    end: Option<Arc<Ended>>,
    _keep: Keep,
}

impl H3Writer {
    pub fn new(send: SendStream, keep: Keep) -> Self {
        Self {
            send: Some(H3Upload::new(send)),
            pending: None,
            writing: None,
            failure: None,
            finished: false,
            end: None,
            _keep: keep,
        }
    }

    pub(super) fn ending(mut self, end: Arc<Ended>) -> Self {
        self.end = Some(end);
        self
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((kind, message)) = &self.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if let Some(pending) = &mut self.pending {
            let (send, result) = ready!(pending.as_mut().poll(cx));
            self.pending = None;
            self.send = Some(send);
            if let Err(err) = result {
                self.failure = Some((err.kind(), err.to_string()));
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H3Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if let Some(written) = this.writing.take() {
            return Poll::Ready(Ok(written));
        }
        if this.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(mut send) = this.send.take() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let body = Bytes::copy_from_slice(data);
        this.pending = Some(Box::pin(async move {
            let result = send.send(body).await;
            (send, result)
        }));
        this.writing = Some(data.len());
        ready!(this.drain(cx))?;
        this.writing = None;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drain(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.finished {
            this.finished = true;
            let Some(mut send) = this.send.take() else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            this.pending = Some(Box::pin(async move {
                let result = send.finish().await;
                (send, result)
            }));
        }
        ready!(this.drain(cx))?;
        if let Some(end) = &this.end {
            end.end();
        }
        Poll::Ready(Ok(()))
    }
}

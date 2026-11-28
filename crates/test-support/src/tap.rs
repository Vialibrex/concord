//! What crossed a TCP connection, for a test that must tell whether bytes went through a
//! proxy as they are or wrapped in another layer.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;

#[allow(
    clippy::disallowed_methods,
    reason = "test-support sits below concord-common, and this is what its sync::lock does"
)]
fn held(bytes: &Mutex<Vec<u8>>) -> MutexGuard<'_, Vec<u8>> {
    bytes.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The bytes a stream read and wrote, in order, over every connection it was given to.
#[derive(Clone, Default)]
pub struct Seen {
    read: Arc<Mutex<Vec<u8>>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Seen {
    pub fn read(&self) -> Vec<u8> {
        held(&self.read).clone()
    }

    pub fn written(&self) -> Vec<u8> {
        held(&self.written).clone()
    }
}

/// A stream that keeps a copy of what is read from and written to it.
pub struct Recorded<S> {
    inner: S,
    seen: Seen,
}

impl<S> Recorded<S> {
    pub fn new(inner: S, seen: &Seen) -> Self {
        Recorded {
            inner,
            seen: seen.clone(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Recorded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let read = &buf.filled()[before..];
        held(&self.seen.read).extend_from_slice(read);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recorded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, data))?;
        held(&self.seen.written).extend_from_slice(&data[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A loopback relay to `to`. What it [`Seen::read`] is what its clients sent toward `to`, and
/// what it [`Seen::written`] is what came back.
pub async fn tap(to: SocketAddr) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Seen::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let seen = kept.clone();
            tokio::spawn(async move {
                let mut client = Recorded::new(client, &seen);
                let mut server = crate::tcp_connect(to).await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    (addr, seen)
}

/// Whether `part` appears in `whole` as it is.
pub fn carries(whole: &[u8], part: &[u8]) -> bool {
    !part.is_empty() && whole.windows(part.len()).any(|window| window == part)
}

use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxStream, BoxWrite, OwnedTcp, Stream, stream_policy};
use concord_platform::preconnect;
use socket2::{SockRef, Socket};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;

/// A connection started with `concord_platform::preconnect`, whose SYN waits for the first
/// write. Writes and a shutdown before the handshake completes wait for it: XNU answers them
/// with ENOTCONN and with a closed connection instead of blocking as Linux does. A read before
/// the first write waits for it, since tokio reads only once the socket reports readable.
pub(crate) struct FastOpenStream {
    stream: TcpStream,
    opening: Opening,
    target: SocketAddr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Opening {
    Unsent,
    Handshaking,
    Open,
}

pub(crate) enum Start {
    FastOpen(FastOpenStream),
    Connect(Socket),
}

/// Preconnects `socket`, or hands back the socket to connect as usual: this one where the
/// platform has no preconnect, a fresh one from `reopen` after a failure.
pub(crate) fn start(
    socket: Socket,
    target: SocketAddr,
    reopen: impl FnOnce() -> io::Result<Socket>,
) -> io::Result<Start> {
    match preconnect(&socket, target) {
        Ok(true) => {
            let stream = TcpStream::from_std(socket.into())?;
            Ok(Start::FastOpen(FastOpenStream::new(stream, target)))
        }
        Ok(false) => Ok(Start::Connect(socket)),
        Err(err) => {
            tracing::debug!("TCP Fast Open is not available: {err}");
            Ok(Start::Connect(reopen()?))
        }
    }
}

fn handshaking(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotConnected
}

/// ENOTCONN means the handshake still runs, unless it failed with an error not yet reported.
fn wait_for_handshake(stream: &TcpStream, err: io::Error) -> io::Error {
    if !handshaking(&err) {
        return err;
    }
    match SockRef::from(stream).take_error() {
        Ok(None) => io::ErrorKind::WouldBlock.into(),
        Ok(Some(failed)) => failed,
        Err(err) => err,
    }
}

impl Opening {
    fn poll_write(
        &mut self,
        stream: &TcpStream,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() && *self == Opening::Unsent {
            self.start(stream)?;
            return Poll::Ready(Ok(0));
        }
        loop {
            ready!(stream.poll_write_ready(cx))?;
            let mut started = false;
            match stream.try_io(Interest::WRITABLE, || {
                SockRef::from(stream).send(buf).map_err(|err| {
                    started = handshaking(&err);
                    wait_for_handshake(stream, err)
                })
            }) {
                Ok(written) => {
                    *self = match *self {
                        Opening::Unsent => Opening::Handshaking,
                        _ => Opening::Open,
                    };
                    return Poll::Ready(Ok(written));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if started {
                        *self = Opening::Handshaking;
                    }
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    /// Sends the SYN without data, as any read syscall would.
    fn start(&mut self, stream: &TcpStream) -> io::Result<()> {
        let mut nothing: [MaybeUninit<u8>; 0] = [];
        match SockRef::from(stream).recv(&mut nothing) {
            Err(err) if err.kind() != io::ErrorKind::WouldBlock => Err(err),
            _ => {
                *self = Opening::Handshaking;
                Ok(())
            }
        }
    }

    /// Ready once the connection is open or has failed.
    fn poll_open(&mut self, stream: &TcpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if *self == Opening::Unsent {
            self.start(stream)?;
        }
        while *self == Opening::Handshaking {
            ready!(stream.poll_write_ready(cx))?;
            match stream.try_io(Interest::WRITABLE, || {
                SockRef::from(stream)
                    .send(&[])
                    .map_err(|err| wait_for_handshake(stream, err))
            }) {
                Ok(_) => *self = Opening::Open,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn first_nonempty<'a>(bufs: &'a [IoSlice<'a>]) -> &'a [u8] {
    bufs.iter()
        .find(|buf| !buf.is_empty())
        .map_or(&[], |buf| &**buf)
}

impl FastOpenStream {
    pub(crate) fn new(stream: TcpStream, target: SocketAddr) -> Self {
        FastOpenStream {
            stream,
            opening: Opening::Unsent,
            target,
        }
    }

    /// A connection written to once and then only read never reaches `Open` through a write.
    fn is_open(&self) -> bool {
        match self.opening {
            Opening::Open => true,
            Opening::Handshaking => self.stream.peer_addr().is_ok(),
            Opening::Unsent => false,
        }
    }
}

impl AsyncRead for FastOpenStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for FastOpenStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.opening {
            Opening::Open => Pin::new(&mut this.stream).poll_write(cx, buf),
            _ => this.opening.poll_write(&this.stream, cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.opening {
            Opening::Open => Pin::new(&mut this.stream).poll_write_vectored(cx, bufs),
            _ => this
                .opening
                .poll_write(&this.stream, cx, first_nonempty(bufs)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.opening.poll_open(&this.stream, cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl Stream for FastOpenStream {
    stream_policy!(stream;
        forward: read_requirements, write_requirements, poll_read_buffer;
        own: tcp, into_tcp, peer_addr, needs_handshake, into_split;
        default: poll_write_buffer, direct);

    fn tcp(&self) -> Option<&TcpStream> {
        self.is_open().then_some(&self.stream)
    }

    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        if self.is_open() {
            return Ok(self.stream.into());
        }
        Err(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.target)
    }

    fn needs_handshake(&self) -> bool {
        self.opening == Opening::Unsent
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let open = self.is_open();
        let opening = self.opening;
        let (read, write) = self.stream.into_split();
        let write: BoxWrite = if open {
            Box::new(write)
        } else {
            Box::new(FastOpenWrite {
                half: write,
                opening,
            })
        };
        (Box::new(read), write)
    }
}

/// Dropped before the handshake completes, tokio's `OwnedWriteHalf` shuts the write side
/// down at once and SYN-SENT discards what was written; only a connection given up does that.
struct FastOpenWrite {
    half: OwnedWriteHalf,
    opening: Opening,
}

impl AsyncWrite for FastOpenWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.opening {
            Opening::Open => Pin::new(&mut this.half).poll_write(cx, buf),
            _ => this.opening.poll_write(this.half.as_ref(), cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.opening {
            Opening::Open => Pin::new(&mut this.half).poll_write_vectored(cx, bufs),
            _ => this
                .opening
                .poll_write(this.half.as_ref(), cx, first_nonempty(bufs)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.half.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().half).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.opening.poll_open(this.half.as_ref(), cx))?;
        Pin::new(&mut this.half).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    use concord_common::{SockOpts, SocketFactory};
    use concord_platform::Platform;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    use crate::Sockets;
    use crate::test_support::{FakePlatform, loopback_listener};

    async fn within<T>(work: impl Future<Output = T>) -> T {
        timeout(Duration::from_secs(20), work)
            .await
            .expect("the exchange did not finish")
    }

    async fn dial(addr: SocketAddr) -> BoxStream {
        let opts = SockOpts {
            tfo: true,
            ..SockOpts::default()
        };
        Sockets::new(Arc::new(FakePlatform::default()) as Arc<dyn Platform>)
            .connect_stream(addr, &opts)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn split_halves_carry_both_directions_and_half_close() {
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            peer.read_to_end(&mut got).await.unwrap();
            peer.write_all(b"pong").await.unwrap();
            got
        });
        within(async {
            let stream = dial(addr).await;
            assert_eq!(stream.peer_addr(), Some(addr));
            let (mut read, mut write) = stream.into_split();
            write.write_all(b"ping").await.unwrap();
            write.write_all(b" again").await.unwrap();
            write.shutdown().await.unwrap();
            let mut reply = Vec::new();
            read.read_to_end(&mut reply).await.unwrap();
            assert_eq!(server.await.unwrap(), b"ping again");
            assert_eq!(reply, b"pong");
        })
        .await;
    }

    #[tokio::test]
    async fn a_shutdown_before_any_write_still_reaches_the_peer() {
        let (listener, addr) = loopback_listener().await;
        within(async {
            let mut stream = dial(addr).await;
            stream.shutdown().await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            peer.read_to_end(&mut got).await.unwrap();
            assert!(got.is_empty());
        })
        .await;
    }

    /// As sing-box's `slowOpenConn.Read`, a read waits for the write that starts the connection.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_read_before_any_write_waits_for_it() {
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"hello").await.unwrap();
            let mut got = [0; 5];
            peer.read_exact(&mut got).await.unwrap();
            got
        });
        within(async {
            let (mut read, mut write) = dial(addr).await.into_split();
            let mut greeting = [0; 5];
            let early = timeout(Duration::from_millis(300), read.read_exact(&mut greeting));
            assert!(early.await.is_err(), "a read started the connection");
            write.write_all(b"world").await.unwrap();
            read.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"hello");
            assert_eq!(&server.await.unwrap(), b"world");
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    fn preconnected(target: SocketAddr) -> FastOpenStream {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.set_nonblocking(true).unwrap();
        assert!(concord_platform::preconnect(&socket, target).unwrap());
        FastOpenStream::new(TcpStream::from_std(socket.into()).unwrap(), target)
    }

    /// Only 127.0.0.1 is assigned on lo0 by default, so a SYN to 127.0.0.2 goes unanswered and
    /// the connection stays in SYN-SENT; a full accept queue would answer with a reset instead.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn writes_and_shutdown_wait_while_the_syn_goes_unanswered() {
        let silent = SocketAddr::from(([127, 0, 0, 2], 9));
        let probe = tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&silent, Duration::from_millis(300))
        });
        match probe.await.unwrap() {
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {}
            other => {
                eprintln!("skipped: a SYN to {silent} is answered here ({other:?})");
                return;
            }
        }
        let mut stream = preconnected(silent);
        assert!(stream.needs_handshake());
        within(stream.write_all(b"first")).await.unwrap();
        assert!(!stream.needs_handshake());
        assert!(stream.tcp().is_none());
        let second = timeout(Duration::from_millis(300), stream.write_all(b"second"));
        assert!(
            second.await.is_err(),
            "a write did not wait for the handshake"
        );
        let shutdown = timeout(Duration::from_millis(300), stream.shutdown());
        assert!(
            shutdown.await.is_err(),
            "a shutdown did not wait for the handshake"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn writes_after_the_first_go_out_in_order() {
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            peer.read_to_end(&mut got).await.unwrap();
            got
        });
        within(async {
            let mut stream = preconnected(addr);
            stream.write_all(b"first").await.unwrap();
            stream.write_all(b"second").await.unwrap();
            stream.shutdown().await.unwrap();
            assert!(stream.tcp().is_some());
            assert_eq!(server.await.unwrap(), b"firstsecond");
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_refused_connection_fails_later_writes_and_the_shutdown() {
        let refused = {
            let (listener, addr) = loopback_listener().await;
            drop(listener);
            addr
        };
        within(async {
            let mut stream = preconnected(refused);
            stream.write_all(b"first").await.unwrap();
            assert!(stream.write_all(b"second").await.is_err());
            assert!(stream.shutdown().await.is_err());
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_connection_written_once_and_then_read_opens() {
        let (listener, addr) = loopback_listener().await;
        tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0; 7];
            peer.read_exact(&mut request).await.unwrap();
            peer.write_all(b"reply").await.unwrap();
            peer
        });
        within(async {
            let mut stream = preconnected(addr);
            stream.write_all(b"request").await.unwrap();
            let mut reply = [0; 5];
            stream.read_exact(&mut reply).await.unwrap();
            assert!(stream.tcp().is_some());
            assert!(Box::new(stream).into_tcp().is_ok());
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_failed_preconnect_connects_a_fresh_socket() {
        let (listener, addr) = loopback_listener().await;
        let listening =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        listening
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        listening.listen(1).unwrap();
        let fresh = || {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        };
        let Start::Connect(socket) = start(listening, addr, fresh).unwrap() else {
            panic!("a listening socket was preconnected");
        };
        within(async {
            let (connected, accepted) = tokio::join!(
                tokio::net::TcpSocket::from_std_stream(socket.into()).connect(addr),
                listener.accept()
            );
            connected.unwrap();
            accepted.unwrap();
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_empty_first_write_starts_the_connection() {
        let (listener, addr) = loopback_listener().await;
        within(async {
            let mut stream = preconnected(addr);
            assert_eq!(stream.write(b"").await.unwrap(), 0);
            assert!(!stream.needs_handshake());
            let (mut peer, _) = listener.accept().await.unwrap();
            stream.write_all(b"later").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut got = Vec::new();
            peer.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"later");
        })
        .await;
    }
}

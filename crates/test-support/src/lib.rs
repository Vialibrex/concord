//! Helpers that several crates' tests share. A dev-dependency only.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, RwLock};
use std::thread;

use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// A loopback TCP port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A loopback port, free for TCP and UDP, for a listener the code under test binds only later.
/// It lies below the range the OS hands out to `bind(0)` and to outgoing connections (from 32768
/// on Linux, 49152 on macOS), where [`free_port`]'s come from and where any socket the run opens
/// meanwhile could take it. Each call in a process gets a different port.
#[expect(
    clippy::disallowed_methods,
    reason = "a loopback probe is never protected"
)]
pub fn port_to_bind_later() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let first = 20_000 + u16::try_from(std::process::id() % 4_000).unwrap_or_default();
    (0..8_000)
        .map(|_| first + NEXT.fetch_add(1, Ordering::Relaxed) % 8_000)
        .find(|&port| {
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
                && std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
        })
        .expect("no loopback port free below the ephemeral range")
}

/// A connected loopback TCP pair: the dialing end, then the accepted end.
#[expect(
    clippy::disallowed_methods,
    reason = "a loopback test pair is never protected"
)]
pub async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dialing = TcpStream::connect(listener.local_addr().unwrap());
    let (dialed, accepted) = tokio::join!(dialing, listener.accept());
    (dialed.unwrap(), accepted.unwrap().0)
}

/// The blocking form of [`tcp_pair`].
#[expect(
    clippy::disallowed_methods,
    reason = "a loopback test pair is never protected"
)]
pub fn std_tcp_pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let dialed = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    (dialed, accepted)
}

/// Dials a loopback test server.
#[expect(
    clippy::disallowed_methods,
    reason = "a loopback test peer is never protected"
)]
pub async fn tcp_connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

/// The value of the environment variable that names an external test peer. An ignored test
/// that needs the peer fails without it rather than passing silently.
pub fn peer(variable: &str) -> String {
    std::env::var(variable)
        .unwrap_or_else(|_| panic!("{variable} is not set; this test needs that peer"))
}

/// A loopback TCP server that sends every byte back and closes after the peer does.
pub async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

#[allow(
    clippy::disallowed_methods,
    reason = "a loopback test peer is never protected"
)]
pub async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    addr
}

/// Poisons `mutex` as a task that panics while holding it does.
#[allow(
    clippy::disallowed_methods,
    reason = "only a panic inside a std lock call poisons the lock"
)]
pub fn poison<T: ?Sized + Send>(mutex: &Mutex<T>) {
    thread::scope(|scope| {
        let holder = scope.spawn(|| {
            let _held = mutex.lock();
            panic!("a lock holder panics");
        });
        assert!(holder.join().is_err());
    });
    assert!(mutex.is_poisoned());
}

/// Poisons `rwlock` as a writer that panics while holding it does.
#[allow(
    clippy::disallowed_methods,
    reason = "only a panic inside a std lock call poisons the lock"
)]
pub fn poison_rwlock<T: ?Sized + Send + Sync>(rwlock: &RwLock<T>) {
    thread::scope(|scope| {
        let holder = scope.spawn(|| {
            let _held = rwlock.write();
            panic!("a lock holder panics");
        });
        assert!(holder.join().is_err());
    });
    assert!(rwlock.is_poisoned());
}

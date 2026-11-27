#![allow(
    clippy::disallowed_methods,
    reason = "test clients dial loopback directly"
)]

mod common;

use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;

use common::*;
use concord_common::Tasks;
use concord_inbound::{
    ListenError, ListenSpec, ListenerId, Listeners, NamedListener, ProxyAuth, Service,
};
use concord_test_support::free_port;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn named(name: &str, bind: SocketAddr, service: Service) -> NamedListener {
    NamedListener {
        id: ListenerId::Named(name.into()),
        name: name.into(),
        label: format!("{name} listener"),
        binds: vec![bind],
        routing_mark: 0,
        special: None,
        service,
    }
}

fn socks() -> Service {
    Service::Socks {
        auth: ProxyAuth::Open,
        udp: false,
    }
}

async fn apply(
    listeners: &Listeners,
    named: Vec<NamedListener>,
    fake: &Arc<Fake>,
) -> Vec<ListenError> {
    listeners
        .reconcile_with(
            &ListenSpec::default(),
            named,
            fake.clone(),
            Tasks::default(),
        )
        .await
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn a_named_listener_takes_its_new_service_on_the_socket_it_kept() {
    let addr = loopback(free_port());
    let (listeners, fake) = (Listeners::new(), Fake::echo());
    assert!(
        apply(&listeners, vec![named("side", addr, socks())], &fake)
            .await
            .is_empty()
    );
    let mut live = socks5_session(addr, "keep.test", 80).await;
    assert_eq!(&*fake.flow(0).inbound.name, "side");

    let http = Service::Http(ProxyAuth::Open);
    assert!(
        apply(&listeners, vec![named("side", addr, http)], &fake)
            .await
            .is_empty()
    );
    live.write_all(b"still").await.unwrap();
    assert_eq!(read_exact(&mut live, 5).await, b"still");
    let mut fresh = connect(addr).await;
    fresh
        .write_all(b"CONNECT next.test:80 HTTP/1.1\r\nHost: next.test:80\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_until(&mut fresh, b"\r\n\r\n")
            .await
            .starts_with(b"HTTP/1.1 200")
    );
}

#[tokio::test]
async fn a_named_port_that_could_not_bind_is_tried_again_and_its_neighbour_runs() {
    let taken = StdListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap();
    let free = loopback(free_port());
    let (listeners, fake) = (Listeners::new(), Fake::echo());
    let wanted = || vec![named("busy", busy, socks()), named("free", free, socks())];

    let errors = apply(&listeners, wanted(), &fake).await;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].id, ListenerId::Named("busy".into()));
    assert_eq!(errors[0].source.kind(), io::ErrorKind::AddrInUse);
    drop(socks5_session(free, "up.test", 80).await);

    drop(taken);
    assert!(apply(&listeners, wanted(), &fake).await.is_empty());
    drop(socks5_session(busy, "late.test", 80).await);
}

#[tokio::test]
async fn stopping_releases_every_named_port() {
    let addr = loopback(free_port());
    let (listeners, fake) = (Listeners::new(), Fake::echo());
    assert!(
        apply(&listeners, vec![named("side", addr, socks())], &fake)
            .await
            .is_empty()
    );
    listeners.stop_all().await;
    assert!(TcpStream::connect(addr).await.is_err());
    assert!(StdListener::bind(addr).is_ok(), "the port is still held");
}

#[tokio::test]
async fn a_listener_listed_twice_runs_once_and_its_port_is_still_released() {
    let addr = loopback(free_port());
    let (listeners, fake) = (Listeners::new(), Fake::echo());
    let tunnel = |addr| NamedListener {
        id: ListenerId::Tunnel(format!("tcp,{addr},example.com:80").into()),
        ..named("", addr, socks())
    };
    for _ in 0..2 {
        let errors = apply(&listeners, vec![tunnel(addr), tunnel(addr)], &fake).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(TcpStream::connect(addr).await.is_ok());
    }
    listeners.stop_all().await;
    assert!(StdListener::bind(addr).is_ok(), "the port is still held");
}

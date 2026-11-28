#![cfg(feature = "server")]
#![allow(
    clippy::disallowed_methods,
    reason = "the test talks to a loopback listener directly"
)]
//! A Shadowsocks 2022 server reads timestamps on the engine's clock. The vendored crate's
//! clock is process-wide and its clients stamp with it too, so this runs in a binary of its
//! own and seals every request before a server installs a clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use concord_common::packet::{PacketBuf, UdpPayload};
use concord_common::serve::{InboundCx, Peer, Protocol};
use concord_common::task::Tasks;
use concord_common::{BoxStream, ClockOffset, FlowHandler, FlowMeta, UdpFlow, UdpReply};
use concord_config::listener::{ListenerKind, SsServer};
use concord_platform::HomeDir;
use concord_proxy::server::{Carried, Keep, ServerEnv, build};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use shadowsocks::relay::udprelay::crypto_io::encrypt_client_payload;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CIPHER: CipherKind = CipherKind::AEAD2022_BLAKE3_AES_128_GCM;
const PASSWORD: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";

#[derive(Default)]
struct Flows(AtomicUsize);

impl FlowHandler for Flows {
    fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn handle_udp(&self, _flow: UdpFlow<'_>, _payload: UdpPayload<'_>, _reply: &Arc<dyn UdpReply>) {
    }
}

fn config() -> ServerConfig {
    ServerConfig::new(("127.0.0.1", 1), PASSWORD, CIPHER).unwrap()
}

fn server(offset: Duration) -> Protocol {
    let clock = Arc::new(ClockOffset::default());
    clock.set(i64::try_from(offset.as_nanos()).unwrap());
    let def = ListenerKind::Shadowsocks(SsServer {
        cipher: CIPHER.to_string(),
        password: PASSWORD.into(),
        users: Default::default(),
        udp: true,
        shadow_tls: None,
        mux: Default::default(),
    });
    let env = ServerEnv {
        home: &Arc::new(HomeDir::new(std::env::temp_dir())),
        tasks: &Tasks::default(),
        keep: &Keep::Named("ss".into()),
        carried: &Carried::default(),
        clock: &clock,
    };
    build(&def, &env).unwrap().unwrap()
}

async fn request() -> Vec<u8> {
    let (near, mut far) = tokio::io::duplex(64 * 1024);
    let context = Context::new_shared(ServerType::Local);
    let target = SsAddress::DomainNameAddress("example.com".into(), 443);
    let mut client = ProxyClientStream::from_stream(context, near, &config(), target);
    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();
    drop(client);
    let mut wire = Vec::new();
    far.read_to_end(&mut wire).await.unwrap();
    wire
}

fn datagram() -> Vec<u8> {
    let context = Context::new_shared(ServerType::Local);
    let mut control = UdpSocketControlData::default();
    control.client_session_id = 1;
    control.packet_id = 1;
    let mut out = BytesMut::new();
    encrypt_client_payload(
        &context,
        CIPHER,
        config().key(),
        &SsAddress::SocketAddress("1.1.1.1:53".parse().unwrap()),
        &control,
        &[],
        b"query",
        &mut out,
    );
    out.to_vec()
}

async fn serves_stream(protocol: &Protocol, wire: &[u8]) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(local).await.unwrap();
    let (accepted, src) = listener.accept().await.unwrap();
    client.write_all(wire).await.unwrap();
    let flows = Arc::new(Flows::default());
    let cx = Arc::new(InboundCx {
        name: "ss".into(),
        special: None,
        handler: flows.clone(),
        tasks: Tasks::default(),
    });
    let stream = protocol.stream.clone().unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        stream.serve(accepted, Peer { src, local }, cx),
    )
    .await
    .unwrap();
    flows.0.load(Ordering::Relaxed) == 1
}

#[tokio::test]
async fn an_aead_2022_server_reads_timestamps_on_the_engines_clock() {
    let wire = request().await;
    let packet = datagram();
    for (offset, accepted) in [(Duration::from_secs(300), false), (Duration::ZERO, true)] {
        let protocol = server(offset);
        assert_eq!(
            serves_stream(&protocol, &wire).await,
            accepted,
            "tcp, {offset:?} ahead"
        );
        let mut copy = PacketBuf::from_slice(&packet);
        let datagrams = protocol.datagram().unwrap();
        let opened = datagrams.open(&mut copy, "127.0.0.1:9".parse().unwrap());
        assert_eq!(opened.is_some(), accepted, "udp, {offset:?} ahead");
    }
}

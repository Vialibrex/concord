//! The sing-mux sessions a listener's clients open at `sp.mux.sing-box.arpa`, served as
//! mihomo's sing listener handler does (`listener/sing/sing.go:76-90`): every stream of a
//! session is a request of its own, handed on as the listener hands on any other.

use std::sync::{Arc, Weak};

use concord_common::serve::{InboundCx, Peer};
use concord_common::{Address, BoxStream, InboundInfo};
use concord_config::listener::MuxServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::flows;
use super::packets::{self, LengthFrames};
use crate::addr_codec::SOCKS;
use crate::uot::AddrFrames;
use crate::util::parse_bps;

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;
const BRUTAL_EXCHANGE: &str = "_BrutalBwExchange";

/// A listener's `mux-option`, with its rates read.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct MuxServe {
    padding: bool,
    brutal: Option<Brutal>,
}

#[derive(Debug, PartialEq, Eq)]
struct Brutal {
    send_bps: u64,
    receive_bps: u64,
}

impl MuxServe {
    pub(super) fn new(config: &MuxServer) -> Arc<Self> {
        Arc::new(MuxServe {
            padding: config.padding,
            brutal: config.brutal.as_ref().map(|brutal| Brutal {
                send_bps: parse_bps(&brutal.up),
                receive_bps: parse_bps(&brutal.down),
            }),
        })
    }
}

/// What the sing-mux sessions of one connection may use: the listener's `mux-option`
/// and, for Brutal, the connection's socket where the session runs on it bare.
#[derive(Clone)]
pub(super) struct Mux {
    serve: Arc<MuxServe>,
    socket: Option<Arc<std::net::TcpStream>>,
}

impl Mux {
    /// A session here cannot run Brutal, as one nested in TLS, a carrier, QUIC or another
    /// mux cannot in mihomo (`brutal_linux.go:24-30`).
    pub(super) fn new(serve: &Arc<MuxServe>) -> Self {
        Mux {
            serve: serve.clone(),
            socket: None,
        }
    }

    /// A session nested in one of this connection's.
    pub(super) fn nested(&self) -> Self {
        Mux::new(&self.serve)
    }

    /// The protocol runs on `stream` itself. The socket is duplicated only for a listener
    /// that runs Brutal.
    pub(super) fn over(serve: &Arc<MuxServe>, stream: &tokio::net::TcpStream) -> Self {
        Mux {
            serve: serve.clone(),
            socket: serve.brutal.as_ref().and_then(|_| duplicate(stream)),
        }
    }
}

#[cfg(unix)]
fn duplicate(stream: &tokio::net::TcpStream) -> Option<Arc<std::net::TcpStream>> {
    use std::os::fd::AsFd;

    let fd = stream.as_fd().try_clone_to_owned().ok()?;
    Some(Arc::new(std::net::TcpStream::from(fd)))
}

#[cfg(not(unix))]
fn duplicate(_stream: &tokio::net::TcpStream) -> Option<Arc<std::net::TcpStream>> {
    None
}

/// Runs one session until it ends. Its streams reach the socket weakly, so the duplicate
/// closes with the session.
pub(super) async fn serve(
    stream: BoxStream,
    inbound: InboundInfo,
    peer: Peer,
    cx: Arc<InboundCx>,
    mux: Mux,
) {
    let socket = mux.socket.as_ref().map(Arc::downgrade);
    let on_stream = |stream| {
        let served = Served {
            inbound: inbound.clone(),
            peer,
            cx: cx.clone(),
            serve: mux.serve.clone(),
            socket: socket.clone(),
        };
        cx.tasks.spawn(served.stream(stream));
    };
    let padding = mux.serve.padding;
    let served = concord_transport::serve_mux_session(stream, padding, &cx.tasks, &on_stream);
    if let Err(err) = served.await {
        tracing::debug!("{}: sing-mux session: {err}", inbound.name);
    }
}

struct Served {
    inbound: InboundInfo,
    peer: Peer,
    cx: Arc<InboundCx>,
    serve: Arc<MuxServe>,
    socket: Option<Weak<std::net::TcpStream>>,
}

impl Served {
    /// `ReadStreamRequest` (`protocol.go:116-135`) and the stream's handling
    /// (`server.go:87-151`).
    async fn stream(self, mut stream: BoxStream) {
        let Ok(flags) = stream.read_u16().await else {
            return;
        };
        let Ok(dst) = SOCKS.read(&mut stream).await else {
            return;
        };
        let (inbound, src, cx) = (self.inbound.clone(), self.peer.src, self.cx.clone());
        if flags & FLAG_UDP == 0 {
            if matches!(&dst, Address::Domain(host, _) if host.as_str() == BRUTAL_EXCHANGE) {
                self.brutal_exchange(stream).await;
            } else {
                let mux = Mux::new(&self.serve);
                flows::tcp(stream, dst, inbound, self.peer, &cx, &mux);
            }
        } else if flags & FLAG_ADDR == 0 {
            packets::serve(stream, LengthFrames, LengthFrames, dst, inbound, src, cx).await;
        } else {
            let frames = AddrFrames(SOCKS);
            packets::serve(stream, frames, frames, dst, inbound, src, cx).await;
        }
    }

    /// The client's receive rate in, `WriteBrutalResponse` out (`server.go:100-134`,
    /// `brutal.go:22-41`): the server sends at the lower of its `up` and that rate.
    async fn brutal_exchange(self, mut stream: BoxStream) {
        let Ok(client_receive) = stream.read_u64().await else {
            return;
        };
        let response = match &self.serve.brutal {
            None => refused("brutal is not enabled by the server"),
            Some(brutal) => {
                let socket = self.socket.as_ref().and_then(Weak::upgrade);
                let set = match socket {
                    None => Err("brutal: nested multiplexing is not supported".to_owned()),
                    Some(socket) => {
                        let send = brutal.send_bps.min(client_receive);
                        concord_platform::set_brutal(&socket, send).map_err(|err| err.to_string())
                    }
                };
                match set {
                    Ok(()) => [&[1][..], &brutal.receive_bps.to_be_bytes()].concat(),
                    Err(err) => refused(&format!("enable TCP Brutal: {err}")),
                }
            }
        };
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    }
}

fn refused(message: &str) -> Vec<u8> {
    let mut out = vec![0];
    let mut len = message.len();
    loop {
        let [low, ..] = len.to_le_bytes();
        len >>= 7;
        if len == 0 {
            out.push(low & 0x7f);
            break;
        }
        out.push(low | 0x80);
    }
    out.extend_from_slice(message.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use concord_common::{InboundKind, Tasks};
    use concord_config::listener::MuxBrutal;
    use concord_transport::{MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions};

    use super::super::quic_testing::Flows;
    use super::*;

    const PROTOCOLS: [MuxProtocol; 3] = [MuxProtocol::Smux, MuxProtocol::Yamux, MuxProtocol::H2Mux];

    fn client(flows: &Arc<Flows>, mux: MuxServer, options: SingMuxOptions) -> Arc<SingMuxClient> {
        let cx = Arc::new(InboundCx {
            name: "in".into(),
            special: None,
            handler: flows.clone(),
            tasks: Tasks::default(),
        });
        let mux = MuxServe::new(&mux);
        let dial: MuxDialFn = Arc::new(move |_| {
            let (near, far) = tokio::io::duplex(1 << 16);
            let peer = Peer {
                src: "10.0.0.2:4000".parse().unwrap(),
                local: "10.0.0.1:443".parse().unwrap(),
            };
            let inbound = cx.inbound(InboundKind::Vmess, peer.local, Some("alice".into()));
            cx.tasks.spawn(serve(
                Box::new(far),
                inbound,
                peer,
                cx.clone(),
                Mux::new(&mux),
            ));
            Box::pin(async move { Ok(Box::new(near) as BoxStream) })
        });
        SingMuxClient::new(options, dial, Tasks::default())
    }

    fn options(protocol: MuxProtocol, padding: bool) -> SingMuxOptions {
        SingMuxOptions {
            protocol,
            padding,
            max_connections: 1,
            ..SingMuxOptions::default()
        }
    }

    #[tokio::test]
    async fn each_stream_is_handed_on_as_a_flow_of_the_listener() {
        for protocol in PROTOCOLS {
            let flows = Arc::new(Flows::default());
            let client = client(&flows, MuxServer::default(), options(protocol, false));
            let dst = Address::new("example.com", 443);
            let mut tcp = client.connect_tcp(&dst).await.unwrap();
            tcp.write_all(b"x").await.unwrap();
            let opened = flows.wait_for(1).await;
            assert_eq!(opened, [(dst, Some(Arc::from("alice")))], "{protocol:?}");

            let mut udp = client
                .connect_udp(&Address::new("8.8.8.8", 53))
                .await
                .unwrap();
            udp.write_all(&[0, 1, b'q']).await.unwrap();
            let mut packets = client.listen_packet(None).await.unwrap();
            let to = Address::new("1.1.1.1", 53);
            let mut packet = vec![0u8; SOCKS.len(&to)];
            SOCKS.write_into(&to, &mut packet).unwrap();
            packet.extend_from_slice(&[0, 1, b'p']);
            packets.write_all(&packet).await.unwrap();
            assert_eq!(flows.datagrams(2).await.len(), 2, "{protocol:?}");
        }
    }

    #[tokio::test]
    async fn a_listener_that_pads_takes_only_padded_sessions() {
        let padded = MuxServer {
            padding: true,
            brutal: None,
        };
        for protocol in PROTOCOLS {
            let flows = Arc::new(Flows::default());
            let plain = client(&flows, padded.clone(), options(protocol, false));
            let refused = async {
                let mut tcp = plain.connect_tcp(&Address::new("example.com", 80)).await?;
                tcp.write_all(b"x").await?;
                tcp.read_u8().await
            };
            assert!(refused.await.is_err(), "{protocol:?}");
            assert!(flows.opened().is_empty());

            let client = client(&flows, padded.clone(), options(protocol, true));
            let mut tcp = client
                .connect_tcp(&Address::new("example.com", 80))
                .await
                .unwrap();
            tcp.write_all(b"x").await.unwrap();
            flows.wait_for(1).await;
        }
    }

    fn brutal() -> MuxServer {
        MuxServer {
            padding: false,
            brutal: Some(MuxBrutal {
                up: "10".into(),
                down: "10".into(),
            }),
        }
    }

    async fn exchange_refusal(mux: MuxServer) -> String {
        let flows = Arc::new(Flows::default());
        let mut options = options(MuxProtocol::Smux, false);
        options.brutal = Some(concord_transport::Brutal {
            send_bps: 1,
            receive_bps: 1,
        });
        let client = client(&flows, mux, options);
        match client.connect_tcp(&Address::new("example.com", 80)).await {
            Ok(_) => panic!("the exchange succeeded"),
            Err(err) => err.to_string(),
        }
    }

    #[tokio::test]
    async fn a_brutal_exchange_is_refused_where_the_listener_does_not_run_brutal() {
        let refusal = exchange_refusal(MuxServer::default()).await;
        assert!(
            refusal.contains("brutal is not enabled by the server"),
            "{refusal}"
        );
    }

    #[tokio::test]
    async fn a_session_away_from_the_socket_refuses_brutal() {
        let refusal = exchange_refusal(brutal()).await;
        assert!(
            refusal.contains("enable TCP Brutal: brutal: nested"),
            "{refusal}"
        );
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use concord_common::serve::{InboundCx, Peer, ServeFuture};
use concord_common::{Address, BoxStream, InboundKind};
use concord_config::listener::VlessUser;
use concord_tls::TlsConn;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use super::front::Conn;
use super::mux::{Mux, MuxServe};
use super::{bounded, flows, unread, user};
use crate::addr_codec::VMESS;
use crate::lazy::HeadFirst;
use crate::vless::{CMD_MUX, CMD_TCP, CMD_UDP, FLOW_VISION, Vision};
use crate::vmess::crypto::user_id;

const VERSION: u8 = 0;
/// The response header: the version and no addons, sent with the first reply bytes.
const RESPONSE: [u8; 2] = [VERSION, 0];

/// mihomo's VLESS service (`listener/sing_vless/service.go`), with the `xtls-rprx-vision`
/// flow.
pub(super) struct Vless {
    users: HashMap<[u8; 16], Account>,
    /// Some user's flow is Vision, so the listener's TLS keeps its own record layer.
    vision: bool,
    mux: Arc<MuxServe>,
}

struct Account {
    name: Option<Arc<str>>,
    vision: bool,
}

impl Vless {
    pub(super) fn new(users: &[VlessUser]) -> Self {
        let users: HashMap<_, _> = users
            .iter()
            .map(|entry| {
                let account = Account {
                    name: user(&entry.username),
                    vision: entry.flow == FLOW_VISION,
                };
                (user_id(&entry.uuid), account)
            })
            .collect();
        Vless {
            vision: users.values().any(|account| account.vision),
            users,
            mux: Arc::default(),
        }
    }

    /// The listener's `mux-option`; without it, sing-mux sessions neither pad nor run Brutal.
    pub(super) fn with_mux(mut self, mux: Arc<MuxServe>) -> Self {
        self.mux = mux;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Plain,
    Vision,
}

struct Request {
    id: [u8; 16],
    user: Option<Arc<str>>,
    flow: Flow,
    command: u8,
    dst: Address,
}

impl Vless {
    async fn request<R: AsyncRead + Unpin>(&self, io: &mut R) -> Option<Request> {
        if io.read_u8().await.ok()? != VERSION {
            return None;
        }
        let mut id = [0u8; 16];
        io.read_exact(&mut id).await.ok()?;
        let mut addons = vec![0u8; usize::from(io.read_u8().await.ok()?)];
        io.read_exact(&mut addons).await.ok()?;
        let flow = match addon_flow(&addons) {
            [] => Flow::Plain,
            flow if flow == FLOW_VISION.as_bytes() => Flow::Vision,
            _ => return None,
        };
        let command = io.read_u8().await.ok()?;
        let dst = if command == CMD_MUX {
            Address::new("v1.mux.cool", 0)
        } else {
            VMESS.read(io).await.ok()?
        };
        let account = self.users.get(&id)?;
        // `service.go:115-119`: a request without a flow is taken from any user.
        if flow == Flow::Vision && !account.vision {
            return None;
        }
        Some(Request {
            id,
            user: account.name.clone(),
            flow,
            command,
            dst,
        })
    }
}

fn relay(stream: BoxStream, request: Request, peer: Peer, cx: &Arc<InboundCx>, mux: &Mux) {
    let inbound = cx.inbound(InboundKind::Vless, peer.local, request.user);
    match (request.command, request.flow) {
        (CMD_TCP | CMD_MUX, _) => flows::tcp(stream, request.dst, inbound, peer, cx, mux),
        (CMD_UDP, Flow::Plain) => flows::udp(stream, request.dst, inbound, peer, cx),
        (CMD_UDP, Flow::Vision) => {
            tracing::debug!("{}: xtls-rprx-vision flow does not support UDP", cx.name);
        }
        (command, _) => tracing::debug!("{}: VLESS command {command} is not served", cx.name),
    }
}

/// The `flow` of the request's addons, protobuf field 1; any other field is skipped.
fn addon_flow(mut addons: &[u8]) -> &[u8] {
    while let [tag, rest @ ..] = addons {
        let Some((&len, rest)) = rest.split_first() else {
            return &[];
        };
        let len = usize::from(len);
        let Some((value, rest)) = rest.split_at_checked(len) else {
            return &[];
        };
        if *tag == 0x0a {
            return value;
        }
        addons = rest;
    }
    &[]
}

impl Conn for Vless {
    fn mux(&self) -> &Arc<MuxServe> {
        &self.mux
    }

    fn handle(
        self: Arc<Self>,
        stream: BoxStream,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture {
        Box::pin(async move {
            let mut buffered = BufReader::with_capacity(512, stream);
            let Some(request) = bounded(self.request(&mut buffered)).await else {
                return;
            };
            if request.flow == Flow::Vision {
                tracing::debug!(
                    "{}: failed to use vision, maybe \"tls\" is not enable and \"encryption\" is empty",
                    cx.name
                );
                return;
            }
            let stream: BoxStream = Box::new(HeadFirst::new(unread(buffered), RESPONSE.to_vec()));
            relay(stream, request, peer, &cx, &mux);
        })
    }

    fn takes_records(&self) -> bool {
        self.vision
    }

    /// The request header is read straight from the records, so that nothing past it is
    /// buffered outside the TLS when Vision takes its halves.
    fn handle_tls(
        self: Arc<Self>,
        mut tls: TlsConn,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture {
        Box::pin(async move {
            let Some(request) = bounded(self.request(&mut tls)).await else {
                return;
            };
            let stream: BoxStream = match request.flow {
                Flow::Plain => Box::new(HeadFirst::new(tls, RESPONSE.to_vec())),
                Flow::Vision => match Vision::serve(tls, RESPONSE.to_vec(), request.id) {
                    Ok(vision) => Box::new(vision),
                    Err(err) => {
                        tracing::debug!("{}: initialize vision: {err}", cx.name);
                        return;
                    }
                },
            };
            relay(stream, request, peer, &cx, &mux);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flow_is_read_from_the_addons() {
        let addons = [0x0a, 3, b'a', b'b', b'c', 0x12, 1, 9];
        assert_eq!(addon_flow(&addons), b"abc");
        assert_eq!(addon_flow(&[0x12, 1, 9, 0x0a, 1, b'x']), b"x");
        assert_eq!(addon_flow(&[0x0a, 9]), b"");
        assert_eq!(addon_flow(&[]), b"");
    }

    const PLAIN: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const VISION: &str = "0b2d7c4e-8f1a-4c3b-9d6e-5a4f3e2d1c0b";

    fn server() -> Vless {
        let user = |name: &str, uuid: &str, flow: &str| VlessUser {
            username: name.into(),
            uuid: uuid.into(),
            flow: flow.into(),
        };
        Vless::new(&[user("pat", PLAIN, ""), user("vic", VISION, FLOW_VISION)])
    }

    /// A TCP request to 1.2.3.4:80 from `uuid`, with `flow` in its addons.
    fn header(uuid: &str, flow: &str) -> Vec<u8> {
        let mut header = vec![VERSION];
        header.extend_from_slice(&user_id(uuid));
        let mut addons = Vec::new();
        if !flow.is_empty() {
            addons.extend_from_slice(&[0x0a, u8::try_from(flow.len()).unwrap()]);
            addons.extend_from_slice(flow.as_bytes());
        }
        header.push(u8::try_from(addons.len()).unwrap());
        header.extend_from_slice(&addons);
        header.extend_from_slice(&[CMD_TCP, 0, 80, 1, 1, 2, 3, 4]);
        header
    }

    async fn taken(header: Vec<u8>) -> Option<(Option<Arc<str>>, Flow)> {
        let request = server().request(&mut header.as_slice()).await?;
        Some((request.user, request.flow))
    }

    #[tokio::test]
    async fn a_request_is_taken_by_its_users_flow_as_mihomo_takes_it() {
        assert_eq!(
            taken(header(PLAIN, "")).await,
            Some((Some("pat".into()), Flow::Plain))
        );
        assert_eq!(
            taken(header(VISION, FLOW_VISION)).await,
            Some((Some("vic".into()), Flow::Vision))
        );
        assert_eq!(
            taken(header(VISION, "")).await,
            Some((Some("vic".into()), Flow::Plain))
        );
        assert_eq!(taken(header(PLAIN, FLOW_VISION)).await, None);
        assert_eq!(taken(header(VISION, "xtls-rprx-direct")).await, None);
        assert_eq!(
            taken(header("00000000-0000-0000-0000-000000000000", "")).await,
            None
        );
    }
}

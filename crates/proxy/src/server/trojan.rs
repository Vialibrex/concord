use std::collections::HashMap;
use std::sync::Arc;

use concord_common::serve::{InboundCx, Peer, ServeFuture};
use concord_common::{Address, BoxStream, InboundKind};
use concord_config::listener::TrojanUser;
use tokio::io::{AsyncReadExt, BufReader};

use super::front::Conn;
use super::mux::{Mux, MuxServe};
use super::{bounded, flows, packets, unread, user};
use crate::addr_codec::SOCKS;
use crate::trojan::{CMD_TCP, CMD_UDP, TrojanFrames, password_key};

/// mihomo's trojan listener (`listener/trojan/server.go`): a key it does not know closes
/// the connection.
pub(super) struct Trojan {
    users: HashMap<[u8; 56], Option<Arc<str>>>,
    mux: Arc<MuxServe>,
}

impl Trojan {
    pub(super) fn new(users: &[TrojanUser]) -> Self {
        Trojan {
            users: users
                .iter()
                .map(|entry| (password_key(&entry.password), user(&entry.username)))
                .collect(),
            mux: Arc::default(),
        }
    }

    /// The listener's `mux-option`; without it, sing-mux sessions neither pad nor run Brutal.
    pub(super) fn with_mux(mut self, mux: Arc<MuxServe>) -> Self {
        self.mux = mux;
        self
    }
}

impl Trojan {
    /// The key, command and address of a request, and the user the key names.
    async fn request(
        &self,
        buffered: &mut BufReader<BoxStream>,
    ) -> Option<(Option<Arc<str>>, u8, Address)> {
        let mut key = [0u8; 58];
        buffered.read_exact(&mut key).await.ok()?;
        let user = self.users.get(key.get(..56)?)?.clone();
        let command = buffered.read_u8().await.ok()?;
        let dst = SOCKS.read(buffered).await.ok()?;
        let mut crlf = [0u8; 2];
        buffered.read_exact(&mut crlf).await.ok()?;
        Some((user, command, dst))
    }
}

impl Conn for Trojan {
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
            let Some((user, command, dst)) = bounded(self.request(&mut buffered)).await else {
                return;
            };
            let stream = unread(buffered);
            let inbound = cx.inbound(InboundKind::Trojan, peer.local, user);
            match command {
                CMD_TCP => flows::tcp(stream, dst, inbound, peer, &cx, &mux),
                CMD_UDP => {
                    cx.tasks.spawn(packets::serve(
                        stream,
                        TrojanFrames,
                        TrojanFrames,
                        dst,
                        inbound,
                        peer.src,
                        cx.clone(),
                    ));
                }
                _ => tracing::debug!("{}: trojan command {command} is not served", cx.name),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn a_known_key_names_its_user_and_the_rest_stays_unread() {
        let server = Trojan::new(&[
            TrojanUser {
                username: "alice".into(),
                password: "p1".into(),
            },
            TrojanUser {
                username: String::new(),
                password: "p2".into(),
            },
        ]);
        for (password, user) in [("p1", Some("alice")), ("p2", None)] {
            let (mut near, far) = tokio::io::duplex(1024);
            let mut wire = password_key(password).to_vec();
            wire.extend_from_slice(b"\r\n");
            wire.push(CMD_TCP);
            SOCKS
                .write(&Address::new("example.com", 443), &mut wire)
                .unwrap();
            wire.extend_from_slice(b"\r\nhello");
            near.write_all(&wire).await.unwrap();
            let mut buffered = BufReader::new(Box::new(far) as BoxStream);
            let (got, command, dst) = server.request(&mut buffered).await.unwrap();
            assert_eq!(got.as_deref(), user);
            assert_eq!(command, CMD_TCP);
            assert_eq!(dst, Address::new("example.com", 443));
            let mut rest = [0u8; 5];
            unread(buffered).read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest, b"hello");
        }
        let (mut near, far) = tokio::io::duplex(1024);
        near.write_all(&password_key("nobody")).await.unwrap();
        near.write_all(b"\r\n").await.unwrap();
        let mut buffered = BufReader::new(Box::new(far) as BoxStream);
        assert!(server.request(&mut buffered).await.is_none());
    }
}

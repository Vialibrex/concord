use std::collections::HashMap;
use std::sync::Arc;

use concord_common::serve::{InboundCx, Peer, ServeFuture};
use concord_common::{BoxStream, InboundInfo, InboundKind};
use concord_config::listener::AnyTlsServer;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use super::front::Conn;
use super::{ServerError, bounded, flows, unread, user};
use crate::addr_codec::SOCKS;
use crate::anytls::{AnyTlsStream, ServerPadding};

/// mihomo's anytls listener (`listener/anytls/server.go`): a password hash it does not know
/// closes the connection.
pub(super) struct AnyTls {
    users: HashMap<[u8; 32], Option<Arc<str>>>,
    padding: ServerPadding,
}

impl AnyTls {
    pub(super) fn new(server: &AnyTlsServer) -> Result<Self, ServerError> {
        let padding = ServerPadding::new(&server.padding_scheme)
            .ok_or_else(|| ServerError::Invalid("incorrect padding scheme format".into()))?;
        let users = server
            .users
            .iter()
            .map(|(name, password)| (Sha256::digest(password).into(), user(name)))
            .collect();
        Ok(AnyTls { users, padding })
    }

    /// The user the password hash names, once the padding after it is read.
    async fn authenticate<R: AsyncRead + Unpin>(&self, conn: &mut R) -> Option<Option<Arc<str>>> {
        let mut key = [0u8; 32];
        conn.read_exact(&mut key).await.ok()?;
        let user = self.users.get(&key)?.clone();
        let padding = u64::from(conn.read_u16().await.ok()?);
        let skipped = tokio::io::copy(&mut conn.take(padding), &mut tokio::io::sink())
            .await
            .ok()?;
        (skipped == padding).then_some(user)
    }
}

impl Conn for AnyTls {
    fn handle(self: Arc<Self>, stream: BoxStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture {
        Box::pin(async move {
            let mut buffered = BufReader::with_capacity(512, stream);
            let Some(user) = bounded(self.authenticate(&mut buffered)).await else {
                return;
            };
            let inbound = cx.inbound(InboundKind::AnyTls, peer.local, user);
            let tasks = cx.tasks.clone();
            self.padding.serve(unread(buffered), &tasks, move |stream| {
                cx.tasks
                    .spawn(relay(stream, inbound.clone(), peer, cx.clone()));
            });
        })
    }
}

/// One stream of the session: its destination, then the flow
/// (`listener/anytls/server.go:243-258`).
async fn relay(mut stream: AnyTlsStream, inbound: InboundInfo, peer: Peer, cx: Arc<InboundCx>) {
    let Ok(dst) = SOCKS.read(&mut stream).await else {
        return;
    };
    if stream.handshake_success().await.is_err() {
        return;
    }
    flows::tcp(Box::new(stream), dst, inbound, peer, &cx);
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;

    fn server() -> AnyTls {
        AnyTls::new(&AnyTlsServer {
            users: IndexMap::from([("alice".to_string(), "pw".to_string())]),
            padding_scheme: String::new(),
            tls: None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_known_hash_names_its_user_past_the_padding() {
        let mut wire = Sha256::digest("pw").to_vec();
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(b"padrest");
        let mut conn = wire.as_slice();
        let user = server().authenticate(&mut conn).await;
        assert_eq!(user, Some(Some(Arc::from("alice"))));
        assert_eq!(conn, b"rest");
    }

    #[tokio::test]
    async fn an_unknown_hash_or_short_padding_is_refused() {
        let mut unknown = Sha256::digest("other").to_vec();
        unknown.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(server().authenticate(&mut unknown.as_slice()).await, None);
        let mut short = Sha256::digest("pw").to_vec();
        short.extend_from_slice(&9u16.to_be_bytes());
        short.extend_from_slice(b"pad");
        assert_eq!(server().authenticate(&mut short.as_slice()).await, None);
    }

    #[test]
    fn a_scheme_that_does_not_parse_fails_the_listener() {
        let built = AnyTls::new(&AnyTlsServer {
            users: IndexMap::new(),
            padding_scheme: "0=1-2".into(),
            tls: None,
        });
        assert!(matches!(built, Err(ServerError::Invalid(_))));
    }
}

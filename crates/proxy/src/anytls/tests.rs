#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "the test runs a loopback server"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use concord_common::{Address, DialCx, Initiator, Outbound};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::ctx::BuildCtx;
use crate::testing::{HeldLookup, test_env};

/// A TLS server that takes every connection and reads what comes without answering.
async fn silent_server() -> (u16, Arc<AtomicUsize>) {
    let (config, _) = concord_test_support::localhost_tls(rustls::DEFAULT_VERSIONS);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = accepted.clone();
    tokio::spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(io).await {
                    let mut sink = Vec::new();
                    let _ = tls.read_to_end(&mut sink).await;
                }
            });
        }
    });
    (port, accepted)
}

fn node(port: u16) -> Arc<dyn Outbound> {
    let proxy = json!({
        "name": "a", "type": "anytls", "server": "localhost", "port": port, "password": "pw",
        "sni": "localhost", "skip-cert-verify": true,
    });
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("the proxy was quarantined");
    };
    let ProxyKind::AnyTls(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
}

#[tokio::test]
async fn a_session_made_across_a_reset_is_not_kept() {
    let (port, accepted) = silent_server().await;
    let outbound = node(port);
    let target = Address::new("example.test", 80);
    let held = HeldLookup::new();
    let straddling = {
        let (outbound, env, target) = (outbound.clone(), held.env(), target.clone());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            outbound.connect(&cx, &target).await.map(drop)
        })
    };
    held.entered().await;
    outbound.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    drop(outbound.connect(&cx, &target).await.unwrap());
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "the next stream went over the session made before the reset"
    );
    assert!(outcome.is_err());
}

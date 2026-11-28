use std::sync::Arc;
use std::time::Duration;

use concord_test_support::tcp_pair;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::support::{Ca, Sealer, key_pem_of, pem_of};
use crate::TlsConn;
use crate::policy::provider;
use crate::server::{Certs, ClientAuth, ServerOptions, TlsServer};

fn server(ca: &Ca) -> TlsServer {
    let leaf = ca.leaf(&["node.test"]);
    let certs = Certs::new(
        pem_of(leaf.leaf_der()).as_bytes(),
        key_pem_of(&leaf.key_der).as_bytes(),
    )
    .unwrap();
    TlsServer::new(&ServerOptions {
        certs: Arc::new(certs),
        client_auth: ClientAuth::None,
        client_ca_pem: None,
        alpn: vec![b"h2".to_vec()],
    })
    .unwrap()
}

async fn accepted(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> (TlsStream<TcpStream>, TlsConn) {
    let ca = Ca::new();
    let server = server(&ca);
    let mut roots = RootCertStore::empty();
    roots.add(ca.der.clone()).unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.enable_secret_extraction = true;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let (client, far) = tcp_pair().await;
    let name = ServerName::try_from("node.test").unwrap();
    let (client, served) = tokio::join!(
        connector.connect(name, client),
        server.accept_records(Box::new(far))
    );
    (client.unwrap(), served.unwrap())
}

async fn exchange(client: &mut TlsStream<TcpStream>, served: &mut TlsConn, up: &[u8], down: &[u8]) {
    client.write_all(up).await.unwrap();
    client.flush().await.unwrap();
    let mut got = vec![0u8; up.len()];
    served.read_exact(&mut got).await.unwrap();
    assert_eq!(got, up);
    served.write_all(down).await.unwrap();
    served.flush().await.unwrap();
    let mut got = vec![0u8; down.len()];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(got, down);
}

#[tokio::test]
async fn a_server_with_its_own_records_follows_a_client_key_update() {
    let (mut client, mut served) = accepted(&[&rustls::version::TLS13]).await;
    assert!(served.is_tls13());
    assert_eq!(served.negotiated_alpn(), Some(&b"h2"[..]));
    exchange(&mut client, &mut served, b"hello", b"world").await;
    client.get_mut().1.refresh_traffic_keys().unwrap();
    let large = vec![7u8; 100_000];
    exchange(&mut client, &mut served, &large, &large).await;
    assert!(served.at_record_boundary());
    assert!(!served.has_pending_plaintext());
}

#[tokio::test]
async fn a_tls12_client_gets_the_records_too() {
    let (mut client, mut served) = accepted(&[&rustls::version::TLS12]).await;
    assert!(!served.is_tls13());
    exchange(&mut client, &mut served, b"over", b"tls 1.2").await;
}

#[tokio::test]
async fn the_halves_of_a_served_connection_carry_each_way() {
    let (mut client, served) = accepted(&[&rustls::version::TLS13]).await;
    let (mut read, mut write) = served.into_halves().ok().unwrap();
    client.write_all(b"first").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0u8; 5];
    read.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"first");
    write.write_all(b"halves").await.unwrap();
    write.flush().await.unwrap();
    let mut got = [0u8; 6];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"halves");
}

/// Go's server answers a ticket from its client with an unexpected-message alert and fails;
/// this one fails without the alert.
#[tokio::test]
async fn a_ticket_from_the_client_fails_the_servers_read() {
    let (client, mut served) = accepted(&[&rustls::version::TLS13]).await;
    let (mut tcp, conn) = client.into_inner();
    let suite = conn.negotiated_cipher_suite().unwrap();
    let (seq, secrets) = conn.dangerous_extract_secrets().unwrap().tx;
    let encrypter = crate::record::test_encrypter(suite, secrets, seq).unwrap();
    let mut sealer = Sealer { encrypter, seq };
    let ticket = [u8::from(rustls::HandshakeType::NewSessionTicket), 0, 0, 0];
    tcp.write_all(&sealer.seal(rustls::ContentType::Handshake, &ticket))
        .await
        .unwrap();
    let read = tokio::time::timeout(Duration::from_secs(5), served.read(&mut [0u8; 1])).await;
    let err = read.expect("the ticket was taken").unwrap_err();
    assert!(
        err.to_string().contains("unexpected handshake message"),
        "{err}"
    );
}

/// A handshake that fails tells the client why, as tokio-rustls and Go do, rather than
/// closing in silence.
#[tokio::test]
async fn a_failed_handshake_sends_its_alert() {
    let server = server(&Ca::new());
    let (mut client, far) = tcp_pair().await;
    let short_hello = [22, 3, 1, 0, 5, 1, 0, 0, 1, 0];
    client.write_all(&short_hello).await.unwrap();
    let served = tokio::time::timeout(Duration::from_secs(5), server.accept_records(Box::new(far)));
    assert!(served.await.expect("the handshake stalled").is_err());
    let mut answer = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut answer))
        .await
        .expect("no alert came")
        .unwrap();
    assert_eq!(
        (answer[0], answer[5]),
        (u8::from(rustls::ContentType::Alert), 2),
        "{answer:?}"
    );
}

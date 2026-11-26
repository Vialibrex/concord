use std::sync::Arc;

use concord_test_support::localhost_tls;

pub fn endpoints_with_transport(
    server_transport: quinn::TransportConfig,
    client_transport: quinn::TransportConfig,
) -> (quinn::Endpoint, quinn::Endpoint) {
    let (mut server_tls, mut client_tls) = localhost_tls(&[&rustls::version::TLS13]);
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(server_transport));
    let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));
    config.transport_config(Arc::new(client_transport));
    client.set_default_client_config(config);
    (server, client)
}

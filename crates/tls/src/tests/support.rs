use std::sync::Arc;

use concord_common::BoxStream;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::task::JoinHandle;

use crate::{TlsConn, TlsConnector, TrustStore};

pub async fn connect_whole(
    connector: &TlsConnector,
    io: BoxStream,
    sni_fallback: &str,
) -> std::io::Result<TlsConn> {
    let mut io = Some(io);
    let dial = || {
        std::future::ready(
            io.take()
                .ok_or_else(|| std::io::Error::other("dialed twice")),
        )
    };
    connector.connect_whole_dialing(dial, sni_fallback).await
}

pub struct Ca {
    pub der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub key_der: Vec<u8>,
}

impl Leaf {
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    pub fn leaf_der(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }
}

impl Ca {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "concord test ca");
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().clone();
        Self {
            der,
            issuer: Issuer::new(params, key),
        }
    }

    pub fn trust(&self) -> Arc<TrustStore> {
        TrustStore::from_parts(Vec::new(), b"", vec![self.der.clone()])
    }

    pub fn leaf(&self, names: &[&str]) -> Leaf {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap_or_else(|_| CertificateParams::default());
        for name in names {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                params.subject_alt_names.push(SanType::IpAddress(ip));
            }
        }
        self.sign(params)
    }

    pub fn expired_leaf(&self, name: &str) -> Leaf {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.not_before = OffsetDateTime::now_utc() - Duration::days(30);
        params.not_after = OffsetDateTime::now_utc() - Duration::days(1);
        self.sign(params)
    }

    fn sign(&self, params: CertificateParams) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            chain: vec![cert.der().clone()],
            key_der: key.serialize_der(),
        }
    }

    pub fn with_intermediate(&self, names: &[&str]) -> (Leaf, CertificateDer<'static>) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "concord test intermediate");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.signed_by(&ca_key, &self.issuer).unwrap();
        let ca_der = ca_cert.der().clone();
        let intermediate = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        let leaf = params.signed_by(&leaf_key, &intermediate).unwrap();
        (
            Leaf {
                chain: vec![leaf.der().clone(), ca_der.clone()],
                key_der: leaf_key.serialize_der(),
            },
            ca_der,
        )
    }
}

#[derive(Debug)]
struct AnyClientCert;

impl ClientCertVerifier for AnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crate::policy::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone, Default)]
pub struct ServerSpec {
    pub alpn: Vec<&'static [u8]>,
    pub tls13_only: bool,
    pub request_client_cert: bool,
}

#[derive(Debug, Default, Clone)]
pub struct Seen {
    pub sni: Option<String>,
    pub alpn: Option<Vec<u8>>,
    pub client_cert: Option<Vec<u8>>,
}

pub fn server_config(leaf: &Leaf, spec: &ServerSpec) -> Arc<ServerConfig> {
    let provider = crate::policy::provider();
    let builder = ServerConfig::builder_with_provider(provider);
    let builder = if spec.tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .unwrap();
    let builder = if spec.request_client_cert {
        builder.with_client_cert_verifier(Arc::new(AnyClientCert))
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(leaf.chain.clone(), leaf.key())
        .unwrap();
    config.alpn_protocols = spec.alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A TLS echo server on one end of an in-memory pipe; returns the client end.
pub fn echo_server(config: Arc<ServerConfig>) -> (BoxStream, JoinHandle<Option<Seen>>) {
    let (client, server) = duplex(1 << 20);
    let handle = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(server)
            .await
            .ok()?;
        let (_, conn) = stream.get_ref();
        let seen = Seen {
            sni: conn.server_name().map(str::to_owned),
            alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
            client_cert: conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| cert.as_ref().to_vec()),
        };
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() || stream.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
        Some(seen)
    });
    (Box::new(client), handle)
}

pub fn pem_of(der: &CertificateDer<'_>) -> String {
    use base64_pem::encode;
    encode("CERTIFICATE", der.as_ref())
}

mod base64_pem {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    pub fn encode(label: &str, der: &[u8]) -> String {
        let body = STANDARD.encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }
}

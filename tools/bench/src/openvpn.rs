use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use rand::Rng;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::json;
use tokio::process::Child;

use crate::cases::{Case, Spec};
use crate::isolate::{self, Placement};

const READY: &str = "Initialization Sequence Completed";

const CA: &str = "ovpn-ca.pem";
const SERVER_CERT: &str = "ovpn-server.pem";
const SERVER_KEY: &str = "ovpn-server-key.pem";
const CLIENT_CERT: &str = "ovpn-client.pem";
const CLIENT_KEY: &str = "ovpn-client-key.pem";
const TLS_CRYPT: &str = "ovpn-tls-crypt.key";

/// A CA, a server and a client certificate with the key usages OpenVPN checks, and a
/// tls-crypt key in OpenVPN's static key format.
pub fn write_pki(dir: &Path) -> std::io::Result<()> {
    let io = std::io::Error::other;
    let mut ca = CertificateParams::new(Vec::new()).map_err(io)?;
    ca.distinguished_name = named("bench-ovpn-ca");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().map_err(io)?).map_err(io)?;
    std::fs::write(dir.join(CA), ca.pem())?;
    for (usage, name, cert, key) in [
        (
            ExtendedKeyUsagePurpose::ServerAuth,
            "bench-ovpn-server",
            SERVER_CERT,
            SERVER_KEY,
        ),
        (
            ExtendedKeyUsagePurpose::ClientAuth,
            "bench-ovpn-client",
            CLIENT_CERT,
            CLIENT_KEY,
        ),
    ] {
        let mut params = CertificateParams::new(Vec::new()).map_err(io)?;
        params.distinguished_name = named(name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let pair = KeyPair::generate().map_err(io)?;
        let made = params.signed_by(&pair, &ca).map_err(io)?;
        std::fs::write(dir.join(cert), made.pem())?;
        std::fs::write(dir.join(key), pair.serialize_pem())?;
    }
    let mut secret = [0u8; 256];
    rand::rng().fill_bytes(&mut secret);
    let mut text = String::from("-----BEGIN OpenVPN Static key V1-----\n");
    for line in secret.chunks(16) {
        let _ = writeln!(text, "{}", hex::encode(line));
    }
    text.push_str("-----END OpenVPN Static key V1-----\n");
    std::fs::write(dir.join(TLS_CRYPT), text)
}

/// rcgen gives every certificate the same default name, and a leaf named like its issuer reads
/// to OpenSSL as self-signed.
fn named(common: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common);
    name
}

/// The `openvpn` and `openvpn-tcp` cases: the core dials an OpenVPN 2.6 server beside the
/// origin, whose tunnel ends in the far namespace, so the origin's own address is reached
/// through it.
pub fn case(spec: Spec, host: &str, port: u16, certs: &Path) -> Option<Case> {
    let (proto, subnet) = match spec.name {
        "openvpn" => ("udp", 0),
        "openvpn-tcp" => ("tcp", 1),
        _ => return None,
    };
    let read = |name: &str| std::fs::read_to_string(certs.join(name)).unwrap_or_default();
    let server_proto = if proto == "udp" {
        "udp4"
    } else {
        "tcp4-server"
    };
    let path = |name: &str| certs.join(name).display().to_string();
    // Every core under test connects with the same client certificate and stays up for the
    // whole run; without duplicate-cn the server drops the older session for the newer one.
    let config = format!(
        "dev tun\ntopology subnet\nserver 10.8.{subnet}.0 255.255.255.0\nproto {server_proto}\n\
         local {host}\nport {port}\nca {}\ncert {}\nkey {}\ndh none\ntls-crypt {}\n\
         data-ciphers AES-256-GCM\nkeepalive 10 60\nduplicate-cn\ndisable-dco\nverb 3\n",
        path(CA),
        path(SERVER_CERT),
        path(SERVER_KEY),
        path(TLS_CRYPT),
    );
    Some(Case {
        openvpn: Some(config),
        proxy: Some(json!({
            "name": spec.name, "type": "openvpn", "server": host, "port": port, "proto": proto,
            "udp": true, "cipher": "AES-256-GCM", "ca": read(CA), "cert": read(CLIENT_CERT),
            "key": read(CLIENT_KEY), "tls-crypt": read(TLS_CRYPT),
        })),
        ..Case::bare(spec)
    })
}

/// Starts one OpenVPN server per OpenVPN case and waits until each has its tunnel up.
pub async fn start(
    cases: &[Case],
    ip: IpAddr,
    binary: Option<&Path>,
    dir: &Path,
    placement: &Placement,
) -> std::io::Result<Vec<(String, Child)>> {
    let fail = std::io::Error::other;
    let mut children = Vec::new();
    for case in cases {
        let Some(config) = &case.openvpn else {
            continue;
        };
        if ip.is_loopback() {
            return Err(fail(format!(
                "{} needs --netem: the tunnel ends beside the origin, and a loopback origin is \
                 not reachable through a tunnel device",
                case.name()
            )));
        }
        let binary = binary.ok_or_else(|| {
            fail(format!(
                "{} needs --openvpn (or CONCORD_OPENVPN) pointing to an OpenVPN 2.6 binary",
                case.name()
            ))
        })?;
        let file = dir.join(format!("server/{}.conf", case.name()));
        std::fs::write(&file, config)?;
        let log_path = dir.join(format!("logs/{}-openvpn.log", case.name()));
        let log = std::fs::File::create(&log_path)?;
        let mut command = isolate::command(binary, placement);
        command
            .arg("--config")
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        let mut child = isolate::spawn(&mut command, placement)
            .map_err(|error| fail(format!("spawn OpenVPN server: {error}")))?;
        let started = Instant::now();
        loop {
            let text = std::fs::read_to_string(&log_path).unwrap_or_default();
            if text.contains(READY) {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(fail(format!(
                    "the OpenVPN server for {} exited: {status}; see {}",
                    case.name(),
                    log_path.display()
                )));
            }
            if started.elapsed() > Duration::from_secs(10) {
                return Err(fail(format!(
                    "the OpenVPN server for {} did not come up in 10 s; see {}",
                    case.name(),
                    log_path.display()
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        children.push((case.name().to_string(), child));
    }
    Ok(children)
}

pub fn exited(servers: &mut [(String, Child)]) -> Option<String> {
    servers.iter_mut().find_map(|(name, server)| {
        let status = server.try_wait().ok()??;
        Some(format!(
            "the OpenVPN server for {name} exited: {status}; see logs/{name}-openvpn.log"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pki_verifies_against_its_ca() {
        let dir = std::env::temp_dir().join(format!("bench-ovpn-pki-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_pki(&dir).unwrap();
        for leaf in [SERVER_CERT, CLIENT_CERT] {
            let out = std::process::Command::new("openssl")
                .arg("verify")
                .arg("-CAfile")
                .arg(dir.join(CA))
                .arg(dir.join(leaf))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{leaf}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let key = std::fs::read_to_string(dir.join(TLS_CRYPT)).unwrap();
        assert_eq!(key.lines().filter(|line| line.len() == 32).count(), 16);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

use super::*;

const CONGESTION: &[&str] = &["", "bbr", "cubic", "reno"];

pub(super) fn parse(f: &mut Fields<'_>, caps: &Capabilities) -> R<NaiveOpts> {
    let (server, port) = server_port(f)?;
    f.ignore("alpn", "NaiveProxy negotiates h2 or h3 itself");
    f.ignore(
        "client-fingerprint",
        "NaiveProxy always sends Chrome's hello",
    );
    for key in ["reality-opts", "certificate", "private-key"] {
        if f.has(key) {
            return quarantine(format!("option '{key}' is not supported on naive"));
        }
    }
    let mut tls = tls_without_reality(f, "sni", caps)?;
    tls.enabled = true;
    tls.alpn.clear();
    tls.alpn_set = false;
    tls.client_fingerprint.clear();
    let quic_congestion_control = f.string("quic-congestion-control")?;
    if quic_congestion_control == "bbr2" {
        return quarantine("quic-congestion-control 'bbr2' is not supported by this core");
    }
    if !CONGESTION.contains(&quic_congestion_control.as_str()) {
        return Err(Fail::Hard(ConfigError::new(format!(
            "unknown quic congestion control: {quic_congestion_control}"
        ))));
    }
    let version = f.u32("udp-over-tcp-version")?;
    let Ok(udp_over_tcp_version) = u8::try_from(version) else {
        return Err(Fail::Hard(ConfigError::new(format!(
            "unknown udp over tcp protocol version: {version}"
        ))));
    };
    Ok(NaiveOpts {
        server,
        port,
        username: f.string("username")?,
        password: f.string("password")?,
        tls,
        headers: headers(f, "headers")?,
        quic: f.boolean("quic")?,
        insecure_concurrency: u32::try_from(f.i64("insecure-concurrency")?.max(1))
            .unwrap_or(u32::MAX),
        udp_over_tcp: f.boolean("udp-over-tcp")?,
        udp_over_tcp_version,
        stream_receive_window: f.u64("stream-receive-window")?,
        quic_session_receive_window: f.u64("quic-session-receive-window")?,
        quic_congestion_control,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::{Value, json};

    use crate::proxy::{ProxyDef, ProxyKind, ProxyParse};
    use crate::{Capabilities, parse_proxy};

    fn parse(value: Value) -> ProxyParse {
        parse_proxy(value.as_object().unwrap(), &Capabilities::full()).unwrap()
    }

    fn naive(value: Value) -> (ProxyDef, super::NaiveOpts) {
        let ProxyParse::Ok(def) = parse(value) else {
            panic!("naive was set aside");
        };
        let ProxyKind::Naive(opts) = &def.kind else {
            panic!("not naive: {:?}", def.kind);
        };
        let opts = (**opts).clone();
        (*def, opts)
    }

    #[test]
    fn reads_sing_box_options_under_their_kebab_names() {
        let (def, opts) = naive(json!({
            "name": "n", "type": "naive", "server": "a.example.com", "port": 443,
            "username": "u", "password": "p", "quic": true, "insecure-concurrency": 3,
            "headers": {"X-Foo": "bar"}, "udp": true, "udp-over-tcp": true,
            "udp-over-tcp-version": 2, "stream-receive-window": 1048576,
            "quic-session-receive-window": 2097152, "quic-congestion-control": "bbr",
            "sni": "b.example.com", "skip-cert-verify": true, "alpn": ["h2"],
            "client-fingerprint": "firefox",
        }));
        assert!(def.common.udp);
        assert_eq!((opts.server.as_str(), opts.port), ("a.example.com", 443));
        assert_eq!((opts.username.as_str(), opts.password.as_str()), ("u", "p"));
        assert!(opts.quic && opts.udp_over_tcp);
        assert_eq!(opts.insecure_concurrency, 3);
        assert_eq!(opts.headers.get("X-Foo").map(String::as_str), Some("bar"));
        assert_eq!(opts.udp_over_tcp_version, 2);
        assert_eq!(opts.stream_receive_window, 1 << 20);
        assert_eq!(opts.quic_session_receive_window, 2 << 20);
        assert_eq!(opts.quic_congestion_control, "bbr");
        assert!(opts.tls.enabled && opts.tls.skip_cert_verify);
        assert_eq!(opts.tls.server_name, "b.example.com");
        assert!(opts.tls.alpn.is_empty());
        assert!(opts.tls.client_fingerprint.is_empty());
    }

    /// Versions that fit a byte reach the build, which rejects the unknown ones.
    #[test]
    fn a_udp_over_tcp_version_past_a_byte_is_an_error() {
        for version in [256, 258] {
            let raw = json!({
                "name": "n", "type": "naive", "server": "a.example.com", "port": 443,
                "udp-over-tcp": true, "udp-over-tcp-version": version,
            });
            let parsed = parse_proxy(raw.as_object().unwrap(), &Capabilities::full());
            assert!(parsed.is_err(), "version {version}");
        }
        let (_, opts) = naive(json!({
            "name": "n", "type": "naive", "server": "a.example.com", "port": 443,
            "udp-over-tcp": true, "udp-over-tcp-version": 3,
        }));
        assert_eq!(opts.udp_over_tcp_version, 3);
    }

    #[test]
    fn concurrency_below_one_means_one() {
        let (_, opts) = naive(json!({
            "name": "n", "type": "naive", "server": "a.example.com", "port": 443,
            "insecure-concurrency": 0,
        }));
        assert_eq!(opts.insecure_concurrency, 1);
    }

    #[test]
    fn options_cronet_cannot_honour_set_the_node_aside() {
        for (key, value) in [
            ("reality-opts", json!({"public-key": "k"})),
            ("certificate", json!("cert.pem")),
            ("private-key", json!("key.pem")),
            ("quic-congestion-control", json!("bbr2")),
        ] {
            let mut raw =
                json!({"name": "n", "type": "naive", "server": "a.example.com", "port": 443});
            raw.as_object_mut().unwrap().insert(key.into(), value);
            assert!(
                matches!(parse(raw), ProxyParse::Quarantined { .. }),
                "{key}"
            );
        }
        let raw = json!({
            "name": "n", "type": "naive", "server": "a.example.com", "port": 443,
            "quic-congestion-control": "vegas",
        });
        assert!(parse_proxy(raw.as_object().unwrap(), &Capabilities::full()).is_err());
    }
}

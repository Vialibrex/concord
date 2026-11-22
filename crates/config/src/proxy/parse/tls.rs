use super::*;

pub(super) fn ech_opts(f: &mut Fields<'_>, caps: &Capabilities) -> R<Option<EchOpts>> {
    let Some(mut e) = f.sub("ech-opts")? else {
        return Ok(None);
    };
    let out = EchOpts {
        enable: e.boolean("enable")?,
        config: e.string("config")?,
        query_server_name: e.string("query-server-name")?,
    };
    if out.enable {
        if !caps.ech {
            return quarantine("option 'ech-opts' is not implemented yet");
        }
        if !out.config.is_empty() && STANDARD.decode(out.config.as_bytes()).is_err() {
            return Err(Fail::Hard(ConfigError::new(
                "base64 decode ech config string failed",
            )));
        }
    }
    Ok(Some(out))
}

pub(super) fn reality_opts(f: &mut Fields<'_>) -> R<Option<RealityOpts>> {
    let Some(mut r) = f.sub("reality-opts")? else {
        return Ok(None);
    };
    let out = RealityOpts {
        public_key: r.req_string("public-key")?,
        short_id: r.string("short-id")?,
        support_x25519_mlkem768: r.boolean("support-x25519mlkem768")?,
    };
    r.finish()?;
    if !out.public_key.is_empty() {
        let key = URL_SAFE_NO_PAD.decode(out.public_key.as_bytes());
        if key.map(|k| k.len()) != Ok(32) {
            return Err(Fail::Hard(ConfigError::new("invalid REALITY public key")));
        }
        let hex_ok = out.short_id.len().is_multiple_of(2)
            && out.short_id.len() <= 16
            && out.short_id.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex_ok {
            return Err(Fail::Hard(ConfigError::new("invalid REALITY short ID")));
        }
    }
    Ok(Some(out))
}

pub(super) fn jls_auth(mut f: Fields<'_>) -> R<JlsOpts> {
    let auth = JlsOpts {
        username: f.string("username")?,
        password: f.string("password")?,
    };
    if auth.username.is_empty() != auth.password.is_empty() {
        return Err(Fail::Hard(ConfigError::new(
            "jls: username and password are required",
        )));
    }
    Ok(auth)
}

pub(super) fn jls_opts(f: &mut Fields<'_>) -> R<Option<JlsOpts>> {
    let Some(o) = f.sub("jls-opts")? else {
        return Ok(None);
    };
    let auth = jls_auth(o)?;
    Ok((!auth.username.is_empty()).then_some(auth))
}

pub(super) fn jls_plugin(mut f: Fields<'_>) -> R<JlsPlugin> {
    let host = f.req_string("host")?;
    let alpn = if f.has("alpn") {
        f.strings("alpn")?
    } else {
        vec!["h2".into(), "http/1.1".into()]
    };
    let auth = JlsOpts {
        username: f.req_string("username")?,
        password: f.req_string("password")?,
    };
    if host.is_empty() || auth.username.is_empty() || auth.password.is_empty() {
        return Err(Fail::Hard(ConfigError::new(
            "jls: host, username and password are required",
        )));
    }
    Ok(JlsPlugin { host, auth, alpn })
}

pub(super) fn tls_opts(f: &mut Fields<'_>, name_key: &str, caps: &Capabilities) -> R<TlsOpts> {
    let mut tls = tls_fields(f, name_key, caps)?;
    tls.reality = reality_opts(f)?;
    tls.shadow_tls = shadow_tls_layer(f)?.flatten();
    tls.jls = jls_opts(f)?;
    Ok(tls)
}

/// mihomo `ShadowTLSOptions.Parse` (`adapter/outbound/shadowtls.go:10-15`): written with neither
/// a password nor a version it is off, and version 0 means 2.
pub(super) fn shadow_tls_layer(f: &mut Fields<'_>) -> R<Option<Option<ShadowTlsLayer>>> {
    let Some(mut o) = f.sub("shadow-tls-opts")? else {
        return Ok(None);
    };
    let password = o.string("password")?;
    let version = o.i64("version")?;
    if password.is_empty() && version == 0 {
        return Ok(Some(None));
    }
    let version = if version == 0 { 2 } else { version };
    let Some(version) = u8::try_from(version).ok().filter(|v| (1..=3).contains(v)) else {
        return quarantine(format!("shadow-tls: unknown protocol version: {version}"));
    };
    Ok(Some(Some(ShadowTlsLayer { password, version })))
}

/// mihomo reads `reality-opts` on vmess, vless and trojan only.
pub(super) fn tls_without_reality(
    f: &mut Fields<'_>,
    name_key: &str,
    caps: &Capabilities,
) -> R<TlsOpts> {
    f.ignore("reality-opts", "this type does not use REALITY");
    tls_fields(f, name_key, caps)
}

fn tls_fields(f: &mut Fields<'_>, name_key: &str, caps: &Capabilities) -> R<TlsOpts> {
    Ok(TlsOpts {
        enabled: false,
        server_name: f.string(name_key)?,
        alpn: f.strings("alpn")?,
        alpn_set: f.has("alpn"),
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        fingerprint: f.string("fingerprint")?,
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        name_cert_verify: f.string("name-cert-verify")?,
        client_fingerprint: f.string("client-fingerprint")?,
        reality: None,
        jls: None,
        ech: ech_opts(f, caps)?,
        shadow_tls: None,
    })
}

/// mihomo's socks5 and http nodes dial plain Go TLS: no ALPN, uTLS, REALITY or ECH.
pub(super) fn plain_tls(f: &mut Fields<'_>) -> R<TlsOpts> {
    for key in ["alpn", "client-fingerprint", "reality-opts", "ech-opts"] {
        f.ignore(key, "socks5 and http nodes dial plain TLS");
    }
    Ok(TlsOpts {
        enabled: f.boolean("tls")?,
        server_name: f.string("sni")?,
        skip_cert_verify: f.boolean("skip-cert-verify")?,
        fingerprint: f.string("fingerprint")?,
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        name_cert_verify: f.string("name-cert-verify")?,
        ..TlsOpts::default()
    })
}

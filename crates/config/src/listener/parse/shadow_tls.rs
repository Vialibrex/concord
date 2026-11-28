use indexmap::IndexMap;
use serde_json::Value;

use super::super::{ShadowTlsHandshake, ShadowTlsServer, WildcardSni};
use super::{R, skip, user_list};
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;

/// The block as mihomo decodes it whether or not it is enabled; an enabled one comes with
/// its check, which mihomo makes after it has picked one security mode.
pub(super) fn shadow_tls(f: &mut Fields<'_>) -> Result<Option<R<ShadowTlsServer>>> {
    let Some(mut block) = f.sub("shadow-tls")? else {
        return Ok(None);
    };
    block.require("enable");
    let enable = block.boolean("enable")?;
    let version = block.loose::<i64>("version", 0)?;
    let password = block.string("password")?;
    let users = user_list(&mut block, "users", &["name", "password"])?
        .into_iter()
        .map(|mut user| (user.remove(0), user.remove(0)))
        .collect::<Vec<_>>();
    let handshake = match block.sub("handshake")? {
        Some(mut fields) => shadow_tls_handshake(&mut fields)?,
        None => ShadowTlsHandshake::default(),
    };
    let mut by_name = IndexMap::new();
    if let Some(map) = block.object("handshake-for-server-name")? {
        for (name, value) in map {
            let path = format!("{}.handshake-for-server-name.{name}", block.path());
            let Value::Object(entry) = value else {
                return Err(ConfigError::new(format!("'{path}' expected a map")));
            };
            by_name.insert(
                name.clone(),
                shadow_tls_handshake(&mut Fields::new(entry, &path, true))?,
            );
        }
    }
    let strict_mode = block.boolean("strict-mode")?;
    let wildcard_sni = match block.string("wildcard-sni")?.as_str() {
        "authed" => WildcardSni::Authed,
        "all" => WildcardSni::All,
        _ => WildcardSni::Off,
    };
    block.finish()?;
    if !enable {
        return Ok(None);
    }
    let decoded = ShadowTlsServer {
        version: 0,
        password,
        users,
        handshake,
        handshake_for_server_name: by_name,
        strict_mode,
        wildcard_sni,
    };
    Ok(Some(checked(decoded, version)))
}

/// `transport/shadowtls/server.go:53-89`; v1 builds no handshake by server name
/// (`listener/shadowtls/listener.go:29-35`).
fn checked(mut server: ShadowTlsServer, version: i64) -> R<ShadowTlsServer> {
    server.version = match u8::try_from(version) {
        Ok(version @ 1..=3) => version,
        _ => return skip(format!("shadow-tls: unknown protocol version: {version}")),
    };
    if server.version == 3 && server.users.is_empty() {
        return skip("shadow-tls: at least one user is required");
    }
    if server.handshake.dest.is_empty()
        && (server.wildcard_sni == WildcardSni::Off || server.version < 3)
    {
        return skip("shadow-tls: missing default handshake information");
    }
    if server.version == 1 {
        server.handshake_for_server_name.clear();
    }
    if let Some((name, _)) = server
        .handshake_for_server_name
        .iter()
        .find(|(name, handshake)| name.is_empty() || handshake.dest.is_empty())
    {
        return skip(format!(
            "shadow-tls: invalid handshake for server name {name:?}"
        ));
    }
    Ok(server)
}

fn shadow_tls_handshake(f: &mut Fields<'_>) -> Result<ShadowTlsHandshake> {
    f.require("dest");
    let handshake = ShadowTlsHandshake {
        dest: f.string("dest")?,
        proxy: f.string("proxy")?,
    };
    f.unset()?;
    Ok(handshake)
}

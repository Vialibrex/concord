use crate::error::Result;
use crate::lenient::Fields;

/// A `tailscale` node with mihomo's field names. `state_dir` is as written; the builder resolves
/// it against the home directory, defaulting to `tailscale` there as mihomo does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TailscaleOpts {
    pub hostname: String,
    pub auth_key: String,
    pub control_url: String,
    pub state_dir: String,
    pub ephemeral: bool,
    pub udp: bool,
    pub accept_routes: Option<bool>,
    pub exit_node: String,
    pub exit_node_allow_lan_access: Option<bool>,
}

pub(super) fn parse(f: &mut Fields<'_>) -> Result<TailscaleOpts> {
    Ok(TailscaleOpts {
        hostname: f.string("hostname")?,
        auth_key: f.string("auth-key")?,
        control_url: f.string("control-url")?,
        state_dir: f.string("state-dir")?,
        ephemeral: f.boolean("ephemeral")?,
        udp: f.boolean("udp")?,
        accept_routes: f.opt_bool("accept-routes")?,
        exit_node: f.string("exit-node")?,
        exit_node_allow_lan_access: f.opt_bool("exit-node-allow-lan-access")?,
    })
}

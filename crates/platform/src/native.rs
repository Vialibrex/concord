use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use concord_common::sync;
use concord_common::{FlowKey, ProcessInfo, RawSocket};

use crate::{InterfaceInfo, Platform, netinfo, owner};

/// The desktop implementation. On Android only the embedding app can protect a
/// socket or name a flow's owner, so there it answers the rest and returns `None`.
#[derive(Default)]
pub struct NativePlatform {
    excluded: RwLock<Vec<String>>,
    tables: netinfo::Cache,
}

impl NativePlatform {
    pub fn new() -> Self {
        Self::default()
    }

    fn tables(&self) -> Arc<netinfo::Tables> {
        self.tables.get(|| {
            let excluded = sync::read(&self.excluded);
            netinfo::Tables::read(&excluded)
        })
    }
}

#[async_trait]
impl Platform for NativePlatform {
    fn protect(&self, _socket: RawSocket) -> bool {
        true
    }

    async fn find_owner(&self, flow: &FlowKey) -> Option<ProcessInfo> {
        let (network, src) = (flow.network, flow.src);
        tokio::task::spawn_blocking(move || owner::find_owner_blocking(network, src))
            .await
            .inspect_err(|err| tracing::warn!("process lookup task failed: {err}"))
            .ok()
            .flatten()
    }

    fn default_interface(&self) -> Option<InterfaceInfo> {
        self.tables().default_interface()
    }

    fn interface_for(&self, dest: IpAddr) -> Option<InterfaceInfo> {
        self.tables().interface_for(dest)
    }

    fn interface_by_name(&self, name: &str) -> Option<InterfaceInfo> {
        self.tables().by_name(name)
    }

    fn system_dns(&self) -> Vec<SocketAddr> {
        netinfo::system_dns()
    }

    fn is_local_ip(&self, ip: IpAddr) -> bool {
        self.tables().is_local_ip(ip)
    }

    fn set_excluded_interfaces(&self, names: Vec<String>) {
        *sync::write(&self.excluded) = names;
        self.tables.invalidate();
    }

    fn network_changed(&self) {
        self.tables.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use concord_common::Network;

    use super::*;

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test connects to its own loopback listener"
    )]
    fn a_connection_of_this_process_is_found_through_the_trait() {
        #[cfg(target_os = "macos")]
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let flow = FlowKey {
            network: Network::Tcp,
            src: client.local_addr().unwrap(),
            dst: addr,
        };
        let platform: Box<dyn Platform> = Box::new(NativePlatform::new());
        if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let info = rt.block_on(platform.find_owner(&flow)).unwrap();
            assert!(!info.path.is_empty());
        }
        assert!(!platform.fd_pressure());
    }

    #[test]
    fn any_interface_address_is_local() {
        let platform = NativePlatform::new();
        assert!(platform.is_local_ip("127.0.0.1".parse().unwrap()));
        assert!(!platform.is_local_ip("203.0.113.9".parse().unwrap()));
        if let Some(default) = platform.default_interface() {
            assert!(default.addrs.iter().all(|ip| platform.is_local_ip(*ip)));
        }
    }

    #[test]
    fn a_destination_on_a_local_subnet_binds_to_that_interface() {
        let platform = NativePlatform::new();
        let Some(default) = platform.default_interface() else {
            return;
        };
        let Some(addr) = default.addrs.iter().find(|ip| ip.is_ipv4()) else {
            return;
        };
        assert_eq!(
            platform.interface_for(*addr).map(|i| i.name),
            Some(default.name.clone())
        );
        platform.set_excluded_interfaces(vec![default.name.to_string()]);
        assert_ne!(
            platform.interface_for(*addr).map(|i| i.name),
            Some(default.name)
        );
    }

    #[test]
    fn the_default_interface_honours_the_exclusion_list() {
        let platform = NativePlatform::new();
        let Some(found) = platform.default_interface() else {
            return;
        };
        assert!(found.index > 0);
        platform.set_excluded_interfaces(vec![found.name.to_string()]);
        assert_ne!(
            platform.default_interface().map(|i| i.name),
            Some(found.name)
        );
    }
}

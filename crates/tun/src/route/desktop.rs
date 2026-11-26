use super::ranges::auto_route_ranges;
use super::{IfaceInfo, Os, Plan, RouteSpec, Step, StrictRoute};
use crate::options::{Prefix, TunOptions};

/// Routes for macOS and Windows: one entry per range pointing at the interface. macOS routes by
/// interface alone, Windows through the address after the interface's own.
pub fn plan_desktop(os: Os, options: &TunOptions, iface: &IfaceInfo) -> Plan {
    let mut plan = Plan::default();
    if !options.auto_route && options.route_address.is_empty() {
        return plan;
    }
    let darwin = os == Os::MacOs;
    let next = |addresses: &[Prefix]| {
        addresses
            .first()
            .and_then(|first| first.next_host().or(Some(first.addr())))
    };
    for dest in auto_route_ranges(options, darwin) {
        let gateway = if darwin {
            None
        } else if dest.is_ipv4() {
            next(&options.inet4_address)
        } else {
            next(&options.inet6_address)
        };
        plan.steps.push(Step::Route(RouteSpec {
            dest,
            gateway,
            if_index: iface.index,
            table: None,
        }));
    }
    if darwin && options.auto_route {
        let servers: Vec<_> = [&options.inet4_address, &options.inet6_address]
            .into_iter()
            .filter_map(|addresses| addresses.first().and_then(Prefix::next_host))
            .collect();
        if !servers.is_empty() {
            plan.steps.push(Step::Dns {
                ifname: iface.name.clone(),
                servers,
            });
        }
    }
    if options.strict_route {
        if darwin {
            plan.warnings
                .push("strict-route has no effect on this platform".into());
        } else if options.auto_route {
            plan.steps.push(Step::StrictRoute(StrictRoute {
                if_index: iface.index,
                inet4: !options.inet4_address.is_empty(),
                inet6: !options.inet6_address.is_empty(),
                block_dns: true,
            }));
        }
    }
    if !options.include_interface.is_empty()
        || !options.exclude_interface.is_empty()
        || !options.include_uid.is_empty()
        || !options.exclude_uid.is_empty()
        || !options.exclude_src_port.is_empty()
        || !options.exclude_dst_port.is_empty()
    {
        plan.warnings
            .push("interface, uid and port route filters are only applied on Linux".into());
    }
    plan
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub use manager::ManagerBackend;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub use stub::ManagerBackend;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod stub {
    use std::io;

    use async_trait::async_trait;

    use super::super::{Op, RouteBackend, Step};

    /// Placeholder so the module tree is the same everywhere; only macOS and Windows use it.
    #[derive(Default)]
    pub struct ManagerBackend;

    #[async_trait]
    impl RouteBackend for ManagerBackend {
        async fn apply(&mut self, _op: Op, _step: &Step) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "route manager backend is not built for this platform",
            ))
        }

        async fn clean_stale(&mut self, _priorities: (u32, u32)) -> io::Result<usize> {
            Ok(0)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod manager {
    use std::io;

    use async_trait::async_trait;
    use route_manager::{Route, RouteManager};

    use super::super::{Op, RouteBackend, RouteSpec, Step};

    #[derive(Default)]
    pub struct ManagerBackend {
        #[cfg(windows)]
        wfp: Option<super::super::wfp::Wfp>,
        #[cfg(target_os = "macos")]
        dns: Option<super::super::system_dns::Registration>,
    }

    #[cfg(target_os = "macos")]
    async fn flush_dns_cache() {
        let _ = tokio::process::Command::new("/usr/bin/dscacheutil")
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .arg("-flushcache")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }

    fn route_of(spec: &RouteSpec) -> Route {
        let mut route = Route::new(spec.dest.addr(), spec.dest.len()).with_if_index(spec.if_index);
        if let Some(gateway) = spec.gateway {
            route = route.with_gateway(gateway);
        }
        route
    }

    #[async_trait]
    impl RouteBackend for ManagerBackend {
        async fn apply(&mut self, op: Op, step: &Step) -> io::Result<()> {
            #[cfg(windows)]
            if let Step::StrictRoute(strict) = step {
                match op {
                    Op::Add => {
                        let strict = strict.clone();
                        let wfp = tokio::task::spawn_blocking(move || {
                            super::super::wfp::install(&strict)
                        })
                        .await
                        .map_err(io::Error::other)??;
                        self.wfp = Some(wfp);
                    }
                    Op::Delete => self.wfp = None,
                }
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            if let Step::Dns { ifname, servers } = step {
                match op {
                    Op::Add => {
                        let (ifname, servers) = (ifname.clone(), servers.clone());
                        let registration = tokio::task::spawn_blocking(move || {
                            super::super::system_dns::register(&ifname, &servers)
                        })
                        .await
                        .map_err(io::Error::other)??;
                        self.dns = Some(registration);
                    }
                    Op::Delete => self.dns = None,
                }
                flush_dns_cache().await;
                return Ok(());
            }
            let Step::Route(spec) = step else {
                return Ok(());
            };
            let route = route_of(spec);
            tokio::task::spawn_blocking(move || {
                let mut manager = RouteManager::new()?;
                match op {
                    Op::Add => manager.add(&route),
                    Op::Delete => manager.delete(&route),
                }
            })
            .await
            .map_err(io::Error::other)?
        }

        async fn clean_stale(&mut self, _priorities: (u32, u32)) -> io::Result<usize> {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> TunOptions {
        TunOptions {
            auto_route: true,
            inet4_address: vec![Prefix::parse("198.18.0.1/30").unwrap()],
            ..TunOptions::default()
        }
    }

    fn iface() -> IfaceInfo {
        IfaceInfo {
            name: "utun9".into(),
            index: 14,
        }
    }

    fn dests(plan: &Plan) -> Vec<String> {
        plan.steps
            .iter()
            .filter_map(|step| match step {
                Step::Route(route) => Some(route.dest.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn macos_uses_eight_split_routes_without_a_gateway() {
        let plan = plan_desktop(Os::MacOs, &options(), &iface());
        assert_eq!(dests(&plan).len(), 8);
        assert_eq!(dests(&plan)[0], "1.0.0.0/8");
        assert_eq!(dests(&plan)[7], "128.0.0.0/1");
        assert!(plan.steps[..8].iter().all(|step| matches!(
            step,
            Step::Route(RouteSpec {
                gateway: None,
                if_index: 14,
                ..
            })
        )));
    }

    #[test]
    fn macos_points_the_system_resolver_at_the_next_addresses_last() {
        let mut o = options();
        o.inet6_address = vec![Prefix::parse("fdfe:dcba:9876::1/126").unwrap()];
        let plan = plan_desktop(Os::MacOs, &o, &iface());
        assert_eq!(
            plan.steps.last(),
            Some(&Step::Dns {
                ifname: "utun9".into(),
                servers: vec![
                    "198.18.0.2".parse().unwrap(),
                    "fdfe:dcba:9876::2".parse().unwrap(),
                ],
            })
        );
        assert!(
            plan_desktop(Os::Windows, &o, &iface())
                .steps
                .iter()
                .all(|step| !matches!(step, Step::Dns { .. }))
        );
    }

    #[test]
    fn windows_uses_the_default_route_through_the_next_address() {
        let plan = plan_desktop(Os::Windows, &options(), &iface());
        assert_eq!(dests(&plan), ["0.0.0.0/0"]);
        assert!(matches!(
            &plan.steps[0],
            Step::Route(RouteSpec { gateway: Some(gateway), .. }) if gateway.to_string() == "198.18.0.2"
        ));
    }

    #[test]
    fn no_auto_route_plans_nothing_and_filters_warn() {
        let mut o = options();
        o.auto_route = false;
        assert!(plan_desktop(Os::MacOs, &o, &iface()).steps.is_empty());
        o.auto_route = true;
        o.exclude_uid = vec![crate::options::IdRange::single(1)];
        o.strict_route = true;
        assert_eq!(plan_desktop(Os::MacOs, &o, &iface()).warnings.len(), 2);
        assert_eq!(plan_desktop(Os::Windows, &o, &iface()).warnings.len(), 1);
    }

    #[test]
    fn windows_strict_route_adds_the_firewall_step_last() {
        let mut o = options();
        o.strict_route = true;
        let plan = plan_desktop(Os::Windows, &o, &iface());
        assert!(plan.warnings.is_empty());
        assert_eq!(
            plan.steps.last(),
            Some(&Step::StrictRoute(StrictRoute {
                if_index: 14,
                inet4: true,
                inet6: false,
                block_dns: true,
            }))
        );
        assert!(
            plan_desktop(Os::MacOs, &o, &iface())
                .steps
                .iter()
                .all(|step| !matches!(step, Step::StrictRoute(_)))
        );
    }

    #[test]
    fn a_tunnel_address_with_no_next_host_is_its_own_gateway_on_windows() {
        let mut o = options();
        o.inet4_address = vec![Prefix::parse("198.18.0.1/32").unwrap()];
        let plan = plan_desktop(Os::Windows, &o, &iface());
        assert!(matches!(
            &plan.steps[0],
            Step::Route(RouteSpec { gateway: Some(gateway), .. }) if gateway.to_string() == "198.18.0.1"
        ));
    }
}

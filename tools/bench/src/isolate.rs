//! Keeping the four processes of a measurement from sharing CPUs, and on Linux
//! putting the far end behind a real link instead of loopback.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::Path;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Core,
    Server,
    Origin,
    Client,
}

impl Role {
    const ALL: [Role; 4] = [Role::Core, Role::Server, Role::Origin, Role::Client];

    fn parse(text: &str) -> Option<Role> {
        Role::ALL
            .into_iter()
            .find(|r| format!("{r:?}").eq_ignore_ascii_case(text))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CpuPlan {
    pub sets: BTreeMap<Role, Vec<usize>>,
}

impl CpuPlan {
    pub fn get(&self, role: Role) -> Option<&[usize]> {
        self.sets.get(&role).map(Vec::as_slice)
    }

    /// `core=0-1,server=2-3,origin=4,client=5-7`, or a split of the CPUs this
    /// process may run on: the core and the server get two each when there are
    /// enough, the origin one, and the load generator the rest.
    pub fn resolve(spec: Option<&str>) -> Result<Option<CpuPlan>, String> {
        if cfg!(target_os = "macos") {
            return match spec {
                Some(_) => Err("--cpus: macOS has no CPU affinity".into()),
                None => Ok(None),
            };
        }
        if spec == Some("off") {
            return Ok(None);
        }
        if let Some(spec) = spec {
            let mut sets = BTreeMap::new();
            for part in spec.split(',') {
                let (role, list) = part.split_once('=').ok_or(format!("--cpus: {part}"))?;
                let role = Role::parse(role).ok_or(format!("--cpus: unknown role {role}"))?;
                sets.insert(role, parse_list(list)?);
            }
            if sets.len() != 4 {
                return Err("--cpus names core, server, origin and client".into());
            }
            return Ok(Some(CpuPlan { sets }));
        }
        let mut cpus = allowed_cpus();
        // Fastest first, so on a big.LITTLE phone the core under test gets the big cores.
        cpus.sort_by_key(|&cpu| std::cmp::Reverse(max_freq_khz(cpu).unwrap_or(0)));
        let n = cpus.len();
        if n < 4 {
            return Ok(None);
        }
        let core = if n >= 6 { 2 } else { 1 };
        let server = if n >= 7 { 2 } else { 1 };
        let mut taken = cpus.into_iter();
        let mut next = |count: usize| taken.by_ref().take(count).collect::<Vec<_>>();
        let mut sets = BTreeMap::new();
        sets.insert(Role::Core, next(core));
        sets.insert(Role::Server, next(server));
        sets.insert(Role::Origin, next(1));
        sets.insert(Role::Client, next(usize::MAX));
        Ok(Some(CpuPlan { sets }))
    }
}

pub fn max_freq_khz(cpu: usize) -> Option<u64> {
    std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq"
    ))
    .ok()?
    .trim()
    .parse()
    .ok()
}

fn parse_list(list: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for item in list.split(['+', ' ']).filter(|s| !s.is_empty()) {
        match item.split_once('-') {
            Some((a, b)) => {
                let (a, b): (usize, usize) = (
                    a.parse().map_err(|_| format!("cpu {a}"))?,
                    b.parse().map_err(|_| format!("cpu {b}"))?,
                );
                cpus.extend(a..=b);
            }
            None => cpus.push(item.parse().map_err(|_| format!("cpu {item}"))?),
        }
    }
    if cpus.is_empty() {
        return Err(format!("empty cpu list {list}"));
    }
    Ok(cpus)
}

#[derive(Clone, Debug, Serialize)]
pub struct Link {
    pub rtt_ms: f64,
    pub rate_mbit: Option<u64>,
    pub loss_pct: f64,
    /// Microsecond TCP timestamps on both namespaces' routes, which largely suppresses the loopback small-segment
    /// regime described in `.agents/benchmarking.md`.
    pub usec_ts: bool,
}

impl Link {
    /// `lan`, `wan`, `lossy` or `veth`, then any `key=value` settings, which also stand alone:
    /// `wan,ts=usec`, `rtt=40ms,rate=200mbit,loss=0.5%,ts=usec`.
    pub fn parse(text: &str) -> Result<Link, String> {
        let mut parts = text.split(',').peekable();
        let preset = |rtt_ms: f64, rate_mbit: Option<u64>, loss_pct: f64| Link {
            rtt_ms,
            rate_mbit,
            loss_pct,
            usec_ts: false,
        };
        let named = match parts.peek().copied() {
            Some("lan") => Some(preset(0.5, Some(1000), 0.0)),
            Some("wan") => Some(preset(40.0, Some(300), 0.0)),
            Some("lossy") => Some(preset(80.0, Some(100), 1.0)),
            Some("veth") => Some(preset(0.0, None, 0.0)),
            _ => None,
        };
        let mut link = match named {
            Some(link) => {
                parts.next();
                link
            }
            None => preset(0.0, None, 0.0),
        };
        for part in parts {
            let (key, value) = part.split_once('=').ok_or(format!("--link: {part}"))?;
            let number = |suffix: &str| {
                value
                    .trim_end_matches(suffix)
                    .parse::<f64>()
                    .map_err(|_| format!("--link: {part}"))
            };
            match key {
                "rtt" => link.rtt_ms = number("ms")?,
                "rate" => link.rate_mbit = Some(number("mbit")? as u64),
                "loss" => link.loss_pct = number("%")?,
                "ts" if value == "usec" => link.usec_ts = true,
                "ts" if value == "ms" => link.usec_ts = false,
                _ => return Err(format!("--link: unknown key {key}")),
            }
        }
        Ok(link)
    }

    pub(crate) fn netem(&self) -> Vec<String> {
        let mut args = vec!["netem".to_string()];
        if self.rtt_ms > 0.0 {
            args.extend([
                "delay".into(),
                format!("{}us", (self.rtt_ms * 500.0) as u64),
            ]);
        }
        if let Some(rate) = self.rate_mbit {
            args.extend(["rate".into(), format!("{rate}mbit")]);
        }
        if self.loss_pct > 0.0 {
            args.extend(["loss".into(), format!("{}%", self.loss_pct)]);
        }
        args.extend(["limit".into(), "100000".into()]);
        args
    }
}

/// Two network namespaces joined by a veth pair. The harness and the core run in
/// `near`, whose default route is the veth, so a TUN core's own sockets leave
/// through it while the routing table hands the harness's sockets to the TUN.
pub struct Netns {
    pub near: String,
    pub far: String,
    pub far_ip: IpAddr,
}

const NEAR_IP: &str = "10.211.0.1";
const FAR_LINK_IP: &str = "10.211.0.2";
// Off the veth's subnet, so `near` reaches it only through its default route: a TUN
// core's auto-route defers to a more specific route, and the connected /24 would
// carry the harness straight past the TUN.
const FAR_IP: [u8; 4] = [10, 211, 1, 2];

impl Netns {
    pub fn create(link: &Link) -> Result<Netns, String> {
        let tag = std::process::id() % 100_000;
        let ns = Netns {
            near: format!("cbnear{tag}"),
            far: format!("cbfar{tag}"),
            far_ip: IpAddr::from(FAR_IP),
        };
        let far_ip = ns.far_ip.to_string();
        let (near_if, far_if) = (format!("cbn{tag}"), format!("cbf{tag}"));
        let features = if link.usec_ts {
            " features tcp_usec_ts"
        } else {
            ""
        };
        let steps: Vec<Vec<String>> = vec![
            vec!["netns".into(), "add".into(), ns.near.clone()],
            vec!["netns".into(), "add".into(), ns.far.clone()],
            words(&format!(
                "link add {near_if} netns {} type veth peer name {far_if} netns {}",
                ns.near, ns.far
            )),
            words(&format!(
                "-n {} addr add {NEAR_IP}/24 dev {near_if}",
                ns.near
            )),
            words(&format!(
                "-n {} addr add {FAR_LINK_IP}/24 dev {far_if}",
                ns.far
            )),
            words(&format!("-n {} addr add {far_ip}/32 dev lo", ns.far)),
            words(&format!("-n {} link set lo up", ns.near)),
            words(&format!("-n {} link set lo up", ns.far)),
            words(&format!("-n {} link set {near_if} up", ns.near)),
            words(&format!("-n {} link set {far_if} up", ns.far)),
            words(&format!(
                "-n {} route add default via {FAR_LINK_IP}{features}",
                ns.near
            )),
            words(&format!(
                "-n {} route add default via {NEAR_IP}{features}",
                ns.far
            )),
        ];
        for step in steps {
            if let Err(err) = run("ip", &step) {
                ns.destroy();
                return Err(err);
            }
        }
        let netem = link.netem();
        if netem.len() > 3 {
            for (space, dev) in [(&ns.near, &near_if), (&ns.far, &far_if)] {
                let mut args = words(&format!("-n {space} qdisc add dev {dev} root"));
                args.extend(netem.iter().cloned());
                if let Err(err) = run("tc", &args) {
                    ns.destroy();
                    return Err(err);
                }
            }
        }
        Ok(ns)
    }

    /// Moves the calling thread, and every thread it starts afterwards, into `near`.
    pub fn enter_near(&self) -> Result<(), String> {
        enter(&format!("/var/run/netns/{}", self.near))
    }

    pub fn destroy(&self) {
        for space in [&self.near, &self.far] {
            let _ = run(
                "ip",
                &["netns".to_string(), "del".to_string(), space.clone()],
            );
        }
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        self.destroy();
    }
}

pub(crate) fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

pub(crate) fn run(program: &str, args: &[String]) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Where a child runs: which CPUs and which network namespace.
#[derive(Clone, Debug, Default)]
pub struct Placement {
    pub cpus: Option<Vec<usize>>,
    pub netns: Option<String>,
}

/// Spawns `command`. Windows has no affinity to inherit, so the mask is set right
/// after the spawn; the cores read it only once the harness has sent their token.
pub fn spawn(
    command: &mut tokio::process::Command,
    placement: &Placement,
) -> std::io::Result<tokio::process::Child> {
    let child = command.spawn()?;
    #[cfg(windows)]
    if let (Some(cpus), Some(pid)) = (&placement.cpus, child.id()) {
        imp::pin_pid(pid, cpus).map_err(std::io::Error::other)?;
    }
    #[cfg(not(windows))]
    let _ = placement;
    Ok(child)
}

pub fn command(program: &Path, placement: &Placement) -> tokio::process::Command {
    let mut command = match &placement.netns {
        Some(space) => {
            let mut c = tokio::process::Command::new("ip");
            c.args([
                OsStr::new("netns"),
                OsStr::new("exec"),
                OsStr::new(space),
                program.as_os_str(),
            ]);
            c
        }
        None => tokio::process::Command::new(program),
    };
    command.kill_on_drop(true);
    if let Some(cpus) = placement.cpus.clone() {
        if cfg!(windows) {
            command.env("GOMAXPROCS", cpus.len().to_string());
            command.env("TOKIO_WORKER_THREADS", cpus.len().to_string());
        }
        pin_child(&mut command, cpus);
    }
    command
}

pub fn pin_self(cpus: &[usize]) -> Result<(), String> {
    imp::pin(cpus)
}

pub fn allowed_cpus() -> Vec<usize> {
    imp::allowed()
}

/// CPUs the kernel knows, online or not; `None` where there is no sysfs.
pub fn present_cpus() -> Option<usize> {
    let list = std::fs::read_to_string("/sys/devices/system/cpu/present").ok()?;
    parse_list(list.trim().replace(',', "+").as_str())
        .ok()
        .map(|cpus| cpus.len())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn pin_child(command: &mut tokio::process::Command, cpus: Vec<usize>) {
    let set = imp::set_of(&cpus);
    #[allow(
        unsafe_code,
        reason = "pre_exec runs between fork and exec; the closure only calls sched_setaffinity on a set built before the fork"
    )]
    unsafe {
        command.pre_exec(move || imp::apply(&set));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pin_child(_: &mut tokio::process::Command, _: Vec<usize>) {}

#[cfg(target_os = "linux")]
pub(crate) fn enter(path: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    #[allow(
        unsafe_code,
        reason = "setns takes a namespace descriptor that `file` keeps open for the call"
    )]
    let status = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("setns {path}: {}", std::io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn enter(_: &str) -> Result<(), String> {
    Err("network namespaces need Linux".into())
}

/// Runs `read` inside the named network namespace, on a thread of its own so the caller stays where it is.
pub fn in_netns<T: Send>(name: &str, read: impl FnOnce() -> T + Send) -> Option<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                enter(&format!("/var/run/netns/{name}")).ok()?;
                Some(read())
            })
            .join()
            .ok()
            .flatten()
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(
    unsafe_code,
    reason = "cpu_set_t is a plain bit array passed by pointer to the affinity calls"
)]
mod imp {
    pub fn set_of(cpus: &[usize]) -> libc::cpu_set_t {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
        set
    }

    pub fn apply(set: &libc::cpu_set_t) -> std::io::Result<()> {
        let status =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set) };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub fn pin(cpus: &[usize]) -> Result<(), String> {
        apply(&set_of(cpus)).map_err(|e| format!("sched_setaffinity {cpus:?}: {e}"))
    }

    pub fn allowed() -> Vec<usize> {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) }
            != 0
        {
            return Vec::new();
        }
        (0..std::mem::size_of::<libc::cpu_set_t>() * 8)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
            .collect()
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "the affinity calls take a process handle and a mask passed by value or local pointer"
)]
mod imp {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessAffinityMask, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_INFORMATION, SetProcessAffinityMask,
    };

    fn mask(cpus: &[usize]) -> usize {
        cpus.iter()
            .filter(|&&c| c < usize::BITS as usize)
            .fold(0, |m, &c| m | (1 << c))
    }

    pub fn pin(cpus: &[usize]) -> Result<(), String> {
        let ok = unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask(cpus)) };
        if ok != 0 {
            Ok(())
        } else {
            Err(format!(
                "SetProcessAffinityMask {cpus:?}: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn pin_pid(pid: u32, cpus: &[usize]) -> Result<(), String> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(format!(
                "OpenProcess {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ok = unsafe { SetProcessAffinityMask(handle, mask(cpus)) };
        unsafe { CloseHandle(handle) };
        if ok != 0 {
            Ok(())
        } else {
            Err(format!(
                "SetProcessAffinityMask {cpus:?}: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn allowed() -> Vec<usize> {
        let (mut process, mut system) = (0usize, 0usize);
        if unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process, &mut system) } == 0 {
            return Vec::new();
        }
        (0..usize::BITS as usize)
            .filter(|c| process & (1 << c) != 0)
            .collect()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
mod imp {
    pub fn pin(_: &[usize]) -> Result<(), String> {
        Err("no CPU affinity on this OS".into())
    }

    pub fn allowed() -> Vec<usize> {
        (0..std::thread::available_parallelism().map_or(1, |n| n.get())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_preset_takes_settings_after_it() {
        let wan = Link::parse("wan,ts=usec").unwrap();
        assert_eq!(
            (wan.rtt_ms, wan.rate_mbit, wan.usec_ts),
            (40.0, Some(300), true)
        );
        let veth = Link::parse("ts=usec").unwrap();
        assert_eq!(
            (veth.rtt_ms, veth.rate_mbit, veth.usec_ts),
            (0.0, None, true)
        );
        assert!(!Link::parse("lan").unwrap().usec_ts);
        assert!(Link::parse("bogus,ts=usec").is_err());
        assert!(Link::parse("wan,lan").is_err());
    }
}

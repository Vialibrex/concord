//! What the numbers were measured on. Host names and user paths stay out, so a
//! results file can be shared as is.

use std::process::Command;

use serde_json::{Value, json};

fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn load_average() -> Option<f64> {
    read("/proc/loadavg")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
pub fn load_average() -> Option<f64> {
    output("sysctl", &["-n", "vm.loadavg"])?
        .trim_matches(|c| c == '{' || c == '}' || c == ' ')
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn load_average() -> Option<f64> {
    None
}

/// Android system properties joined by spaces; `None` elsewhere.
fn getprop(keys: &[&str]) -> Option<String> {
    if !cfg!(target_os = "android") {
        return None;
    }
    let values: Vec<String> = keys
        .iter()
        .filter_map(|k| output("getprop", &[k]))
        .collect();
    (!values.is_empty()).then(|| values.join(" "))
}

/// `PowerManager` thermal status, 0 when not throttling.
fn thermal_status() -> Option<u64> {
    if !cfg!(target_os = "android") {
        return None;
    }
    output("dumpsys", &["thermalservice"])?
        .lines()
        .find_map(|l| l.trim().strip_prefix("Thermal Status:"))?
        .trim()
        .parse()
        .ok()
}

/// The interface whose address the kernel picks as the source towards `target`.
#[cfg(unix)]
pub fn route_interface(target: std::net::SocketAddr) -> Option<String> {
    let socket =
        crate::socks::owned(|| std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)))
            .ok()?;
    socket.connect(target).ok()?;
    let source = socket.local_addr().ok()?.ip();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    #[allow(
        unsafe_code,
        reason = "getifaddrs fills a list that is read here and freed before returning"
    )]
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return None;
        }
        let mut found = None;
        let mut cursor = list;
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ifa_addr.is_null() && i32::from((*entry.ifa_addr).sa_family) == libc::AF_INET
            {
                let addr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                if std::net::IpAddr::from(u32::from_be(addr.sin_addr.s_addr).to_be_bytes())
                    == source
                {
                    found = Some(
                        std::ffi::CStr::from_ptr(entry.ifa_name)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    break;
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(list);
        found
    }
}

#[cfg(not(unix))]
pub fn route_interface(_: std::net::SocketAddr) -> Option<String> {
    None
}

pub fn on_battery() -> Option<bool> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    output("pmset", &["-g", "batt"]).map(|s| s.contains("Battery Power"))
}

pub fn collect() -> Value {
    let cpu = if cfg!(target_os = "macos") {
        output("sysctl", &["-n", "machdep.cpu.brand_string"])
    } else if cfg!(windows) {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    } else {
        read("/proc/cpuinfo").and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
    };
    #[cfg(windows)]
    let memory = memory_bytes();
    #[cfg(not(windows))]
    let memory = if cfg!(target_os = "macos") {
        output("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse::<u64>().ok())
    } else {
        read("/proc/meminfo").and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
                .map(|kib| kib * 1024)
        })
    };
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": if cfg!(windows) { output("cmd", &["/c", "ver"]) } else { output("uname", &["-r"]) },
        "os_version": if cfg!(target_os = "macos") { output("sw_vers", &["-productVersion"]) } else { read("/etc/os-release").and_then(|t| t.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string())) },
        "cpu": cpu.or_else(|| getprop(&["ro.soc.manufacturer", "ro.soc.model"])),
        "device": getprop(&["ro.product.manufacturer", "ro.product.model"]),
        "android": getprop(&["ro.build.version.release"]),
        "cpu_max_mhz": (0..std::thread::available_parallelism().map_or(0, |n| n.get()))
            .filter_map(|cpu| crate::isolate::max_freq_khz(cpu).map(|khz| khz / 1000))
            .collect::<Vec<_>>(),
        "thermal_status": thermal_status(),
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "memory_bytes": memory,
        "governor": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "perf_event_paranoid": read("/proc/sys/kernel/perf_event_paranoid"),
        "on_battery": on_battery(),
        "load_average_1m": load_average(),
        "footprint": crate::probe::FOOTPRINT_KIND,
        "bench_version": env!("CARGO_PKG_VERSION"),
        "bench_rev": crate::revs::describe_head(),
    })
}

/// Lifts the open-file limit to its hard maximum; holding thousands of
/// connections needs more than macOS's default 256.
#[cfg(unix)]
pub fn raise_fd_limit() {
    #[allow(
        unsafe_code,
        reason = "getrlimit and setrlimit take a pointer to a local rlimit"
    )]
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        let target = if cfg!(target_os = "macos") {
            limit.rlim_max.min(24_576)
        } else {
            limit.rlim_max
        };
        limit.rlim_cur = target;
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
    }
}

#[cfg(not(unix))]
pub fn raise_fd_limit() {}

#[cfg(unix)]
pub fn is_root() -> bool {
    #[allow(unsafe_code, reason = "geteuid takes no arguments and cannot fail")]
    unsafe {
        libc::geteuid() == 0
    }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

const INTERRUPTED: &str = "interrupted; partial results kept";
#[cfg(unix)]
const TERMINATED: &str = "terminated; partial results kept";

#[cfg(unix)]
static SIGTERM_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn record_sigterm(_: libc::c_int) {
    SIGTERM_SEEN.store(true, std::sync::atomic::Ordering::Release);
}

/// Installs an async-signal-safe SIGTERM handler before `Netns::create` so a signal arriving
/// before `runtime.block_on` is recorded instead of killing the process and leaking namespaces.
#[cfg(unix)]
pub fn arm_sigterm() {
    #[allow(
        unsafe_code,
        reason = "sigaction installs an async-signal-safe AtomicBool store for SIGTERM"
    )]
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_sigterm as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        let _ = libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
    }
}

#[cfg(not(unix))]
pub fn arm_sigterm() {}

/// Waits for Ctrl-C (SIGINT) or, on Unix, SIGTERM so `run` exits gracefully, saves partial
/// results and runs its post-loop drop teardown.
#[cfg(unix)]
pub async fn shutdown_signal() -> &'static str {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    if SIGTERM_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return TERMINATED;
    }
    match terminate {
        Ok(mut terminate) => tokio::select! {
            _ = tokio::signal::ctrl_c() => INTERRUPTED,
            _ = terminate.recv() => TERMINATED,
        },
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            INTERRUPTED
        }
    }
}

#[cfg(not(unix))]
pub async fn shutdown_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    INTERRUPTED
}

#[cfg(windows)]
fn memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    #[allow(
        unsafe_code,
        reason = "GlobalMemoryStatusEx fills a local struct whose length it is told"
    )]
    let status = unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (GlobalMemoryStatusEx(&mut status) != 0).then_some(status.ullTotalPhys)
    };
    status
}

//! Per-process system call counts from the `syscalls:sys_enter_*` and `raw_syscalls:sys_enter` tracepoints,
//! counted per thread with `perf_event_open` and never sampled, so the measured binary stays as it is.
//!
//! Enabling any syscall tracepoint sends every system call on the machine through the kernel's slow entry path
//! while it is open, so this is opt-in (`--count-syscalls`) and its runs are for counts, not for timing. Reading
//! the tracepoint ids needs tracefs, which usually means root.

use std::sync::atomic::{AtomicBool, Ordering};

/// The calls a relay's data path is made of, and the two that show its wakeups.
pub const NAMES: [&str; 14] = [
    "read",
    "readv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "write",
    "writev",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "splice",
    "epoll_pwait",
    "epoll_pwait2",
    "futex",
];
pub const RECV: [&str; 5] = ["read", "readv", "recvfrom", "recvmsg", "recvmmsg"];
pub const SEND: [&str; 5] = ["write", "writev", "sendto", "sendmsg", "sendmmsg"];

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn enable() -> Result<(), String> {
    imp::check()?;
    if Counters::open(std::process::id()).is_none() {
        return Err("--count-syscalls: perf_event_open refused the tracepoints (perf_event_paranoid, or not root)".into());
    }
    ENABLED.store(true, Ordering::Relaxed);
    Ok(())
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Calls over a window: all of them, and each of `NAMES` (zero where the kernel has no such tracepoint).
#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub total: u64,
    pub by_name: [u64; NAMES.len()],
}

impl Counts {
    pub fn get(&self, name: &str) -> u64 {
        NAMES
            .iter()
            .position(|n| *n == name)
            .map_or(0, |i| self.by_name[i])
    }

    pub fn sum(&self, names: &[&str]) -> u64 {
        names.iter().map(|n| self.get(n)).sum()
    }
}

pub use imp::Counters;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(
    unsafe_code,
    reason = "perf_event_open has no safe wrapper; every pointer passed is a live local"
)]
mod imp {
    use std::os::fd::{FromRawFd, OwnedFd};

    use std::sync::OnceLock;

    use super::{Counts, NAMES};

    pub(super) struct Ids {
        total: Option<u64>,
        by_name: Vec<(&'static str, u64)>,
    }

    pub(super) fn check() -> Result<(), String> {
        match ids() {
            None => Err(
                "--count-syscalls needs the syscall tracepoints in tracefs (Linux, usually as root)".into(),
            ),
            Some(ids) if ids.total.is_none() => {
                Err("--count-syscalls: no raw_syscalls:sys_enter tracepoint".into())
            }
            Some(_) => Ok(()),
        }
    }

    const PERF_TYPE_TRACEPOINT: u32 = 2;
    const EXCLUDE_KERNEL: u64 = 1 << 5;
    const EXCLUDE_HV: u64 = 1 << 6;
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

    #[repr(C)]
    struct Attr {
        kind: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        bp_addr: u64,
    }

    pub(super) fn ids() -> Option<&'static Ids> {
        static IDS: OnceLock<Option<Ids>> = OnceLock::new();
        IDS.get_or_init(|| {
            let root = [
                "/sys/kernel/tracing/events",
                "/sys/kernel/debug/tracing/events",
            ]
            .into_iter()
            .find(|r| std::path::Path::new(r).join("syscalls").is_dir())?;
            let id = |path: String| -> Option<u64> {
                std::fs::read_to_string(format!("{root}/{path}/id"))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };
            let by_name: Vec<_> = NAMES
                .iter()
                .filter_map(|n| Some((*n, id(format!("syscalls/sys_enter_{n}"))?)))
                .collect();
            (!by_name.is_empty()).then(|| Ids {
                total: id("raw_syscalls/sys_enter".into()),
                by_name,
            })
        })
        .as_ref()
    }

    fn open(tid: i32, config: u64, flags: u64) -> Option<OwnedFd> {
        let attr = Attr {
            kind: PERF_TYPE_TRACEPOINT,
            size: std::mem::size_of::<Attr>() as u32,
            config,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags,
            wakeup_events: 0,
            bp_type: 0,
            bp_addr: 0,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &raw const attr,
                tid,
                -1i32,
                -1i32,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn read(fd: OwnedFd) -> u64 {
        use std::io::Read;
        let mut bytes = [0u8; 8];
        match std::fs::File::from(fd).read_exact(&mut bytes) {
            Ok(()) => u64::from_ne_bytes(bytes),
            Err(_) => 0,
        }
    }

    pub struct Counters {
        total: Vec<OwnedFd>,
        by_name: Vec<(&'static str, Vec<OwnedFd>)>,
    }

    impl Counters {
        pub fn open(pid: u32) -> Option<Counters> {
            let ids = ids()?;
            let tids: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/task"))
                .ok()?
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .collect();
            for flags in [EXCLUDE_HV, EXCLUDE_HV | EXCLUDE_KERNEL] {
                let each = |id: u64| -> Option<Vec<OwnedFd>> {
                    tids.iter().map(|&tid| open(tid, id, flags)).collect()
                };
                let Some(total) = ids.total.and_then(each) else {
                    continue;
                };
                let by_name: Option<Vec<_>> = ids
                    .by_name
                    .iter()
                    .map(|&(name, id)| Some((name, each(id)?)))
                    .collect();
                if let Some(by_name) = by_name {
                    return Some(Counters { total, by_name });
                }
            }
            None
        }

        pub fn read(self) -> Counts {
            let mut counts = Counts {
                total: self.total.into_iter().map(read).sum(),
                ..Counts::default()
            };
            for (name, fds) in self.by_name {
                if let Some(i) = NAMES.iter().position(|n| *n == name) {
                    counts.by_name[i] = fds.into_iter().map(read).sum();
                }
            }
            counts
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use super::Counts;

    pub(super) fn check() -> Result<(), String> {
        Err("--count-syscalls needs Linux".into())
    }

    pub struct Counters;

    impl Counters {
        pub fn open(_: u32) -> Option<Counters> {
            None
        }

        pub fn read(self) -> Counts {
            Counts::default()
        }
    }
}

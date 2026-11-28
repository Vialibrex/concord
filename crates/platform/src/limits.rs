#[cfg(unix)]
pub use unix::{FdPressure, fd_limit, open_fd_count, raise_fd_limit};
#[cfg(windows)]
pub use windows::{FdPressure, fd_limit, open_fd_count, raise_fd_limit};

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn read_rlimit() -> Option<libc::rlimit> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid out-pointer for the duration of the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        (rc == 0).then_some(limit)
    }

    #[allow(
        clippy::useless_conversion,
        reason = "rlim_t is 32-bit on armv7 Android"
    )]
    pub fn fd_limit() -> Option<u64> {
        let soft = u64::from(read_rlimit()?.rlim_cur).min(platform_cap());
        (soft > 0).then_some(soft)
    }

    #[cfg(target_os = "macos")]
    fn platform_cap() -> u64 {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: the name is NUL-terminated and `value`/`len` match the size passed.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.maxfilesperproc".as_ptr(),
                std::ptr::from_mut(&mut value).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 && value > 0 {
            value as u64
        } else {
            10_240
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn platform_cap() -> u64 {
        u64::MAX
    }

    /// Go's runtime raises the soft limit to one below the hard limit on start (`syscall/rlimit.go:32-42`);
    /// a Rust process keeps the default soft limit otherwise.
    #[allow(
        clippy::useless_conversion,
        reason = "rlim_t is 32-bit on armv7 Android"
    )]
    pub fn raise_fd_limit() -> Option<u64> {
        let mut limit = read_rlimit()?;
        let target = u64::from(limit.rlim_max)
            .saturating_sub(1)
            .min(platform_cap());
        if u64::from(limit.rlim_cur) < target {
            limit.rlim_cur = target as libc::rlim_t;
            // SAFETY: `limit` is a valid in-pointer for the duration of the call.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                tracing::warn!(
                    "raising the descriptor limit failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
        fd_limit()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn open_fd_count() -> Option<usize> {
        let entries = std::fs::read_dir("/proc/self/fd").ok()?.count();
        Some(entries.saturating_sub(1))
    }

    #[cfg(target_os = "macos")]
    pub fn open_fd_count() -> Option<usize> {
        let pid = std::process::id() as libc::c_int;
        let item = std::mem::size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer asks only for the size the table needs.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return None;
        }
        let capacity = size as usize / item + 16;
        let mut entries = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            capacity
        ];
        // SAFETY: `entries` is writable for `capacity * item` bytes, the size passed.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                (capacity * item) as libc::c_int,
            )
        };
        (written > 0).then(|| written as usize / item)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub fn open_fd_count() -> Option<usize> {
        None
    }

    /// Refuses new dials above three quarters of `RLIMIT_NOFILE`. The limit is read
    /// when first needed, never at construction, because it may be raised after.
    pub struct FdPressure {
        null: Option<File>,
        armed: AtomicBool,
        ceiling: AtomicU64,
        last_blocked: AtomicBool,
        limit: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    }

    impl Default for FdPressure {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FdPressure {
        pub fn new() -> Self {
            Self::with_limit_source(Box::new(fd_limit))
        }

        pub fn with_limit_source(limit: Box<dyn Fn() -> Option<u64> + Send + Sync>) -> Self {
            let null = File::open("/dev/null")
                .inspect_err(|err| tracing::error!("fd pressure probe disabled: {err}"))
                .ok();
            FdPressure {
                armed: AtomicBool::new(null.is_some()),
                null,
                ceiling: AtomicU64::new(0),
                last_blocked: AtomicBool::new(false),
                limit,
            }
        }

        pub fn should_block(&self) -> bool {
            if !self.armed.load(Ordering::Relaxed) {
                return false;
            }
            let blocked = self.probe();
            if self.last_blocked.swap(blocked, Ordering::Relaxed) != blocked {
                if blocked {
                    tracing::warn!(
                        "refusing new connections: {} of {} descriptors in use",
                        open_fd_count().unwrap_or_default(),
                        self.ceiling()
                    );
                } else {
                    tracing::warn!("descriptor pressure cleared, accepting new connections");
                }
            }
            blocked
        }

        fn ceiling(&self) -> u64 {
            match self.ceiling.load(Ordering::Relaxed) {
                0 => self.refresh_ceiling(),
                value => value,
            }
        }

        fn refresh_ceiling(&self) -> u64 {
            let limit = (self.limit)().unwrap_or(u64::MAX);
            let ceiling = limit / 4 * 3;
            self.ceiling.store(ceiling, Ordering::Relaxed);
            ceiling
        }

        fn disarm(&self, err: &io::Error) {
            if self.armed.swap(false, Ordering::Relaxed) {
                self.last_blocked.store(false, Ordering::Relaxed);
                tracing::error!("fd pressure probe disabled after an unexpected error: {err}");
            }
        }

        // `dup` reports the lowest free descriptor, not how many are open, so a high
        // long-lived descriptor alone must not block: count for real past the ceiling.
        fn probe(&self) -> bool {
            let Some(null) = &self.null else {
                return false;
            };
            let lowest_free = match null.try_clone() {
                Ok(dup) => dup.as_raw_fd() as u64,
                Err(err) => {
                    if matches!(err.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
                        return true;
                    }
                    self.disarm(&err);
                    return false;
                }
            };
            if lowest_free <= self.ceiling() {
                return false;
            }
            let ceiling = self.refresh_ceiling();
            open_fd_count().is_some_and(|count| count as u64 > ceiling)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_limit_can_be_read_and_raised() {
            let before = fd_limit().unwrap();
            let after = raise_fd_limit().unwrap();
            assert!(after >= before);
            assert_eq!(fd_limit(), Some(after));
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn open_descriptors_are_counted() {
            let before = open_fd_count().unwrap();
            let files: Vec<File> = (0..64).map(|_| File::open("/dev/null").unwrap()).collect();
            let after = open_fd_count().unwrap();
            assert!(after >= before + files.len() / 2, "{before} -> {after}");
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn pressure_follows_the_limit_and_recovers() {
            // Other tests can close low descriptors after this guard opens its sentinel.
            // Its process-wide descriptor fixture must therefore run in its own process.
            const CHILD: &str = "CONCORD_TEST_FD_PRESSURE_CHILD";
            if std::env::var_os(CHILD).is_none() {
                #[cfg(target_os = "macos")]
                let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .env(CHILD, "1")
                    .args([
                        "--exact",
                        "limits::unix::tests::pressure_follows_the_limit_and_recovers",
                        "--test-threads=1",
                    ])
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(output.status.success(), "{stdout}\n{stderr}");
                assert!(
                    stdout.contains("test result: ok. 1 passed; 0 failed;"),
                    "child did not run the assertion body: {stdout}\n{stderr}"
                );
                return;
            }
            let limit = std::sync::Arc::new(AtomicU64::new(4));
            let source = std::sync::Arc::clone(&limit);
            let pressure = FdPressure::with_limit_source(Box::new(move || {
                Some(source.load(Ordering::Relaxed))
            }));
            assert!(pressure.should_block());
            assert!(pressure.should_block());

            limit.store(1 << 16, Ordering::Relaxed);
            assert!(!pressure.should_block());
            assert!(!pressure.should_block());
        }

        #[test]
        fn plenty_of_headroom_never_blocks() {
            let pressure = FdPressure::new();
            raise_fd_limit();
            for _ in 0..3 {
                assert!(!pressure.should_block());
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    #[allow(
        clippy::useless_conversion,
        reason = "rlim_t is 32-bit on armv7 Android"
    )]
    pub fn fd_limit() -> Option<u64> {
        None
    }

    #[allow(
        clippy::useless_conversion,
        reason = "rlim_t is 32-bit on armv7 Android"
    )]
    pub fn raise_fd_limit() -> Option<u64> {
        None
    }

    pub fn open_fd_count() -> Option<usize> {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

        let mut count = 0u32;
        // SAFETY: the pseudo handle needs no cleanup and `count` is a valid out-pointer.
        let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
        (ok != 0).then_some(count as usize)
    }

    /// Windows has no descriptor ceiling to protect, so it never refuses a dial.
    #[derive(Default)]
    pub struct FdPressure;

    impl FdPressure {
        pub fn new() -> Self {
            FdPressure
        }

        pub fn should_block(&self) -> bool {
            false
        }
    }
}

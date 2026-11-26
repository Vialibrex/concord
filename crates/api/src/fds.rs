#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use concord_common::sync::lock;

/// Descriptors a host opened for the core and registered before `tun.start`
/// names them. Registering hands over ownership.
#[cfg(unix)]
#[derive(Default)]
pub struct AdoptedFds {
    next: AtomicU64,
    held: Mutex<HashMap<u64, OwnedFd>>,
}

#[cfg(unix)]
impl AdoptedFds {
    pub fn adopt(&self, fd: OwnedFd) -> u64 {
        let handle = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        {
            let mut held = lock(&self.held);
            held.insert(handle, fd);
        }
        handle
    }

    pub fn take(&self, handle: u64) -> Option<OwnedFd> {
        lock(&self.held).remove(&handle)
    }

    pub fn clear(&self) {
        lock(&self.held).clear();
    }

    pub fn len(&self) -> usize {
        lock(&self.held).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

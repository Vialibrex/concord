use std::ffi::c_void;
use std::panic::{UnwindSafe, catch_unwind};

use crate::callback::{Callback, Deliver, Release};
use crate::dart::{self, DartPort};
use crate::hub::hub;

fn guarded<T: Default>(run: impl FnOnce() -> T + UnwindSafe) -> T {
    catch_unwind(run).unwrap_or_default()
}

/// `Dart_InitializeApiDL`. Returns 0 on success; call it once with `NativeApi.initializeApiDLData`.
///
/// # Safety
/// `data` must be the pointer the Dart VM provides.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn concord_init_dart_api(data: *const c_void) -> i32 {
    // SAFETY: forwarded from this function's contract.
    let ready = unsafe { dart::initialize(data) };
    if ready { 0 } else { -1 }
}

/// Opens a session whose messages are posted to the Dart port `port`. Returns the session, or 0 when
/// the core is not up or the Dart API was not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn concord_open(port: i64) -> u64 {
    guarded(|| match hub() {
        Some(hub) if dart::is_initialized() => hub.open(Box::new(DartPort(port))),
        _ => 0,
    })
}

/// Opens a session whose messages are handed to `deliver` with `context`, one at a time on a core
/// thread; the bytes are valid only during the call. `deliver` returns false once the host is gone,
/// which ends the session. `release`, when set, runs with `context` once the core no longer holds the
/// session, and right away when this returns 0 because the core is not up.
///
/// # Safety
/// The callbacks must be safe to call from any thread with `context` until `release` has run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn concord_open_callback(
    deliver: Deliver,
    context: *mut c_void,
    release: Option<Release>,
) -> u64 {
    let receiver = Box::new(Callback::new(deliver, context, release));
    guarded(move || hub().map_or(0, |hub| hub.open(receiver)))
}

/// Copies one message onto a session. Returns 0 when the session does not exist.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn concord_send(session: u64, data: *const u8, len: usize) -> i32 {
    if len > 0 && (data.is_null() || len > isize::MAX as usize) {
        return 0;
    }
    let message = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: `data` is non-null, `len <= isize::MAX`, and the caller guarantees `len` readable bytes.
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    guarded(move || i32::from(hub().is_some_and(|hub| hub.send(session, message))))
}

#[unsafe(no_mangle)]
pub extern "C" fn concord_close(session: u64) {
    guarded(|| {
        if let Some(hub) = hub() {
            hub.close(session);
        }
    });
}

/// Hands a descriptor to the core, which closes it. The returned handle is what `tun.start` names as
/// `{"kind":"inherited","handle":…}`; 0 means the core is not up, and the descriptor is closed.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub extern "C" fn concord_adopt_fd(fd: i32) -> u64 {
    use std::os::fd::{FromRawFd, OwnedFd};

    if fd < 0 {
        return 0;
    }
    // SAFETY: `fd >= 0`, the host passes the descriptor on, and nothing else closes it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    guarded(move || hub().map_or(0, |hub| hub.adopt_fd(fd)))
}

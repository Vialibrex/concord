//! `libconcord.so`: the Rust core as an Android library. Its C ABI is `concord_start`, which
//! builds the core, `concord_set_platform_host` for the `VpnService` callbacks, and the session
//! functions of `concord-ffi`. A host binds them to its own runtime; the JNI glue is the host's.
//! Everything here is tested on the host.

#![allow(
    unsafe_code,
    reason = "the exported C functions, a descriptor handed over by the VpnService and liblog"
)]

mod abi;
pub mod core;
mod logcat;
pub mod platform;

pub use abi::{ConcordPlatformHost, concord_set_platform_host, concord_start};

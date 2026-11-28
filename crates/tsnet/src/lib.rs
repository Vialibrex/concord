#![allow(
    unsafe_code,
    reason = "the Tailscale node is a Go library behind a C ABI, loaded at run time"
)]

//! The Tailscale node runs in a Go library (`go/`, tsnet from metacubex/tailscale) that is only
//! loaded when a profile has a tailscale node. Packets cross the C ABI in batches: Concord's
//! userspace stack is the node's TUN device, so TCP, UDP and their lifetimes stay in Rust and
//! the library sees IP packets only.

use std::ffi::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use concord_common::RawSocket;

mod stage;

const ABI_VERSION: i32 = 3;
/// The most packets one `Node::send` or `Host::deliver` carries (`CTS_BATCH`).
pub const BATCH: usize = 128;
const EVENT_STATE: i32 = 1;
const EVENT_LOGIN_URL: i32 = 2;
const EVENT_ADDRS: i32 = 3;
const EVENT_LOG: i32 = 4;
const EVENT_ERROR: i32 = 5;
const EVENT_DEBUG: i32 = 6;
const EVENT_FAILED: i32 = 7;
const IO_TIMEOUT: i64 = -1;
const IO_FAILED: i64 = -2;
const IO_READ: i32 = 1;
const IO_WRITE: i32 = 2;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub const LIBRARY_NAME: &str = "libconcord_tsnet.so";
#[cfg(target_os = "macos")]
pub const LIBRARY_NAME: &str = "libconcord_tsnet.dylib";
#[cfg(windows)]
pub const LIBRARY_NAME: &str = "concord_tsnet.dll";
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
pub const LIBRARY_NAME: &str = "libconcord_tsnet.so";

/// What the node reports about itself.
#[derive(Debug)]
pub enum Event<'a> {
    State(&'a str),
    LoginUrl(&'a str),
    /// `{"ipv4": "...", "ipv6": "..."}` once the node is running, and again if they change.
    Addrs(&'a str),
    Log(&'a str),
    /// tsnet's `Logf`, sent only while `Host::verbose` says so.
    Debug(&'a str),
    /// The node stopped for good; `Error` is a problem it reports and goes on after.
    Failed(&'a str),
    Error(&'a str),
}

/// Packets the library hands over, valid for the `Host::deliver` call only.
pub struct Packets<'a> {
    ptrs: &'a [*const u8],
    lens: &'a [usize],
}

impl<'a> Packets<'a> {
    pub fn len(&self) -> usize {
        self.ptrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ptrs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let (ptrs, lens) = (self.ptrs, self.lens);
        // SAFETY: `on_deliver` builds `Packets` only from Go's pinned buffers, each covering its
        // length, and the borrow ends with the call.
        ptrs.iter()
            .zip(lens)
            .map(|(p, len)| unsafe { std::slice::from_raw_parts(*p, *len) })
    }
}

/// The Concord side of one node. Every method runs on a Go thread and must not block on the
/// tokio runtime. `deliver` and `writable` carry the traffic and must not allocate: glibc gives
/// each thread that allocates an arena of its own, and Go runs many threads.
pub trait Host: Send + Sync + 'static {
    /// Packets from the tailnet.
    fn deliver(&self, packets: Packets<'_>);
    /// The library has room again after `Node::send` took less than it was given.
    fn writable(&self);
    /// A socket the library opened for control, DERP or WireGuard traffic, before it is used.
    /// `dest` is the address it connects or binds to; `None` for one tailscale opened through
    /// netns (port mapping, netcheck), which is routed as one to any global address.
    fn prepare_socket(
        &self,
        socket: RawSocket,
        ipv6: bool,
        datagram: bool,
        dest: Option<&str>,
    ) -> bool;
    fn event(&self, event: Event<'_>);
    fn dns_answer(&self, id: u64, answer: Result<&[u8], &str>);
    /// The addresses of a control or DERP host; may block.
    fn lookup(&self, host: &str) -> Option<Vec<std::net::IpAddr>>;
    /// Whether tsnet's own log is wanted now.
    fn verbose(&self) -> bool;
    fn conns(&self) -> &dyn Conns;
}

/// The node's own connections when it has a dialer-proxy (`go/via.go`): control, DERP and
/// WireGuard's UDP, which Concord carries. `open` blocks and may allocate; the others carry
/// traffic and, like `Host::deliver`, must not allocate.
pub trait Conns: Send + Sync {
    /// A stream to `addr`, or a UDP session when `datagram`; `None` when it failed.
    fn open(&self, datagram: bool, addr: &str, timeout: Option<Duration>) -> Option<i64>;
    /// Waits for data and copies it into `buf`; `Done(0)` is the end of a stream. A session
    /// writes the sender as text into `from` and returns its length with the count.
    fn read(&self, conn: i64, buf: &mut [u8], from: &mut [u8]) -> (Io, usize);
    /// Waits for room and takes some of a stream's bytes, or a whole packet for `to`.
    fn write(&self, conn: i64, data: &[u8], to: &str) -> Io;
    /// Waiting reads, writes or both give up `after` from now, or never.
    fn deadline(&self, conn: i64, read: bool, write: bool, after: Option<Duration>);
    fn close(&self, conn: i64);
    /// Ends every connection, so no call the library waits in outlasts the node.
    fn close_all(&self);
}

pub enum Io {
    Done(usize),
    TimedOut,
    Failed,
}

impl Io {
    fn code(self) -> i64 {
        match self {
            Io::Done(len) => i64::try_from(len).unwrap_or(IO_FAILED),
            Io::TimedOut => IO_TIMEOUT,
            Io::Failed => IO_FAILED,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(
        "the Tailscale library {name} was not found ({cause}); a tailscale node needs it next to Concord"
    )]
    NotFound { name: String, cause: String },
    #[error("the Tailscale library {name} lacks {symbol}: {cause}")]
    Symbol {
        name: String,
        symbol: &'static str,
        cause: String,
    },
    #[error("the Tailscale library speaks ABI {found}, this Concord needs {ABI_VERSION}")]
    Version { found: i32 },
    #[error(
        "the Tailscale library {path} failed verification: its SHA-256 is {found}, this Concord was built for {pinned}"
    )]
    Mismatch {
        path: String,
        found: String,
        pinned: &'static str,
    },
    #[error("the checked Tailscale library could not be loaded: {0}")]
    Stage(String),
}

#[repr(C)]
struct Callbacks {
    user: *const c_void,
    deliver: unsafe extern "C" fn(*const c_void, *const *const u8, *const usize, usize),
    writable: unsafe extern "C" fn(*const c_void),
    prepare_socket: unsafe extern "C" fn(*const c_void, i64, i32, i32, *const c_char, usize) -> i32,
    event: unsafe extern "C" fn(*const c_void, i32, *const c_char, usize),
    dns_answer: unsafe extern "C" fn(*const c_void, u64, *const u8, usize, *const c_char, usize),
    lookup: unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_char, usize) -> i64,
    verbose: unsafe extern "C" fn(*const c_void) -> i32,
    conn_open: unsafe extern "C" fn(*const c_void, i32, *const c_char, usize, i64) -> i64,
    conn_read:
        unsafe extern "C" fn(*const c_void, i64, *mut u8, usize, *mut c_char, *mut usize) -> i64,
    conn_write:
        unsafe extern "C" fn(*const c_void, i64, *const u8, usize, *const c_char, usize) -> i64,
    conn_deadline: unsafe extern "C" fn(*const c_void, i64, i32, i64),
    conn_close: unsafe extern "C" fn(*const c_void, i64),
}

type StartFn =
    unsafe extern "C" fn(*const c_char, usize, *const Callbacks, *mut c_char, *mut usize) -> i64;
type SendFn = unsafe extern "C" fn(i64, *const *const u8, *const usize, usize) -> usize;
type QueryFn = unsafe extern "C" fn(i64, u64, *const u8, usize) -> i32;
type LinkFn = unsafe extern "C" fn(i64);
type StopFn = unsafe extern "C" fn(i64);

/// The loaded library. A Go runtime cannot be unloaded, so it stays for the life of the process
/// once a node needed it; with no node running it holds only idle Go threads and its heap.
pub struct Library {
    start: StartFn,
    send: SendFn,
    query_dns: QueryFn,
    link_changed: LinkFn,
    stop: StopFn,
    _lib: libloading::Library,
}

static LOADED: OnceLock<Result<Library, LoadError>> = OnceLock::new();

fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(path) = std::env::var_os("CONCORD_TSNET_LIB") {
        out.push(PathBuf::from(path));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
    {
        out.push(dir.join(LIBRARY_NAME));
        #[cfg(target_os = "macos")]
        out.push(dir.join("../Frameworks").join(LIBRARY_NAME));
    }
    // Windows looks a bare name up along PATH too, where anyone may put a DLL of that name.
    #[cfg(not(windows))]
    out.push(PathBuf::from(LIBRARY_NAME));
    out
}

impl Library {
    /// Loads the library on first use, which blocks; later calls return the same result.
    pub fn get() -> Result<&'static Library, &'static LoadError> {
        LOADED.get_or_init(Library::load).as_ref()
    }

    /// What `get` returned, once it has.
    pub fn loaded() -> Option<Result<&'static Library, &'static LoadError>> {
        LOADED.get().map(Result::as_ref)
    }

    /// Runs once; a library that fails its check is not replaced by another candidate.
    fn load() -> Result<Library, LoadError> {
        let mut causes = Vec::new();
        let loaded = candidates()
            .into_iter()
            .find_map(|path| match stage::open(&path) {
                Ok(stage::Opened::Loaded(lib)) => {
                    Some(kept_on_error(lib, Library::bind).map(|(fns, lib)| fns.into_library(lib)))
                }
                Ok(stage::Opened::Missing(why)) => {
                    causes.push(why);
                    None
                }
                Err(err) => Some(Err(err)),
            });
        let result = loaded.unwrap_or_else(|| {
            Err(LoadError::NotFound {
                name: LIBRARY_NAME.to_string(),
                cause: causes.join("; "),
            })
        });
        if let Err(err) = &result {
            tracing::warn!("[Tailscale] {err}");
        }
        result
    }

    fn bind(lib: &libloading::Library) -> Result<Bound, LoadError> {
        fn symbol<T: Copy>(lib: &libloading::Library, name: &'static str) -> Result<T, LoadError> {
            // SAFETY: each name is looked up with the signature `go/cts.h` and `go/main.go`
            // export it with, checked against the ABI version below.
            unsafe { lib.get::<T>(name.as_bytes()) }
                .map(|found| *found)
                .map_err(|err| LoadError::Symbol {
                    name: LIBRARY_NAME.to_string(),
                    symbol: name,
                    cause: err.to_string(),
                })
        }
        let version: unsafe extern "C" fn() -> i32 = symbol(lib, "cts_abi_version")?;
        // SAFETY: takes no arguments and returns a constant.
        let found = unsafe { version() };
        if found != ABI_VERSION {
            return Err(LoadError::Version { found });
        }
        Ok(Bound {
            start: symbol(lib, "cts_start")?,
            send: symbol(lib, "cts_send")?,
            query_dns: symbol(lib, "cts_query_dns")?,
            link_changed: symbol(lib, "cts_link_changed")?,
            stop: symbol(lib, "cts_stop")?,
        })
    }
}

struct Bound {
    start: StartFn,
    send: SendFn,
    query_dns: QueryFn,
    link_changed: LinkFn,
    stop: StopFn,
}

impl Bound {
    fn into_library(self, lib: libloading::Library) -> Library {
        Library {
            start: self.start,
            send: self.send,
            query_dns: self.query_dns,
            link_changed: self.link_changed,
            stop: self.stop,
            _lib: lib,
        }
    }
}

/// Binds a loaded library, and keeps it loaded when it does not fit: loading started its Go
/// runtime, whose threads run its code from then on. Go marks an ELF c-shared library nodelete,
/// but a DLL or dylib would be unmapped under them.
fn kept_on_error<L, T>(
    lib: L,
    bind: impl FnOnce(&L) -> Result<T, LoadError>,
) -> Result<(T, L), LoadError> {
    match bind(&lib) {
        Ok(bound) => Ok((bound, lib)),
        Err(err) => {
            std::mem::forget(lib);
            Err(err)
        }
    }
}

struct Shared {
    host: Arc<dyn Host>,
}

/// One running node. Dropping it stops the node and waits for its Go side to finish, so drop it
/// where blocking for a moment is allowed.
pub struct Node {
    lib: &'static Library,
    handle: i64,
    callbacks: *mut Callbacks,
    shared: *const Shared,
}

// SAFETY: the raw pointers are owned by the node and only freed in Drop, after cts_stop
// returned; the Go side synchronises its own state. Not Sync: cts_send's batch views are
// one caller's at a time.
unsafe impl Send for Node {}

#[derive(Debug, thiserror::Error)]
#[error("the Tailscale library refused the node: {0}")]
pub struct StartError(String);

impl Node {
    /// Starts bringing a node up from `config` (JSON with `go/main.go`'s `nodeConfig` fields) and
    /// returns at once; progress arrives as events.
    pub fn start(
        lib: &'static Library,
        config: &str,
        host: Arc<dyn Host>,
    ) -> Result<Node, StartError> {
        let shared = Box::into_raw(Box::new(Shared { host }));
        let callbacks = Box::into_raw(Box::new(Callbacks {
            user: shared.cast(),
            deliver: on_deliver,
            writable: on_writable,
            prepare_socket: on_prepare_socket,
            event: on_event,
            dns_answer: on_dns_answer,
            lookup: on_lookup,
            verbose: on_verbose,
            conn_open: on_conn_open,
            conn_read: on_conn_read,
            conn_write: on_conn_write,
            conn_deadline: on_conn_deadline,
            conn_close: on_conn_close,
        }));
        let mut why = [0u8; 512];
        let mut why_len = why.len();
        // SAFETY: `config` is valid for the call and copied by Go, as is `why`, which Go writes
        // at most `why_len` bytes into; `callbacks` and the `Shared` it points to live until
        // Drop, after cts_stop guarantees no callback runs.
        let handle = unsafe {
            (lib.start)(
                config.as_ptr().cast(),
                config.len(),
                callbacks,
                why.as_mut_ptr().cast(),
                &raw mut why_len,
            )
        };
        if handle <= 0 {
            // SAFETY: Go did not keep the pointers when it refused the node.
            unsafe {
                drop(Box::from_raw(callbacks));
                drop(Box::from_raw(shared));
            }
            let why = why.get(..why_len).unwrap_or_default();
            return Err(StartError(String::from_utf8_lossy(why).into_owned()));
        }
        Ok(Node {
            lib,
            handle,
            callbacks,
            shared,
        })
    }

    /// Offers up to `BATCH` packets for the tailnet and returns how many were taken; Go copies
    /// them before it returns. A short count is followed by one `Host::writable`.
    pub fn send<'p>(&self, packets: impl IntoIterator<Item = &'p [u8]>) -> usize {
        let mut ptrs = [std::ptr::null::<u8>(); BATCH];
        let mut lens = [0usize; BATCH];
        let mut count = 0;
        for (packet, (ptr, len)) in packets.into_iter().zip(ptrs.iter_mut().zip(&mut lens)) {
            (*ptr, *len) = (packet.as_ptr(), packet.len());
            count += 1;
        }
        // SAFETY: both arrays and the packets they point to outlive the call; Go copies them.
        unsafe { (self.lib.send)(self.handle, ptrs.as_ptr(), lens.as_ptr(), count) }
    }

    /// Asks the node's resolver; the answer comes as `Host::dns_answer` with `id`, unless this
    /// returns false because the node is gone.
    pub fn query_dns(&self, id: u64, query: &[u8]) -> bool {
        // SAFETY: Go copies the query before it returns.
        unsafe { (self.lib.query_dns)(self.handle, id, query.as_ptr(), query.len()) == 0 }
    }

    /// The device's network changed under the node; it reopens its sockets and finds its paths
    /// again, in the background.
    pub fn link_changed(&self) {
        // SAFETY: takes the handle only and returns at once.
        unsafe { (self.lib.link_changed)(self.handle) }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // SAFETY: `shared` lives until the end of this function.
        unsafe { &*self.shared }.host.conns().close_all();
        // SAFETY: cts_stop returns only after the node's goroutines and its calls through
        // `Conns` ended, so no callback can use the pointers freed after it.
        unsafe {
            (self.lib.stop)(self.handle);
            drop(Box::from_raw(self.callbacks));
            drop(Box::from_raw(self.shared.cast_mut()));
        }
    }
}

fn guarded<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// # Safety
/// `user` is the `Shared` a live `Node` owns.
unsafe fn shared<'a>(user: *const c_void) -> &'a Shared {
    // SAFETY: the caller's contract.
    unsafe { &*user.cast::<Shared>() }
}

/// # Safety
/// `ptr` is null or points to `len` readable bytes, valid for `'a`.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// # Safety
/// `ptr` is null or points to `len` bytes, valid and not otherwise borrowed for `'a`.
unsafe fn bytes_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if ptr.is_null() {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

/// # Safety
/// `text` is null or points to `len` readable bytes.
unsafe fn text<'a>(text: *const c_char, len: usize) -> &'a str {
    if text.is_null() {
        return "";
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), len) };
    std::str::from_utf8(bytes).unwrap_or("")
}

unsafe extern "C" fn on_deliver(
    user: *const c_void,
    packets: *const *const u8,
    lens: *const usize,
    count: usize,
) {
    guarded((), || {
        // SAFETY: Go passes `count` pinned packets with their lengths, valid for this call.
        let packets = unsafe {
            Packets {
                ptrs: std::slice::from_raw_parts(packets, count),
                lens: std::slice::from_raw_parts(lens, count),
            }
        };
        // SAFETY: `user` belongs to a live node.
        unsafe { shared(user) }.host.deliver(packets);
    });
}

unsafe extern "C" fn on_writable(user: *const c_void) {
    // SAFETY: `user` belongs to a live node.
    guarded((), || unsafe { shared(user) }.host.writable());
}

unsafe extern "C" fn on_prepare_socket(
    user: *const c_void,
    fd: i64,
    family: i32,
    datagram: i32,
    addr: *const c_char,
    addr_len: usize,
) -> i32 {
    guarded(-1, || {
        // SAFETY: Go passes `addr_len` bytes valid for this call.
        let dest = Some(unsafe { text(addr, addr_len) }).filter(|addr| !addr.is_empty());
        // SAFETY: `user` belongs to a live node.
        let host = &unsafe { shared(user) }.host;
        if host.prepare_socket(RawSocket(fd), family == 6, datagram != 0, dest) {
            0
        } else {
            -1
        }
    })
}

unsafe extern "C" fn on_event(user: *const c_void, kind: i32, raw: *const c_char, len: usize) {
    guarded((), || {
        // SAFETY: Go passes `len` bytes valid for this call.
        let body = unsafe { text(raw, len) };
        let event = match kind {
            EVENT_STATE => Event::State(body),
            EVENT_LOGIN_URL => Event::LoginUrl(body),
            EVENT_ADDRS => Event::Addrs(body),
            EVENT_LOG => Event::Log(body),
            EVENT_ERROR => Event::Error(body),
            EVENT_DEBUG => Event::Debug(body),
            EVENT_FAILED => Event::Failed(body),
            _ => return,
        };
        // SAFETY: `user` belongs to a live node.
        unsafe { shared(user) }.host.event(event);
    });
}

unsafe extern "C" fn on_dns_answer(
    user: *const c_void,
    id: u64,
    msg: *const u8,
    len: usize,
    err: *const c_char,
    err_len: usize,
) {
    guarded((), || {
        // SAFETY: `user` belongs to a live node.
        let host = &unsafe { shared(user) }.host;
        if err_len > 0 {
            // SAFETY: Go passes `err_len` bytes valid for this call.
            host.dns_answer(id, Err(unsafe { text(err, err_len) }));
        } else if !msg.is_null() {
            // SAFETY: Go passes `len` bytes valid for this call.
            host.dns_answer(id, Ok(unsafe { std::slice::from_raw_parts(msg, len) }));
        }
    });
}

unsafe extern "C" fn on_lookup(
    user: *const c_void,
    host: *const c_char,
    host_len: usize,
    out: *mut c_char,
    out_cap: usize,
) -> i64 {
    guarded(-1, || {
        // SAFETY: Go passes `host_len` bytes valid for this call.
        let host = unsafe { text(host, host_len) };
        // SAFETY: `user` belongs to a live node.
        let Some(found) = unsafe { shared(user) }.host.lookup(host) else {
            return -1;
        };
        // SAFETY: Go passes a buffer of `out_cap` writable bytes, valid for this call.
        let out = unsafe { std::slice::from_raw_parts_mut(out.cast::<u8>(), out_cap) };
        let mut used = 0;
        for ip in found {
            let line = format!("{ip}\n");
            let Some(slot) = out.get_mut(used..used + line.len()) else {
                break;
            };
            slot.copy_from_slice(line.as_bytes());
            used += line.len();
        }
        i64::try_from(used).unwrap_or(-1)
    })
}

unsafe extern "C" fn on_verbose(user: *const c_void) -> i32 {
    // SAFETY: `user` belongs to a live node.
    guarded(0, || i32::from(unsafe { shared(user) }.host.verbose()))
}

fn timeout(ns: i64, unit: fn(u64) -> Duration) -> Option<Duration> {
    u64::try_from(ns).ok().map(unit)
}

unsafe extern "C" fn on_conn_open(
    user: *const c_void,
    datagram: i32,
    addr: *const c_char,
    addr_len: usize,
    timeout_ms: i64,
) -> i64 {
    guarded(0, || {
        // SAFETY: Go passes `addr_len` bytes valid for this call.
        let addr = unsafe { text(addr, addr_len) };
        // SAFETY: `user` belongs to a live node.
        let conns = unsafe { shared(user) }.host.conns();
        conns
            .open(
                datagram != 0,
                addr,
                timeout(timeout_ms, Duration::from_millis),
            )
            .unwrap_or(0)
    })
}

unsafe extern "C" fn on_conn_read(
    user: *const c_void,
    conn: i64,
    buf: *mut u8,
    cap: usize,
    from: *mut c_char,
    from_len: *mut usize,
) -> i64 {
    guarded(IO_FAILED, || {
        // SAFETY: Go passes a buffer of `cap` bytes and one of `*from_len` bytes, both valid
        // for this call, and `from_len` itself.
        let (buf, from) = unsafe { (bytes_mut(buf, cap), bytes_mut(from.cast(), *from_len)) };
        // SAFETY: `user` belongs to a live node.
        let (io, written) = unsafe { shared(user) }.host.conns().read(conn, buf, from);
        // SAFETY: as above.
        unsafe { *from_len = written };
        io.code()
    })
}

unsafe extern "C" fn on_conn_write(
    user: *const c_void,
    conn: i64,
    data: *const u8,
    len: usize,
    to: *const c_char,
    to_len: usize,
) -> i64 {
    guarded(IO_FAILED, || {
        // SAFETY: Go passes `len` and `to_len` bytes valid for this call.
        let (data, to) = unsafe { (bytes(data, len), text(to, to_len)) };
        // SAFETY: `user` belongs to a live node.
        unsafe { shared(user) }
            .host
            .conns()
            .write(conn, data, to)
            .code()
    })
}

unsafe extern "C" fn on_conn_deadline(user: *const c_void, conn: i64, dir: i32, timeout_ns: i64) {
    guarded((), || {
        let after = timeout(timeout_ns, Duration::from_nanos);
        // SAFETY: `user` belongs to a live node.
        let conns = unsafe { shared(user) }.host.conns();
        conns.deadline(conn, dir & IO_READ != 0, dir & IO_WRITE != 0, after);
    });
}

unsafe extern "C" fn on_conn_close(user: *const c_void, conn: i64) {
    // SAFETY: `user` belongs to a live node.
    guarded((), || unsafe { shared(user) }.host.conns().close(conn));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct Loaded(Arc<AtomicBool>);

    impl Drop for Loaded {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_library_that_does_not_fit_stays_loaded() {
        let unloaded = Arc::new(AtomicBool::new(false));
        let bound = kept_on_error(Loaded(unloaded.clone()), |_| {
            Err::<(), _>(LoadError::Version { found: 2 })
        });
        assert!(matches!(bound, Err(LoadError::Version { found: 2 })));
        assert!(!unloaded.load(Ordering::SeqCst));
    }

    #[test]
    fn a_library_that_fits_is_kept_with_its_functions() {
        let unloaded = Arc::new(AtomicBool::new(false));
        let bound = kept_on_error(Loaded(unloaded.clone()), |_| Ok(7));
        let Ok((7, lib)) = bound else {
            panic!("did not bind");
        };
        drop(lib);
        assert!(unloaded.load(Ordering::SeqCst));
    }

    #[test]
    fn the_constants_are_those_of_cts_h() {
        let header = include_str!("../go/cts.h");
        let define = |name: &str| -> i64 {
            header
                .lines()
                .find_map(|line| {
                    let rest = line.strip_prefix("#define ")?.strip_prefix(name)?;
                    rest.strip_prefix(' ')?.trim().parse().ok()
                })
                .unwrap_or_else(|| panic!("{name} is not defined in cts.h"))
        };
        assert_eq!(define("CTS_ABI_VERSION"), i64::from(ABI_VERSION));
        assert_eq!(define("CTS_BATCH"), BATCH as i64);
        for (name, value) in [
            ("CTS_EVENT_STATE", EVENT_STATE),
            ("CTS_EVENT_LOGIN_URL", EVENT_LOGIN_URL),
            ("CTS_EVENT_ADDRS", EVENT_ADDRS),
            ("CTS_EVENT_LOG", EVENT_LOG),
            ("CTS_EVENT_ERROR", EVENT_ERROR),
            ("CTS_EVENT_DEBUG", EVENT_DEBUG),
            ("CTS_EVENT_FAILED", EVENT_FAILED),
            ("CTS_IO_READ", IO_READ),
            ("CTS_IO_WRITE", IO_WRITE),
        ] {
            assert_eq!(define(name), i64::from(value), "{name}");
        }
        assert_eq!(define("CTS_IO_TIMEOUT"), IO_TIMEOUT);
        assert_eq!(define("CTS_IO_FAILED"), IO_FAILED);
    }
}

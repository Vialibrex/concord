use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use concord_common::Tasks;
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime};

/// quinn spawns an endpoint's driver and each connection's through its runtime. They run until
/// the connection has drained after its close (3 PTO, RFC 9000 section 10.2), which is what
/// sends the CONNECTION_CLOSE, so they run to their end.
pub struct TrackedRuntime(pub Tasks);

impl std::fmt::Debug for TrackedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrackedRuntime")
    }
}

impl Runtime for TrackedRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        TokioRuntime.new_timer(at)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn_to_end(future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        TokioRuntime.now()
    }
}

/// The peer hears the connection close when the engine stops, as sing-box's outbounds send
/// CONNECTION_CLOSE from their `Close`. The watch holds the connection until it closes, so its
/// owner closes it when dropped.
pub fn close_on_stop(tasks: &Tasks, conn: quinn::Connection) {
    let stop = tasks.clone();
    tasks.spawn_to_end(async move {
        tokio::select! {
            () = stop.stopped() => conn.close(quinn::VarInt::from_u32(0), b""),
            _ = conn.closed() => {}
        }
    });
}

//! A TUN descriptor on a poller of its own, which the sockets of its flows join: the driver
//! hears all of them in one wait, as a sing-tun engine waits on one epoll for its TUN and its
//! flows' sockets (`stack_go_io_linux.go:177-192`, `:227-229`).

use std::sync::Arc;

use super::*;

/// The `Device` methods a device on its own poller takes from it, on Linux and Android alike.
macro_rules! queued_device {
    () => {
        fn prepare(self) -> io::Result<Self> {
            self.queued()
        }

        fn socket_owner(&self) -> Option<std::sync::Arc<dyn concord_netstack::SocketOwner>> {
            self.queue_owner()
        }

        fn socket_watcher(
            &self,
        ) -> Option<std::sync::Arc<dyn concord_common::SocketWatcher + Send + Sync>> {
            self.queue_watcher()
        }

        fn poll_io(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_queue(cx, false)
        }

        fn poll_park(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_queue(cx, true)
        }

        fn set_busy(&self, busy: bool) -> io::Result<bool> {
            self.set_queue_busy(busy)
        }
    };
}
pub(super) use queued_device;

impl DeviceIo {
    fn queued(self) -> io::Result<Self> {
        let Self::Tokio(device) = self else {
            return Ok(self);
        };
        let device = Arc::new(device.into_sync()?);
        let reactor = Arc::new(crate::reactor::Reactor::new()?);
        let ready = Arc::new(concord_netstack::SocketReady::default());
        let registration = reactor.register(Arc::clone(&device), Arc::clone(&ready))?;
        Ok(Self::Queued {
            device,
            reactor,
            ready,
            _registration: registration,
        })
    }

    fn reactor(&self) -> Option<&Arc<crate::reactor::Reactor>> {
        match self {
            Self::Queued { reactor, .. } => Some(reactor),
            Self::Tokio(_) => None,
        }
    }
}

impl TunDevice {
    pub(super) fn queued(self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.queued()?,
            ..self
        })
    }

    pub(super) fn queue_owner(&self) -> Option<Arc<dyn concord_netstack::SocketOwner>> {
        let reactor = self.inner.reactor()?;
        Some(Arc::clone(reactor) as _)
    }

    pub(super) fn queue_watcher(
        &self,
    ) -> Option<Arc<dyn concord_common::SocketWatcher + Send + Sync>> {
        let reactor = self.inner.reactor()?;
        Some(Arc::clone(reactor) as _)
    }

    pub(super) fn poll_queue(&self, cx: &mut Context<'_>, parking: bool) -> Poll<io::Result<()>> {
        match self.inner.reactor() {
            Some(reactor) => reactor.poll(cx, parking),
            None => Poll::Pending,
        }
    }

    pub(super) fn set_queue_busy(&self, busy: bool) -> io::Result<bool> {
        match self.inner.reactor() {
            Some(reactor) => reactor.set_busy(busy),
            None => Ok(false),
        }
    }
}

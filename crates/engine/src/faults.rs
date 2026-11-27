use std::io;
use std::sync::Mutex;

use concord_common::sync::lock;
use concord_inbound::{ListenError, ListenerKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Mixed,
    Http,
    Socks,
    Redir,
    TProxy,
    Tun,
    Dns,
}

/// A service the engine was asked to run and could not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceFault {
    pub service: Service,
    pub address: String,
    pub kind: io::ErrorKind,
    pub message: String,
}

impl ServiceFault {
    /// Only the global ports are faults the host is told of; a profile listener that does
    /// not start is logged, as mihomo logs it.
    pub(crate) fn listener(error: &ListenError) -> Option<Self> {
        let service = match error.kind()? {
            ListenerKind::Mixed => Service::Mixed,
            ListenerKind::Http => Service::Http,
            ListenerKind::Socks => Service::Socks,
            ListenerKind::Redir => Service::Redir,
            ListenerKind::TProxy => Service::TProxy,
        };
        Some(ServiceFault {
            service,
            address: error.addr.clone(),
            kind: error.source.kind(),
            message: error.to_string(),
        })
    }
}

#[derive(Default)]
struct Slots {
    listeners: Vec<ServiceFault>,
    tun: Option<ServiceFault>,
    dns: Option<ServiceFault>,
}

/// Each slot holds the outcome of the last attempt, so a later success clears it.
#[derive(Default)]
pub(crate) struct Faults(Mutex<Slots>);

impl Faults {
    fn with<T>(&self, f: impl FnOnce(&mut Slots) -> T) -> T {
        f(&mut lock(&self.0))
    }

    pub fn set_listeners(&self, faults: Vec<ServiceFault>) {
        self.with(|slots| slots.listeners = faults);
    }

    pub fn set_tun(&self, fault: Option<ServiceFault>) {
        self.with(|slots| slots.tun = fault);
    }

    pub fn set_dns(&self, fault: Option<ServiceFault>) {
        self.with(|slots| slots.dns = fault);
    }

    pub fn tun(&self) -> Option<ServiceFault> {
        self.with(|slots| slots.tun.clone())
    }

    pub fn list(&self) -> Vec<ServiceFault> {
        self.with(|slots| {
            slots
                .listeners
                .iter()
                .chain(&slots.tun)
                .chain(&slots.dns)
                .cloned()
                .collect()
        })
    }
}

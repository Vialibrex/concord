use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use super::{Actions, SmartState, Stamp};

#[derive(Clone, Copy, Debug)]
pub struct FlowEnd {
    pub download: u64,
    /// The remote side reached EOF or an error first; `None` when unknown.
    pub remote_first: Option<bool>,
    pub cancelled: bool,
}

/// One TCP flow through a smart group. After its first call each of `on_upload` and `on_download` is one
/// relaxed atomic load.
pub struct FlowTap {
    state: Arc<SmartState>,
    id: u64,
    node: Arc<str>,
    site: Arc<str>,
    tls: bool,
    uploaded: AtomicBool,
    answered: AtomicBool,
    upload_at: OnceLock<Stamp>,
    done: bool,
}

pub(crate) struct FlowRef<'a> {
    pub id: u64,
    pub node: &'a Arc<str>,
    pub site: &'a Arc<str>,
    pub tls: bool,
    pub upload_at: Option<Stamp>,
}

impl FlowTap {
    pub(super) fn new(
        state: Arc<SmartState>,
        id: u64,
        node: Arc<str>,
        site: Arc<str>,
        tls: bool,
    ) -> FlowTap {
        FlowTap {
            state,
            id,
            node,
            site,
            tls,
            uploaded: AtomicBool::new(false),
            answered: AtomicBool::new(false),
            upload_at: OnceLock::new(),
            done: false,
        }
    }

    pub fn on_upload(&self) {
        if self.uploaded.load(Ordering::Relaxed) {
            return;
        }
        self.first_upload();
    }

    pub fn on_download(&self) {
        if self.answered.load(Ordering::Relaxed) {
            return;
        }
        self.first_download();
    }

    #[cold]
    fn first_upload(&self) {
        if self.uploaded.swap(true, Ordering::Relaxed) {
            return;
        }
        let now = Stamp::now();
        let _ = self.upload_at.set(now);
        if self.tls {
            self.state.flow_uploaded(&self.flow(), now);
        }
    }

    #[cold]
    fn first_download(&self) {
        if self.answered.swap(true, Ordering::Relaxed) {
            return;
        }
        self.state.flow_answered(&self.flow(), Stamp::now());
    }

    pub fn finish(mut self, end: FlowEnd) -> Actions {
        self.done = true;
        self.end(&end)
    }

    fn end(&self, end: &FlowEnd) -> Actions {
        let answered = self.answered.load(Ordering::Relaxed);
        self.state
            .flow_ended(&self.flow(), Stamp::now(), answered, end)
    }

    fn flow(&self) -> FlowRef<'_> {
        FlowRef {
            id: self.id,
            node: &self.node,
            site: &self.site,
            tls: self.tls,
            upload_at: self.upload_at.get().copied(),
        }
    }
}

impl Drop for FlowTap {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let actions = self.end(&FlowEnd {
            download: 0,
            remote_first: None,
            cancelled: true,
        });
        self.state.stash(actions);
    }
}

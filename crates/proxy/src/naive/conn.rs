use std::io;
use std::sync::{Arc, Weak};

use concord_common::{BoxStream, DialCx, Tasks};
use concord_transport::h2io::{Activity, ResponseCheck};
use http::Request;

use super::{h2, h3};
use crate::node::Link;
use crate::quic::QuicLink;

/// The server turned a stream away before processing it, with a GOAWAY, REFUSED_STREAM or
/// H3_REQUEST_REJECTED, so another connection may carry it.
#[derive(Debug)]
struct Unprocessed(io::Error);

impl std::fmt::Display for Unprocessed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Unprocessed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(super) fn unprocessed(err: io::Error) -> io::Error {
    io::Error::new(err.kind(), Unprocessed(err))
}

pub(super) fn is_unprocessed(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|inner| inner.is::<Unprocessed>())
}

pub(super) enum Dialer {
    H2 {
        link: Box<Link>,
        windows: h2::Windows,
        tasks: Tasks,
    },
    H3(Box<QuicLink>),
}

pub(super) enum Conn {
    H2(Arc<h2::Session>),
    H3(Arc<h3::Session>),
}

pub(super) enum Opened {
    H2(h2::Opened),
    H3(Box<h3::Opened>),
}

impl Dialer {
    pub(super) async fn connect(&self, cx: &DialCx<'_>) -> io::Result<Arc<Conn>> {
        let conn = match self {
            Dialer::H2 {
                link,
                windows,
                tasks,
            } => Conn::H2(h2::Session::connect(link, *windows, tasks, cx).await?),
            Dialer::H3(link) => Conn::H3(h3::Session::connect(link, cx).await?),
        };
        Ok(Arc::new(conn))
    }

    pub(super) fn tasks(&self) -> &Tasks {
        match self {
            Dialer::H2 { tasks, .. } => tasks,
            Dialer::H3(link) => &link.tasks,
        }
    }
}

/// A connection a slot moved off, by what its tunnels keep alive: the h2 connection task holds
/// its `Activity`, and each h3 stream its `Session`.
pub(super) enum Retired {
    H2(Weak<Activity>),
    H3(Weak<h3::Session>),
}

impl Retired {
    pub(super) fn gone(&self) -> bool {
        match self {
            Retired::H2(activity) => activity.strong_count() == 0,
            Retired::H3(session) => session.strong_count() == 0,
        }
    }

    pub(super) fn same(&self, other: &Retired) -> bool {
        match (self, other) {
            (Retired::H2(a), Retired::H2(b)) => a.ptr_eq(b),
            (Retired::H3(a), Retired::H3(b)) => a.ptr_eq(b),
            _ => false,
        }
    }

    pub(super) fn close(&self) {
        match self {
            Retired::H2(activity) => {
                if let Some(activity) = activity.upgrade() {
                    activity.close();
                }
            }
            Retired::H3(session) => {
                if let Some(session) = session.upgrade() {
                    session.close();
                }
            }
        }
    }
}

impl Conn {
    pub(super) fn retired(&self) -> Retired {
        match self {
            Conn::H2(session) => Retired::H2(session.activity_weak()),
            Conn::H3(session) => Retired::H3(Arc::downgrade(session)),
        }
    }

    pub(super) fn usable(&self) -> bool {
        match self {
            Conn::H2(session) => session.usable(),
            Conn::H3(session) => session.usable(),
        }
    }

    pub(super) fn close(&self) {
        match self {
            Conn::H2(session) => session.close(),
            Conn::H3(session) => session.close(),
        }
    }

    pub(super) async fn open(&self, request: Request<()>) -> io::Result<Opened> {
        Ok(match self {
            Conn::H2(session) => Opened::H2(session.open(request).await?),
            Conn::H3(session) => Opened::H3(Box::new(session.open(request).await?)),
        })
    }
}

impl Opened {
    /// The stream at once, its reads held until the answer passes `check`.
    pub(super) fn early(self, check: ResponseCheck) -> BoxStream {
        match self {
            Opened::H2(opened) => opened.early(check),
            Opened::H3(opened) => (*opened).early(check),
        }
    }

    /// The stream once its answer has passed `check`.
    pub(super) async fn answered(
        self,
        check: impl FnOnce(&http::response::Parts) -> io::Result<()>,
    ) -> io::Result<BoxStream> {
        match self {
            Opened::H2(opened) => opened.answered(check).await,
            Opened::H3(opened) => (*opened).answered(check).await,
        }
    }
}

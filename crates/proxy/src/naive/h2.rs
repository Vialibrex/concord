use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use concord_common::{BoxStream, DialCx, Tasks};
use concord_transport::h2io::{
    Activity, H2Body, Incoming, ResponseCheck, checked_handshake, h2_io_error,
};
use h2::client::{ResponseFuture, SendRequest};
use http::Request;

use super::conn::unprocessed;
use crate::node::Link;

const HEADER_TABLE: u32 = 64 * 1024;
const MAX_HEADER_LIST: u32 = 256 * 1024;
const STREAM_WINDOW: u32 = 64 * 1024 * 1024;
const SESSION_WINDOW: u32 = 128 * 1024 * 1024;
/// HTTP/2's largest flow-control window, 2^31 - 1 (RFC 9113 §6.9.1).
const MAX_WINDOW: u32 = (1 << 31) - 1;

/// Receive windows: naiveproxy's by default; a configured window sizes the session and half
/// of it each stream, as cronet-go's `SetHTTP2Options`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Windows {
    stream: u32,
    session: u32,
}

impl Windows {
    pub(super) fn new(configured: u64) -> Windows {
        if configured == 0 {
            return Windows {
                stream: STREAM_WINDOW,
                session: SESSION_WINDOW,
            };
        }
        let session = u32::try_from(configured)
            .unwrap_or(u32::MAX)
            .min(MAX_WINDOW);
        Windows {
            stream: (session / 2).max(1),
            session,
        }
    }
}

/// Chromium's SETTINGS, which h2 sends in ascending id order as Chromium does.
fn builder(windows: Windows) -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .header_table_size(HEADER_TABLE)
        .enable_push(false)
        .initial_window_size(windows.stream)
        .max_header_list_size(MAX_HEADER_LIST)
        .initial_connection_window_size(windows.session);
    builder
}

pub(super) struct Session {
    sender: SendRequest<Bytes>,
    activity: Arc<Activity>,
    going_away: AtomicBool,
}

/// A CONNECT sent, its answer not yet read.
pub(super) struct Opened {
    response: ResponseFuture,
    send: h2::SendStream<Bytes>,
    session: Arc<Session>,
}

impl Session {
    pub(super) async fn connect(
        link: &Link,
        windows: Windows,
        tasks: &Tasks,
        cx: &DialCx<'_>,
    ) -> io::Result<Arc<Session>> {
        let tls = link.open_tls(cx).await?;
        if tls.negotiated_alpn() != Some(b"h2") {
            return Err(io::Error::other("naive server did not negotiate h2"));
        }
        let (sender, activity) = checked_handshake(&builder(windows), Box::new(tls), tasks).await?;
        Ok(Arc::new(Session {
            sender,
            activity,
            going_away: AtomicBool::new(false),
        }))
    }

    /// A GOAWAY already read takes the connection out of use before a stream is asked of it, as
    /// Chromium's `MakeUnavailable` on receipt (`spdy_session.cc:2982`).
    pub(super) fn usable(&self) -> bool {
        if self.activity.ended() || self.going_away.load(Ordering::Relaxed) {
            return false;
        }
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(Err(err)) = self.sender.clone().poll_ready(&mut cx)
            && err.is_go_away()
        {
            self.going_away.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// A stream the server never processed may go again; only a GOAWAY also leaves this
    /// connection to the streams it has, as Chromium's `MakeUnavailable` (`spdy_session.cc:2982`).
    fn refused(&self, err: h2::Error) -> io::Error {
        if err.is_go_away() {
            self.going_away.store(true, Ordering::Relaxed);
            return unprocessed(h2_io_error(err));
        }
        if err.reason() == Some(h2::Reason::REFUSED_STREAM) {
            return unprocessed(h2_io_error(err));
        }
        h2_io_error(err)
    }

    pub(super) fn activity_weak(&self) -> Weak<Activity> {
        Arc::downgrade(&self.activity)
    }

    pub(super) fn close(&self) {
        self.activity.close();
    }

    pub(super) async fn open(self: &Arc<Self>, request: Request<()>) -> io::Result<Opened> {
        self.activity.before_stream();
        let sent = match self.sender.clone().ready().await {
            Ok(mut sender) => sender.send_request(request, false),
            Err(err) => Err(err),
        };
        let (response, send) = sent.map_err(|err| self.refused(err))?;
        Ok(Opened {
            response,
            send,
            session: self.clone(),
        })
    }
}

impl Opened {
    pub(super) fn early(self, check: ResponseCheck) -> BoxStream {
        Box::new(
            H2Body::new(self.send, Incoming::Response(self.response))
                .with_response_check(check)
                .without_half_close(),
        )
    }

    pub(super) async fn answered(
        self,
        check: impl FnOnce(&http::response::Parts) -> io::Result<()>,
    ) -> io::Result<BoxStream> {
        let session = self.session;
        let answer = self.response.await.map_err(|err| session.refused(err))?;
        let (head, body) = answer.into_parts();
        check(&head)?;
        Ok(Box::new(
            H2Body::new(self.send, Incoming::Body(body)).without_half_close(),
        ))
    }
}

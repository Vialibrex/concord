use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{BoxStream, Tasks};
use futures_util::future::BoxFuture;
use http::{Method, Request, Uri};

use super::MuxSession;
use crate::h2io::{
    Activity, H2Body, INITIAL_MAX_SEND_STREAMS, Incoming, STREAM_WINDOW, SafeSender, StreamGuard,
    h2_io_error, handshake_split, reserve_stream, spawn_connection,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// sing-mux sets the h2mux transport's `MaxReadFrameSize` to sing's 32 KiB buffer size; the
// connection window is the Go HTTP/2 client's default.
const MAX_FRAME_SIZE: u32 = 32 * 1024;
const CONN_WINDOW: u32 = 65_535 + (1 << 30);

pub(super) fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .initial_max_send_streams(INITIAL_MAX_SEND_STREAMS)
        .max_frame_size(MAX_FRAME_SIZE)
        .enable_push(false);
    builder
}

pub(super) struct H2MuxSession {
    sender: Mutex<SafeSender>,
    activity: Arc<Activity>,
    streams: Arc<AtomicUsize>,
    retired: AtomicBool,
}

impl H2MuxSession {
    pub async fn new(io: BoxStream, tasks: &Tasks) -> io::Result<Self> {
        let (sender, conn) = handshake_split(&client_builder(), io).await?;
        let activity = Activity::new();
        activity.touch();
        spawn_connection(tasks, conn, Some(IDLE_TIMEOUT), activity.clone());
        Ok(H2MuxSession {
            sender: Mutex::new(SafeSender::new(sender)),
            activity,
            streams: Arc::new(AtomicUsize::new(0)),
            retired: AtomicBool::new(false),
        })
    }
}

impl MuxSession for H2MuxSession {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        self.open_reserved(Some(reserve_stream(&self.streams)))
    }

    fn open_reserved(&self, guard: Option<StreamGuard>) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            let guard = guard.unwrap_or_else(|| reserve_stream(&self.streams));
            let sender = lock(&self.sender)
                .clone_sender()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let mut sender = sender.ready().await.map_err(h2_io_error)?;
            let uri: Uri = "localhost"
                .parse()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .body(())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let (response, send) = sender.send_request(request, false).map_err(h2_io_error)?;
            let body = H2Body::new(send, Incoming::Response(response))
                .with_activity(self.activity.clone())
                .on_drop(move || drop(guard));
            Ok(Box::new(body) as BoxStream)
        })
    }

    fn reserve(&self) -> Option<StreamGuard> {
        Some(reserve_stream(&self.streams))
    }

    fn streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.retired.load(Ordering::Relaxed)
            || self.activity.ended()
            || lock(&self.sender).max_streams().is_none()
    }

    fn close(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }

    fn can_take_new_request(&self) -> bool {
        !self.retired.load(Ordering::Relaxed)
            && !self.activity.ended()
            && lock(&self.sender)
                .max_streams()
                .is_some_and(|limit| self.streams() < limit)
    }
}

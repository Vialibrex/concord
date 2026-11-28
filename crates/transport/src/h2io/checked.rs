use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use concord_common::{BoxRead, BoxStream, Tasks};
use h2::client::SendRequest;
use tokio::io::{AsyncRead, ReadBuf};

use super::{Activity, h2_io_error, spawn_checked_connection};

/// An h2 client connection on Chromium's liveness check, whose socket stamps it alive on whatever
/// it reads, as Chromium's `SpdySession` sets `last_read_time_` on every socket read
/// (`spdy_session.cc:2079`): a WINDOW_UPDATE answering an upload counts, so streams need not
/// touch the [`Activity`] themselves. Streams write DATA straight to the write half (see
/// [`super::handshake_split`]).
pub async fn checked_handshake(
    builder: &h2::client::Builder,
    io: BoxStream,
    tasks: &Tasks,
) -> io::Result<(SendRequest<Bytes>, Arc<Activity>)> {
    let activity = Activity::new();
    let (read, write) = io.into_split();
    let read: BoxRead = Box::new(ReadStamp {
        io: read,
        activity: activity.clone(),
    });
    let (sender, connection) = builder
        .handshake_split(read, write)
        .await
        .map_err(h2_io_error)?;
    spawn_checked_connection(tasks, connection, activity.clone());
    Ok((sender, activity))
}

struct ReadStamp {
    io: BoxRead,
    activity: Arc<Activity>,
}

impl AsyncRead for ReadStamp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let read = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        read
    }
}

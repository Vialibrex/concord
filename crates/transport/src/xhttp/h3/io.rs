use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::{Session, error};
use crate::h3io::{H3Reader, RecvStream};

pub(super) struct Reader {
    recv: H3Reader,
    _session: Arc<Session>,
}

impl Reader {
    pub(super) fn new(recv: RecvStream, session: Arc<Session>) -> Self {
        Self {
            recv: H3Reader::new(recv),
            _session: session,
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().recv.poll_read(cx, buf).map_err(error)
    }
}

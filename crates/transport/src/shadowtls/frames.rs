use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, ReadBuf};

use crate::http1::invalid;

pub(super) const HEADER: usize = 5;
pub(super) const MAX_PLAINTEXT: usize = 16384;
pub(super) const CHANGE_CIPHER_SPEC: u8 = 20;
pub(super) const ALERT: u8 = 21;
pub(super) const HANDSHAKE: u8 = 22;
pub(super) const APPLICATION_DATA: u8 = 23;

pub(super) struct FrameReader {
    buf: Vec<u8>,
    have: usize,
    sized: bool,
}

impl FrameReader {
    pub fn new() -> Self {
        FrameReader {
            buf: vec![0; HEADER],
            have: 0,
            sized: false,
        }
    }

    /// `None` is a clean end of stream between two records.
    pub fn poll_frame<S: AsyncRead + Unpin + ?Sized>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            if self.have == self.buf.len() {
                if !self.sized {
                    let len = match (self.buf.get(3), self.buf.get(4)) {
                        (Some(hi), Some(lo)) => usize::from(u16::from_be_bytes([*hi, *lo])),
                        _ => return Poll::Ready(Err(invalid("short TLS record header"))),
                    };
                    self.sized = true;
                    self.buf.resize(HEADER + len, 0);
                    continue;
                }
                let frame = std::mem::replace(&mut self.buf, vec![0; HEADER]);
                self.have = 0;
                self.sized = false;
                return Poll::Ready(Ok(Some(frame)));
            }
            let Some(window) = self.buf.get_mut(self.have..) else {
                return Poll::Ready(Err(invalid("TLS record window")));
            };
            let mut window = ReadBuf::new(window);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut window))?;
            let got = window.filled().len();
            if got == 0 {
                if self.have == 0 && !self.sized {
                    return Poll::Ready(Ok(None));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.have += got;
        }
    }
}

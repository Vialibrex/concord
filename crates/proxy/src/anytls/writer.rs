use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::BoxWrite;
use concord_common::stream_buffer::StreamBuffer;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::frame::Framer;
use super::session::Out;

pub(super) struct FrameWriter {
    pub(super) sink: BoxWrite,
    pub(super) framer: Framer,
}

impl FrameWriter {
    pub(super) fn try_owned(
        &mut self,
        cx: &mut Context<'_>,
        frame: &mut StreamBuffer,
    ) -> io::Result<bool> {
        if !self.framer.passes_through() {
            return Ok(false);
        }
        let Poll::Ready(written) = Pin::new(&mut self.sink).poll_write(cx, frame.as_slice()) else {
            return Ok(false);
        };
        let written = written?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        frame.consume(written)?;
        if !frame.is_empty() {
            return Ok(false);
        }
        match Pin::new(&mut self.sink).poll_flush(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        }
    }

    pub(super) async fn send(&mut self, out: Out) -> io::Result<()> {
        let writes = match out {
            Out::Owned { frame, .. } if self.framer.passes_through() => {
                self.sink.write_all(frame.as_slice()).await?;
                return self.sink.flush().await;
            }
            Out::Owned { frame, .. } => self.framer.push(frame.as_slice().to_vec()),
            Out::Data(bytes) => self.framer.push(bytes),
            Out::FrameSlot => return Ok(()),
            Out::Unbuffer => {
                self.framer.buffering = false;
                None.into_iter().chain(Vec::new())
            }
        };
        for write in writes {
            self.sink.write_all(&write).await?;
        }
        if !self.framer.buffering {
            self.sink.flush().await?;
        }
        Ok(())
    }
}

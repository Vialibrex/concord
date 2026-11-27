use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::BoxWrite;
use concord_common::stream_buffer::StreamBuffer;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::frame::{CMD_PSH, CMD_SYN, Framer, HEADER, MAX_FRAME, data_frames, frame, header};
use super::session::Out;

pub(super) struct FrameWriter {
    pub(super) sink: BoxWrite,
    pub(super) framer: Framer,
}

async fn write_all_slices(sink: &mut BoxWrite, mut parts: [&[u8]; 3]) -> io::Result<()> {
    let mut start = 0;
    while start < parts.len() {
        let slices = [
            IoSlice::new(parts.get(start).copied().unwrap_or_default()),
            IoSlice::new(parts.get(start + 1).copied().unwrap_or_default()),
            IoSlice::new(parts.get(start + 2).copied().unwrap_or_default()),
        ];
        let count = parts.len() - start;
        let mut written = poll_fn(|cx| {
            Pin::new(&mut *sink).poll_write_vectored(cx, slices.get(..count).unwrap_or_default())
        })
        .await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        while written > 0 && start < parts.len() {
            let part = parts.get_mut(start).ok_or(io::ErrorKind::InvalidInput)?;
            if written < part.len() {
                *part = part.get(written..).unwrap_or_default();
                break;
            }
            written -= part.len();
            start += 1;
        }
    }
    Ok(())
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

    async fn send_open(&mut self, sid: u32, head: Vec<u8>) -> io::Result<()> {
        let syn = header(CMD_SYN, sid, 0);
        if self.framer.buffering {
            self.framer.buffer.extend_from_slice(&syn);
            self.framer.buffering = false;
            if head.is_empty() {
                return Ok(());
            }
            let body = if head.len() <= MAX_FRAME {
                frame(CMD_PSH, sid, &head)
            } else {
                data_frames(sid, &head)
            };
            for write in self.framer.push(body) {
                self.sink.write_all(&write).await?;
            }
            return self.sink.flush().await;
        }
        if self.framer.passes_through() && head.len() <= MAX_FRAME {
            if head.is_empty() {
                self.sink.write_all(&syn).await?;
                return self.sink.flush().await;
            }
            let psh = header(CMD_PSH, sid, head.len());
            if self.sink.is_write_vectored() {
                write_all_slices(&mut self.sink, [&syn, &psh, &head]).await?;
            } else {
                let mut combined = Vec::with_capacity(2 * HEADER + head.len());
                combined.extend_from_slice(&syn);
                combined.extend_from_slice(&psh);
                combined.extend_from_slice(&head);
                self.sink.write_all(&combined).await?;
            }
            return self.sink.flush().await;
        }
        for write in self.framer.push(syn.to_vec()) {
            self.sink.write_all(&write).await?;
        }
        if !head.is_empty() {
            let body = if head.len() <= MAX_FRAME {
                frame(CMD_PSH, sid, &head)
            } else {
                data_frames(sid, &head)
            };
            for write in self.framer.push(body) {
                self.sink.write_all(&write).await?;
            }
        }
        self.sink.flush().await
    }

    pub(super) async fn send(&mut self, out: Out) -> io::Result<()> {
        let writes = match out {
            Out::Open { sid, head } => return self.send_open(sid, head).await,
            Out::Owned { frame, .. } if self.framer.passes_through() => {
                self.sink.write_all(frame.as_slice()).await?;
                return self.sink.flush().await;
            }
            Out::Owned { frame, .. } => self.framer.push(frame.as_slice().to_vec()),
            Out::Data(bytes) | Out::Last(bytes) => self.framer.push(bytes),
            Out::FrameSlot => return Ok(()),
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

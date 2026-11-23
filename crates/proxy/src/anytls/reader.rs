use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::BoxRead;
use concord_common::stream_buffer::{ReadBufferOptions, StreamBuffer};
use tokio::io::{AsyncRead, ReadBuf};

use super::frame::{
    CMD_ALERT, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYNACK, CMD_UPDATE_PADDING,
    CMD_WASTE, HEADER,
};

pub(super) enum Frame {
    Data { sid: u32, payload: StreamBuffer },
    Control { cmd: u8, sid: u32, payload: Vec<u8> },
}

enum Body {
    Data {
        sid: u32,
        payload: StreamBuffer,
        len: usize,
    },
    Control {
        cmd: u8,
        sid: u32,
        payload: Vec<u8>,
        filled: usize,
    },
}

/// The session's read half. A frame read partly before `Pending` resumes in whichever task
/// polls next, so the session task and a stream can take turns at it.
pub(super) struct FrameReader {
    source: BoxRead,
    header: [u8; HEADER],
    filled: usize,
    body: Option<Body>,
    held: Option<Frame>,
}

impl FrameReader {
    pub(super) fn new(source: BoxRead) -> Self {
        FrameReader {
            source,
            header: [0; HEADER],
            filled: 0,
            body: None,
            held: None,
        }
    }

    /// Puts a frame back to be returned by the next `poll_frame`.
    pub(super) fn hold(&mut self, frame: Frame) {
        self.held = Some(frame);
    }

    /// The next frame. A data frame is read into a buffer with the room `options` gives for its
    /// stream, so that stream can hand it on whole.
    pub(super) fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        options: impl Fn(u32) -> Option<ReadBufferOptions>,
    ) -> Poll<io::Result<Frame>> {
        if let Some(frame) = self.held.take() {
            return Poll::Ready(Ok(frame));
        }
        loop {
            match &mut self.body {
                None => {
                    while self.filled < HEADER {
                        let rest = self.header.get_mut(self.filled..).unwrap_or_default();
                        self.filled += ready!(poll_fill(&mut self.source, cx, rest))?;
                    }
                    self.filled = 0;
                    self.body = start(self.header, &options)?;
                }
                Some(Body::Data { payload, len, .. }) => {
                    while payload.len() < *len {
                        let want = *len - payload.len();
                        let spare = payload
                            .spare_mut()
                            .get_mut(..want)
                            .ok_or(io::ErrorKind::InvalidInput)?;
                        let read = ready!(poll_fill(&mut self.source, cx, spare))?;
                        payload.advance(read)?;
                    }
                    if let Some(Body::Data { sid, payload, .. }) = self.body.take() {
                        return Poll::Ready(Ok(Frame::Data { sid, payload }));
                    }
                }
                Some(Body::Control {
                    payload, filled, ..
                }) => {
                    while *filled < payload.len() {
                        let rest = payload.get_mut(*filled..).unwrap_or_default();
                        *filled += ready!(poll_fill(&mut self.source, cx, rest))?;
                    }
                    if let Some(Body::Control {
                        cmd, sid, payload, ..
                    }) = self.body.take()
                    {
                        return Poll::Ready(Ok(Frame::Control { cmd, sid, payload }));
                    }
                }
            }
        }
    }
}

fn start(
    header: [u8; HEADER],
    options: &impl Fn(u32) -> Option<ReadBufferOptions>,
) -> io::Result<Option<Body>> {
    let [cmd, a, b, c, d, hi, lo] = header;
    let sid = u32::from_be_bytes([a, b, c, d]);
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    if cmd == CMD_PSH {
        if len == 0 {
            return Ok(None);
        }
        let options = match options(sid) {
            Some(options) => options,
            None => ReadBufferOptions::for_copy(Default::default(), Default::default())?,
        };
        let payload = options.take_for_read(len, 0)?;
        return Ok(Some(Body::Data { sid, payload, len }));
    }
    let carries_payload = matches!(
        cmd,
        CMD_SYNACK
            | CMD_WASTE
            | CMD_SETTINGS
            | CMD_ALERT
            | CMD_UPDATE_PADDING
            | CMD_SERVER_SETTINGS
    );
    let len = if carries_payload { len } else { 0 };
    Ok(Some(Body::Control {
        cmd,
        sid,
        payload: vec![0; len],
        filled: 0,
    }))
}

fn poll_fill(
    source: &mut BoxRead,
    cx: &mut Context<'_>,
    into: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut read = ReadBuf::new(into);
    ready!(Pin::new(source).poll_read(cx, &mut read))?;
    match read.filled().len() {
        0 => Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
        filled => Poll::Ready(Ok(filled)),
    }
}

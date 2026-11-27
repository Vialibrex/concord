mod error;
mod framed_read;
mod framed_write;

pub use self::error::{SendError, UserError};

use self::framed_read::FramedRead;
use self::framed_write::FramedWrite;

use crate::frame::{self, Data, Frame};
use crate::proto::Error;

use bytes::Buf;
use futures_core::Stream;
use futures_sink::Sink;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::length_delimited;

use std::io;

// Concord: split read/write traits allow opt-in client split-I/O connections to
// decouple FramedRead<R> from a shared FramedWrite<W> without changing Codec<T, B>.
pub(crate) trait CodecRead {
    fn set_max_recv_frame_size(&mut self, val: usize);
    fn set_max_recv_header_list_size(&mut self, val: usize);
    fn set_recv_header_table_size(&mut self, val: usize);
}

pub(crate) trait CodecWrite<B> {
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
    fn has_send_capacity(&mut self) -> bool;
    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError>;
    fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
    fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
    fn max_send_frame_size(&self) -> usize;
    fn set_max_send_frame_size(&mut self, val: usize);
    fn set_send_header_table_size(&mut self, val: usize);
    fn take_last_data_frame(&mut self) -> Option<Data<B>>;
    fn is_write_empty(&self) -> bool;
}

pub(crate) trait FrameSink<B>: CodecWrite<B> + Send {}

impl<T, B> FrameSink<B> for FramedWrite<T, B>
where
    T: AsyncWrite + Send + Unpin,
    B: Buf + Send,
{
}

impl<T, B> CodecWrite<B> for FramedWrite<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        FramedWrite::poll_ready(self, cx)
    }

    fn has_send_capacity(&mut self) -> bool {
        FramedWrite::has_capacity(self)
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        FramedWrite::buffer(self, item)
    }

    fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        FramedWrite::flush(self, cx)
    }

    fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        FramedWrite::shutdown(self, cx)
    }

    fn max_send_frame_size(&self) -> usize {
        FramedWrite::max_frame_size(self)
    }

    fn set_max_send_frame_size(&mut self, val: usize) {
        FramedWrite::set_max_frame_size(self, val);
    }

    fn set_send_header_table_size(&mut self, val: usize) {
        FramedWrite::set_header_table_size(self, val);
    }

    fn take_last_data_frame(&mut self) -> Option<Data<B>> {
        FramedWrite::take_last_data_frame(self)
    }

    fn is_write_empty(&self) -> bool {
        FramedWrite::is_empty(self)
    }
}

pub(crate) fn new_framed_write<W, B>(io: W) -> Box<dyn FrameSink<B>>
where
    W: AsyncWrite + Send + Unpin + 'static,
    B: Buf + Send + 'static,
{
    Box::new(FramedWrite::new(io))
}

/// Concord: read-only HTTP/2 frame decoder for split-I/O client connections.
pub(crate) struct SplitRead<R> {
    inner: FramedRead<R>,
}

impl<R: fmt::Debug> fmt::Debug for SplitRead<R> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SplitRead")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<R> SplitRead<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(io: R) -> Self {
        let delimited = length_delimited::Builder::new()
            .big_endian()
            .length_field_length(3)
            .length_adjustment(9)
            .num_skip(0)
            .new_read(io);
        let mut inner = FramedRead::new(delimited);
        inner.set_max_frame_size(frame::DEFAULT_MAX_FRAME_SIZE as usize);
        SplitRead { inner }
    }
}

impl<R> CodecRead for SplitRead<R> {
    fn set_max_recv_frame_size(&mut self, val: usize) {
        self.inner.set_max_frame_size(val);
    }

    fn set_max_recv_header_list_size(&mut self, val: usize) {
        self.inner.set_max_header_list_size(val);
    }

    fn set_recv_header_table_size(&mut self, val: usize) {
        self.inner.set_header_table_size(val);
    }
}

impl<R> Stream for SplitRead<R>
where
    R: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

#[derive(Debug)]
pub struct Codec<T, B> {
    inner: FramedRead<FramedWrite<T, B>>,
}

impl<T, B> Codec<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    /// Returns a new `Codec` with the default max frame size
    #[inline]
    pub fn new(io: T) -> Self {
        Self::with_max_recv_frame_size(io, frame::DEFAULT_MAX_FRAME_SIZE as usize)
    }

    /// Returns a new `Codec` with the given maximum frame size
    pub fn with_max_recv_frame_size(io: T, max_frame_size: usize) -> Self {
        // Wrap with writer
        let framed_write = FramedWrite::new(io);

        // Delimit the frames
        let delimited = length_delimited::Builder::new()
            .big_endian()
            .length_field_length(3)
            .length_adjustment(9)
            .num_skip(0) // Don't skip the header
            .new_read(framed_write);

        let mut inner = FramedRead::new(delimited);

        // Use FramedRead's method since it checks the value is within range.
        inner.set_max_frame_size(max_frame_size);

        Codec { inner }
    }
}

impl<T, B> Codec<T, B> {
    /// Updates the max received frame size.
    ///
    /// The change takes effect the next time a frame is decoded. In other
    /// words, if a frame is currently in process of being decoded with a frame
    /// size greater than `val` but less than the max frame size in effect
    /// before calling this function, then the frame will be allowed.
    #[inline]
    pub fn set_max_recv_frame_size(&mut self, val: usize) {
        self.inner.set_max_frame_size(val)
    }

    /// Returns the current max received frame size setting.
    ///
    /// This is the largest size this codec will accept from the wire. Larger
    /// frames will be rejected.
    #[cfg(feature = "unstable")]
    #[inline]
    pub fn max_recv_frame_size(&self) -> usize {
        self.inner.max_frame_size()
    }

    /// Returns the max frame size that can be sent to the peer.
    pub fn max_send_frame_size(&self) -> usize {
        self.inner.get_ref().max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_send_frame_size(&mut self, val: usize) {
        self.framed_write().set_max_frame_size(val)
    }

    /// Set the peer's header table size size.
    pub fn set_send_header_table_size(&mut self, val: usize) {
        self.framed_write().set_header_table_size(val)
    }

    /// Set the decoder header table size size.
    pub fn set_recv_header_table_size(&mut self, val: usize) {
        self.inner.set_header_table_size(val)
    }

    /// Set the max header list size that can be received.
    pub fn set_max_recv_header_list_size(&mut self, val: usize) {
        self.inner.set_max_header_list_size(val);
    }

    /// Get a reference to the inner stream.
    #[cfg(feature = "unstable")]
    pub fn get_ref(&self) -> &T {
        self.inner.get_ref().get_ref()
    }

    /// Get a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut().get_mut()
    }

    /// Takes the data payload value that was fully written to the socket
    pub(crate) fn take_last_data_frame(&mut self) -> Option<Data<B>> {
        self.framed_write().take_last_data_frame()
    }

    fn framed_write(&mut self) -> &mut FramedWrite<T, B> {
        self.inner.get_mut()
    }
}

impl<T, B> Codec<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    /// Returns `Ready` when the codec can buffer a frame
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().poll_ready(cx)
    }

    /// Returns whether the codec can buffer a frame without flushing the
    /// underlying I/O object.
    pub(crate) fn has_send_capacity(&mut self) -> bool {
        self.framed_write().has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` must be called first to ensure that a frame may be
    /// accepted.
    ///
    /// TODO: Rename this to avoid conflicts with Sink::buffer
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        self.framed_write().buffer(item)
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().flush(cx)
    }

    /// Shutdown the send half
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().shutdown(cx)
    }
}

// Concord: implement CodecRead / CodecWrite for Codec so proto helpers work for both
// unified Codec<T, B> and opt-in split-I/O connections.
impl<T, B> CodecRead for Codec<T, B> {
    fn set_max_recv_frame_size(&mut self, val: usize) {
        Codec::set_max_recv_frame_size(self, val);
    }

    fn set_max_recv_header_list_size(&mut self, val: usize) {
        Codec::set_max_recv_header_list_size(self, val);
    }

    fn set_recv_header_table_size(&mut self, val: usize) {
        Codec::set_recv_header_table_size(self, val);
    }
}

impl<T, B> CodecWrite<B> for Codec<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        Codec::poll_ready(self, cx)
    }

    fn has_send_capacity(&mut self) -> bool {
        Codec::has_send_capacity(self)
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        Codec::buffer(self, item)
    }

    fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        Codec::flush(self, cx)
    }

    fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        Codec::shutdown(self, cx)
    }

    fn max_send_frame_size(&self) -> usize {
        Codec::max_send_frame_size(self)
    }

    fn set_max_send_frame_size(&mut self, val: usize) {
        Codec::set_max_send_frame_size(self, val);
    }

    fn set_send_header_table_size(&mut self, val: usize) {
        Codec::set_send_header_table_size(self, val);
    }

    fn take_last_data_frame(&mut self) -> Option<Data<B>> {
        Codec::take_last_data_frame(self)
    }

    fn is_write_empty(&self) -> bool {
        self.inner.get_ref().is_empty()
    }
}

impl<T, B> Stream for Codec<T, B>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl<T, B> Sink<Frame<B>> for Codec<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    type Error = SendError;

    fn start_send(mut self: Pin<&mut Self>, item: Frame<B>) -> Result<(), Self::Error> {
        Codec::buffer(&mut self, item)?;
        Ok(())
    }
    /// Returns `Ready` when the codec can buffer a frame
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.framed_write().poll_ready(cx).map_err(Into::into)
    }

    /// Flush buffered data to the wire
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.framed_write().flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

// TODO: remove (or improve) this
impl<T> From<T> for Codec<T, bytes::Bytes>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn from(src: T) -> Self {
        Self::new(src)
    }
}

//! The bidirectional streams of a Hysteria 2 connection carry either a TCP request, whose
//! first varint is the frame type 0x401, or an HTTP/3 request. sing-quic tells them apart
//! before HTTP/3 reads the stream (`hysteria2/service.go:337-355`); h3 has no such hook and
//! would take 0x401 for an unknown frame, so the server reads the first varint itself and
//! hands h3 the other streams with what it read in front.

use std::io;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;

use crate::hysteria2::wire::{FRAME_TCP_REQUEST, read_varint};

pub(super) enum Route {
    /// A TCP request, whose frame type has been read.
    Tcp,
    /// Anything else, for h3, with the varint that was read.
    H3(Vec<u8>),
    /// The stream ended before its first varint.
    Ended,
}

pub(super) async fn route<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<Route> {
    Ok(match read_varint(recv).await? {
        Some((FRAME_TCP_REQUEST, _)) => Route::Tcp,
        Some((_, raw)) => Route::H3(raw),
        None => Route::Ended,
    })
}

/// A receiving side that yields `ahead` before the stream's own data.
pub(super) struct Prefixed<R> {
    ahead: Option<Bytes>,
    inner: R,
}

impl<R> Prefixed<R> {
    pub(super) fn new(ahead: Bytes, inner: R) -> Self {
        Prefixed {
            ahead: (!ahead.is_empty()).then_some(ahead),
            inner,
        }
    }
}

impl<R: quic::RecvStream<Buf = Bytes>> quic::RecvStream for Prefixed<R> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if let Some(ahead) = self.ahead.take() {
            return Poll::Ready(Ok(Some(ahead)));
        }
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

type Recv = Prefixed<h3_quinn::RecvStream>;

pub(super) struct Bidi<B: Buf> {
    send: h3_quinn::SendStream<B>,
    recv: Recv,
}

impl<B: Buf> Bidi<B> {
    fn from_h3(stream: h3_quinn::BidiStream<B>) -> Self {
        let (send, recv) = quic::BidiStream::split(stream);
        Bidi {
            send,
            recv: Prefixed::new(Bytes::new(), recv),
        }
    }
}

impl<B: Buf> quic::SendStream<B> for Bidi<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::RecvStream for Bidi<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::BidiStream<B> for Bidi<B> {
    type SendStream = h3_quinn::SendStream<B>;
    type RecvStream = Recv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

/// A stream the server routed to h3: both sides, and what it read of the receiving one.
pub(super) type ForH3 = (quinn::SendStream, quinn::RecvStream, Bytes);

/// The connection h3 serves, whose bidirectional streams come from the server's routing
/// rather than from QUIC directly.
pub(super) struct Dispatched {
    conn: h3_quinn::Connection,
    routed: mpsc::Receiver<ForH3>,
}

impl Dispatched {
    pub(super) fn new(conn: quinn::Connection, routed: mpsc::Receiver<ForH3>) -> Self {
        Dispatched {
            conn: h3_quinn::Connection::new(conn),
            routed,
        }
    }
}

impl<B: Buf> quic::Connection<B> for Dispatched {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_recv(&mut self.conn, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match ready!(self.routed.poll_recv(cx)) {
            Some((send, recv, ahead)) => Poll::Ready(Ok(Bidi {
                send: h3_quinn::SendStream::new(send),
                recv: Prefixed::new(ahead, h3_quinn::RecvStream::new(recv)),
            })),
            None => Poll::Ready(Err(ConnectionErrorIncoming::ApplicationClose {
                error_code: h3::error::Code::H3_NO_ERROR.value(),
            })),
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener(quic::Connection::<B>::opener(&self.conn))
    }
}

impl<B: Buf> quic::OpenStreams<B> for Dispatched {
    type BidiStream = Bidi<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.conn, cx).map_ok(Bidi::from_h3)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.conn, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.conn, code, reason);
    }
}

pub(super) struct Opener(h3_quinn::OpenStreams);

impl Clone for Opener {
    fn clone(&self) -> Self {
        Opener(self.0.clone())
    }
}

impl<B: Buf> quic::OpenStreams<B> for Opener {
    type BidiStream = Bidi<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.0, cx).map_ok(Bidi::from_h3)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.0, code, reason);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;

    use tokio::io::{AsyncReadExt, ReadBuf};

    use super::*;
    use crate::hysteria2::wire::tcp_request;

    /// Hands out one chunk per read, as a QUIC stream does when its frames arrive apart.
    struct Chunks(VecDeque<Vec<u8>>);

    impl AsyncRead for Chunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(mut chunk) = self.0.pop_front() {
                let rest = chunk.split_off(chunk.len().min(out.remaining()));
                out.put_slice(&chunk);
                if !rest.is_empty() {
                    self.0.push_front(rest);
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    /// The route, and what it left of the stream.
    async fn routed(chunks: &[&[u8]]) -> (Route, Vec<u8>) {
        let mut recv = Chunks(chunks.iter().map(|chunk| chunk.to_vec()).collect());
        let route = route(&mut recv).await.unwrap();
        let mut rest = Vec::new();
        recv.read_to_end(&mut rest).await.unwrap();
        (route, rest)
    }

    #[tokio::test]
    async fn a_tcp_request_goes_to_the_tcp_path() {
        let request = tcp_request("example.com:443");
        let (route, rest) = routed(&[&request]).await;
        assert!(matches!(route, Route::Tcp));
        assert_eq!(rest, request.get(2..).unwrap());
    }

    /// What QUIC still holds of a stream once its first varint is read.
    struct Rest(VecDeque<Bytes>);

    impl quic::RecvStream for Rest {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
            Poll::Ready(Ok(self.0.pop_front()))
        }

        fn stop_sending(&mut self, _error_code: u64) {}

        fn recv_id(&self) -> StreamId {
            StreamId::try_from(0).unwrap()
        }
    }

    #[tokio::test]
    async fn a_headers_frame_goes_to_h3_with_what_was_read_in_front() {
        let (Route::H3(raw), rest) = routed(&[&[0x01, 0x05, 0xaa]]).await else {
            panic!("not routed to h3");
        };
        let mut recv = Prefixed::new(Bytes::from(raw), Rest(VecDeque::from([Bytes::from(rest)])));
        let mut seen = Vec::new();
        while let Some(data) = std::future::poll_fn(|cx| quic::RecvStream::poll_data(&mut recv, cx))
            .await
            .unwrap()
        {
            seen.extend_from_slice(&data);
        }
        assert_eq!(seen, [0x01, 0x05, 0xaa]);
    }

    #[tokio::test]
    async fn a_varint_split_across_reads_is_put_together() {
        assert!(matches!(routed(&[&[0x44], &[0x01, 9]]).await, (Route::Tcp, rest) if rest == [9]));
        assert!(
            matches!(routed(&[&[0x40], &[0x01]]).await, (Route::H3(raw), _) if raw == [0x40, 0x01])
        );
    }

    #[tokio::test]
    async fn a_stream_that_ends_before_its_first_varint_is_dropped() {
        assert!(matches!(routed(&[]).await, (Route::Ended, _)));
        assert!(matches!(routed(&[&[0x44]]).await, (Route::Ended, _)));
    }
}

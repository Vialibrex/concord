use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::stream_buffer::{self, BufferRequirements, OwnedDrain, StreamBuffer};
use concord_common::{Address, BoxRead, BoxWrite, Stream};
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context as SsContext, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::crypto_io::{
    CryptoRead, CryptoReadHalf, CryptoStream, CryptoWrite, CryptoWriteHalf, StreamType,
};
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientWriteHalf;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::chunk::Tail;
use crate::ctx::BuildError;

/// Method names as `sing-shadowsocks2` registers them. Methods that the Rust
/// crypto crates do not carry are refused as unsupported.
pub(crate) fn parse_method(name: &str) -> Result<CipherKind, BuildError> {
    let kind = match name {
        "none" => CipherKind::NONE,
        "aes-128-gcm" => CipherKind::AES_128_GCM,
        "aes-256-gcm" => CipherKind::AES_256_GCM,
        "aes-128-ccm" => CipherKind::AES_128_CCM,
        "aes-256-ccm" => CipherKind::AES_256_CCM,
        "aes-128-gcm-siv" => CipherKind::AES_128_GCM_SIV,
        "aes-256-gcm-siv" => CipherKind::AES_256_GCM_SIV,
        "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
        "xchacha20-ietf-poly1305" => CipherKind::XCHACHA20_POLY1305,
        "2022-blake3-aes-128-gcm" => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        "2022-blake3-aes-256-gcm" => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
        "2022-blake3-chacha20-poly1305" => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        "2022-blake3-chacha8-poly1305" => CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305,
        "aes-128-ctr" => CipherKind::AES_128_CTR,
        "aes-192-ctr" => CipherKind::AES_192_CTR,
        "aes-256-ctr" => CipherKind::AES_256_CTR,
        "aes-128-cfb" => CipherKind::AES_128_CFB128,
        "aes-192-cfb" => CipherKind::AES_192_CFB128,
        "aes-256-cfb" => CipherKind::AES_256_CFB128,
        "rc4-md5" => CipherKind::SS_RC4_MD5,
        "chacha20-ietf" => CipherKind::CHACHA20,
        other => {
            return Err(BuildError::unsupported(format!(
                "shadowsocks cipher {other} is not supported"
            )));
        }
    };
    Ok(kind)
}

pub(crate) struct SsKey {
    pub(crate) kind: CipherKind,
    pub(crate) config: ServerConfig,
}

impl SsKey {
    pub(crate) fn new(kind: CipherKind, password: &str) -> Result<Self, BuildError> {
        let config = ServerConfig::new(SocketAddr::from(([0, 0, 0, 0], 0)), password, kind)
            .map_err(|err| BuildError::invalid(format!("shadowsocks password: {err}")))?;
        Ok(SsKey { kind, config })
    }

    pub(crate) fn key(&self) -> &[u8] {
        self.config.key()
    }

    /// The iPSKs ahead of the user key, in config order.
    pub(crate) fn identity_keys(&self) -> &[bytes::Bytes] {
        self.config.identity_keys()
    }
}

pub(crate) fn new_context() -> SharedContext {
    SsContext::new_shared(ServerType::Local)
}

/// The shadowsocks stream cipher alone, without the target-address header.
pub(crate) struct CryptoIo<S> {
    inner: CryptoStream<S>,
    context: SharedContext,
    tail: Tail,
    requirements: BufferRequirements,
}

impl<S: AsyncRead + AsyncWrite + Unpin> CryptoIo<S> {
    pub(crate) fn new(stream: S, key: &SsKey, context: SharedContext) -> Self {
        let requirements = buffer_requirements(key.kind);
        CryptoIo {
            inner: CryptoStream::from_stream(
                &context,
                stream,
                StreamType::Client,
                key.kind,
                key.key(),
            ),
            context,
            tail: Tail::new(requirements.mtu),
            requirements,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CryptoIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_read_decrypted(cx, &this.context, buf)
            .map_err(Into::into)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CryptoIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.tail
            .poll_write(cx, &mut CryptoSink(&mut this.inner), data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tail.poll_flush(cx, &mut CryptoSink(&mut this.inner))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tail
            .poll_shutdown(cx, &mut CryptoSink(&mut this.inner))
    }
}

impl<S: Stream> Stream for CryptoIo<S> {
    concord_common::stream_policy!(
        own: into_split, write_requirements, peer_addr;
        default: read_requirements, poll_read_buffer, poll_write_buffer, tcp,
            needs_handshake, direct, into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        self.requirements
            .compose_writer(self.inner.get_ref().write_requirements())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.get_ref().peer_addr()
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let CryptoIo {
            inner,
            context,
            tail,
            ..
        } = *self;
        let (read, write) = inner.into_split(|stream| Box::new(stream).into_split());
        (
            Box::new(CryptoIoRead {
                inner: read,
                context,
            }),
            Box::new(CryptoIoWrite { inner: write, tail }),
        )
    }
}

struct CryptoIoRead {
    inner: CryptoReadHalf<BoxRead>,
    context: SharedContext,
}

impl AsyncRead for CryptoIoRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.inner
            .poll_read_decrypted(cx, &this.context, buf)
            .map_err(Into::into)
    }
}

struct CryptoIoWrite {
    inner: CryptoWriteHalf<BoxWrite>,
    tail: Tail,
}

impl AsyncWrite for CryptoIoWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.tail
            .poll_write(cx, &mut CryptoHalfSink(&mut this.inner), data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tail
            .poll_flush(cx, &mut CryptoHalfSink(&mut this.inner))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tail
            .poll_shutdown(cx, &mut CryptoHalfSink(&mut this.inner))
    }
}

struct CryptoHalfSink<'a>(&'a mut CryptoWriteHalf<BoxWrite>);

impl AsyncWrite for CryptoHalfSink<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_write_encrypted(cx, data).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_shutdown(cx).map_err(Into::into)
    }
}

struct CryptoSink<'a, S>(&'a mut CryptoStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CryptoSink<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0)
            .poll_write_encrypted(cx, data)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_shutdown(cx).map_err(Into::into)
    }
}

/// A shadowsocks client stream: the target address leaves with the first write.
pub(crate) struct ClientStream<S> {
    inner: ProxyClientStream<S>,
    tail: Tail,
    requirements: BufferRequirements,
    owned_write: OwnedDrain,
}

/// The `MAX_PACKET_SIZE` of the crate's AEAD and AEAD-2022 writers, which cut each write
/// to chunks of at most this much; `shadowsocks` does not export it.
fn chunk_payload(kind: CipherKind) -> usize {
    if kind.is_aead_2022() {
        0xFFFF
    } else if kind.is_aead() {
        0x3FFF
    } else {
        0
    }
}

fn buffer_requirements(kind: CipherKind) -> BufferRequirements {
    let mtu = chunk_payload(kind);
    if mtu == 0 {
        return BufferRequirements::default();
    }
    let tag = kind.tag_len();
    BufferRequirements {
        mtu,
        front: 2 + tag,
        rear: tag,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientStream<S> {
    pub(crate) fn new(stream: S, context: SharedContext, key: &SsKey, target: &Address) -> Self {
        let requirements = buffer_requirements(key.kind);
        let target = match target {
            Address::Socket(addr) => SsAddress::SocketAddress(*addr),
            Address::Domain(host, port) => SsAddress::DomainNameAddress(host.to_string(), *port),
        };
        ClientStream {
            inner: ProxyClientStream::from_stream(context, stream, &key.config, target),
            tail: Tail::new(requirements.mtu),
            requirements,
            owned_write: OwnedDrain::default(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: Stream> ClientStream<S> {
    fn poll_drain_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.get_mut();
        self.owned_write
            .poll_drain(|buffer| inner.poll_write_buffer(cx, buffer))
    }
}

impl<S: Stream> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_write(cx, &mut this.inner, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_shutdown(cx, &mut this.inner)
    }
}

impl<S: Stream> Stream for ClientStream<S> {
    concord_common::stream_policy!(
        own: into_split, write_requirements, poll_write_buffer, peer_addr;
        default: read_requirements, poll_read_buffer, tcp, needs_handshake, direct, into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        self.requirements
            .compose_writer(self.inner.get_ref().write_requirements())
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_drain_owned(cx))?;
        let length = buffer.len();
        let requirements = self.write_requirements();
        if self.inner.can_encrypt_in_place()
            && length > 0
            && length <= self.requirements.mtu
            && buffer.headroom() >= requirements.front
            && buffer.tailroom() >= requirements.rear
            && ready!(self.tail.poll_forward(cx, &mut self.inner, length))?
        {
            buffer.prepend(self.requirements.front)?;
            buffer.append(self.requirements.rear)?;
            if !self.inner.encrypt_in_place(buffer.as_mut_slice()) {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.owned_write.start(buffer);
            self.tail.record_forward(length);
            if let Poll::Ready(Err(error)) = self.poll_drain_owned(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(length));
        }
        stream_buffer::poll_write_buffer(self, cx, buffer)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.get_ref().peer_addr()
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let ClientStream {
            inner,
            tail,
            owned_write,
            ..
        } = *self;
        let (read, write) = inner.into_split(|stream| Box::new(stream).into_split());
        (
            Box::new(read),
            Box::new(ClientWrite {
                inner: write,
                tail,
                owned_write,
            }),
        )
    }
}

struct ClientWrite {
    inner: ProxyClientWriteHalf<BoxWrite>,
    tail: Tail,
    owned_write: OwnedDrain,
}

impl ClientWrite {
    fn poll_drain_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.get_mut();
        self.owned_write
            .poll_drain(|buffer| stream_buffer::poll_write_buffer(inner, cx, buffer))
    }
}

impl AsyncWrite for ClientWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_write(cx, &mut this.inner, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_owned(cx))?;
        this.tail.poll_shutdown(cx, &mut this.inner)
    }
}

#[cfg(test)]
#[path = "crypto_owned_tests.rs"]
mod owned_buffer_tests;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use shadowsocks::relay::tcprelay::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn a_2022_header_with_a_short_payload_reaches_the_server() {
        let kind = parse_method("2022-blake3-aes-128-gcm").unwrap();
        let key = SsKey::new(kind, "AAAAAAAAAAAAAAAAAAAAAA==").unwrap();
        let (near, far) = tokio::io::duplex(1 << 16);
        let target = Address::new("example.test", 443);
        let mut client = ClientStream::new(near, new_context(), &key, &target);
        let server_ctx = SsContext::new_shared(ServerType::Server);
        let mut server = ProxyServerStream::from_stream(server_ctx, far, kind, key.key());
        client.write_all(b"hi").await.unwrap();
        client.flush().await.unwrap();
        let addr = server.handshake().await.unwrap();
        assert_eq!(addr.to_string(), "example.test:443");
        let mut payload = [0u8; 2];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hi");
    }

    async fn wire_len(method: &str, password: &str, writes: &[usize]) -> usize {
        let kind = parse_method(method).unwrap();
        let key = SsKey::new(kind, password).unwrap();
        let (near, mut far) = tokio::io::duplex(1 << 22);
        let target = Address::new("example.test", 443);
        let mut client = ClientStream::new(near, new_context(), &key, &target);
        for &len in writes {
            client.write_all(&vec![7u8; len]).await.unwrap();
        }
        client.shutdown().await.unwrap();
        drop(client);
        let mut wire = Vec::new();
        far.read_to_end(&mut wire).await.unwrap();
        wire.len()
    }

    #[tokio::test]
    async fn a_buffer_that_ends_in_a_runt_costs_no_extra_chunk_on_the_wire() {
        for (method, password, chunk) in [
            ("aes-128-gcm", "secret", 0x3FFF),
            ("chacha20-ietf-poly1305", "secret", 0x3FFF),
            (
                "2022-blake3-aes-128-gcm",
                "AAAAAAAAAAAAAAAAAAAAAA==",
                0xFFFF,
            ),
        ] {
            let joined = wire_len(method, password, &[1000, 2 * chunk]).await;
            let split = wire_len(method, password, &[1000, chunk + 8, chunk - 8]).await;
            assert_eq!(split, joined, "{method}");
        }
    }

    #[tokio::test]
    async fn bulk_writes_of_odd_sizes_arrive_in_order() {
        for (method, password) in [
            ("aes-256-gcm", "secret"),
            (
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        ] {
            let kind = parse_method(method).unwrap();
            let key = SsKey::new(kind, password).unwrap();
            let (near, far) = tokio::io::duplex(1 << 16);
            let target = Address::new("example.test", 443);
            let mut client = ClientStream::new(near, new_context(), &key, &target);
            let server_ctx = SsContext::new_shared(ServerType::Server);
            let mut server = ProxyServerStream::from_stream(server_ctx, far, kind, key.key());

            let sizes = [5usize, 70_001, 3, 16_383, 40_000, 1, 0xFFFF + 7];
            let sent: Vec<u8> = (0..sizes.iter().sum::<usize>()).map(|i| i as u8).collect();
            let writer = async {
                let mut rest = sent.as_slice();
                for size in sizes {
                    let (now, later) = rest.split_at(size);
                    client.write_all(now).await.unwrap();
                    rest = later;
                }
                client.shutdown().await.unwrap();
            };
            let reader = async {
                server.handshake().await.unwrap();
                let mut got = Vec::new();
                server.read_to_end(&mut got).await.unwrap();
                got
            };
            let ((), got) = tokio::join!(writer, reader);
            assert!(got == sent, "{method}");
        }
    }

    #[tokio::test]
    async fn interactive_writes_reach_the_server_without_a_flush_or_a_full_chunk() {
        let kind = parse_method("aes-128-gcm").unwrap();
        let key = SsKey::new(kind, "secret").unwrap();
        let (near, far) = tokio::io::duplex(1 << 16);
        let target = Address::new("example.test", 443);
        let mut client = ClientStream::new(near, new_context(), &key, &target);
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            far,
            kind,
            key.key(),
        );
        for round in 0..3u8 {
            client.write_all(&[round; 20]).await.unwrap();
            let mut got = [0u8; 20];
            let arrival = async {
                if round == 0 {
                    server.handshake().await.unwrap();
                }
                server.read_exact(&mut got).await
            };
            tokio::time::timeout(Duration::from_secs(5), arrival)
                .await
                .expect("a small write waited for more data")
                .unwrap();
            assert_eq!(got, [round; 20]);
        }
    }

    #[tokio::test]
    async fn a_relay_that_runs_out_of_data_flushes_the_tail_of_a_bulk_burst() {
        struct NoMeter;
        impl concord_net::Meter for NoMeter {
            fn on_upload(&self, _: u64) {}
            fn on_download(&self, _: u64) {}
        }

        let kind = parse_method("aes-128-gcm").unwrap();
        let key = SsKey::new(kind, "secret").unwrap();
        let (near, far) = tokio::io::duplex(1 << 20);
        let target = Address::new("example.test", 443);
        let proxy: concord_common::BoxStream =
            Box::new(ClientStream::new(near, new_context(), &key, &target));
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            far,
            kind,
            key.key(),
        );
        let (source, mut app) = tokio::io::duplex(1 << 20);
        let cancel = tokio_util::sync::CancellationToken::new();
        let relaying = tokio::spawn({
            let cancel = cancel.clone();
            async move { concord_net::relay(Box::new(source), proxy, &NoMeter, &cancel).await }
        });

        let burst = 1_000_003;
        app.write_all(&vec![5u8; burst]).await.unwrap();
        let mut got = vec![0u8; burst];
        let arrival = async {
            server.handshake().await.unwrap();
            server.read_exact(&mut got).await
        };
        tokio::time::timeout(Duration::from_secs(5), arrival)
            .await
            .expect("the tail of the burst waited for more data")
            .unwrap();
        cancel.cancel();
        relaying.await.unwrap();
    }

    #[tokio::test]
    async fn a_first_write_longer_than_a_chunk_reaches_the_server_whole() {
        for (method, password) in [
            ("aes-128-gcm", "password"),
            ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ] {
            let kind = parse_method(method).unwrap();
            let key = SsKey::new(kind, password).unwrap();
            let (near, far) = tokio::io::duplex(1 << 16);
            let target = Address::new("example.test", 443);
            let mut client = ClientStream::new(near, new_context(), &key, &target);
            let server_ctx = SsContext::new_shared(ServerType::Server);
            let mut server = ProxyServerStream::from_stream(server_ctx, far, kind, key.key());
            let sent: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
            let writing = async {
                client.write_all(&sent).await.unwrap();
                client.shutdown().await.unwrap();
            };
            let reading = async {
                server.handshake().await.unwrap();
                let mut got = Vec::new();
                server.read_to_end(&mut got).await.unwrap();
                got
            };
            let ((), got) = tokio::join!(writing, reading);
            assert_eq!(got.len(), sent.len(), "{method}");
            assert!(got == sent, "{method}");
        }
    }

    async fn split_echo(method: &str, password: &str) {
        let kind = parse_method(method).unwrap();
        let key = SsKey::new(kind, password).unwrap();
        let (near, far) = tokio::io::duplex(1 << 16);
        let target = Address::new("example.test", 443);
        let client = Box::new(ClientStream::new(near, new_context(), &key, &target));
        let (mut read, mut write) = client.into_split();
        let server_ctx = SsContext::new_shared(ServerType::Server);
        let mut server = ProxyServerStream::from_stream(server_ctx, far, kind, key.key());
        let echo = tokio::spawn(async move {
            server.handshake().await.unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            server.write_all(&got).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let payload: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&sent).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        assert!(reader.await.unwrap() == payload, "{method}");
        writer.await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn a_split_aead_client_moves_data_both_ways() {
        split_echo("aes-256-gcm", "password").await;
    }

    #[tokio::test]
    async fn a_split_2022_client_checks_the_request_salt_and_moves_data_both_ways() {
        split_echo("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").await;
    }

    #[tokio::test]
    async fn a_split_stream_cipher_moves_data_both_ways() {
        let kind = parse_method("aes-256-cfb").unwrap();
        let key = SsKey::new(kind, "password").unwrap();
        let (near, far) = tokio::io::duplex(1 << 16);
        let client = Box::new(CryptoIo::new(near, &key, new_context()));
        let (mut read, mut write) = client.into_split();
        let mut server = CryptoIo::new(far, &key, new_context());
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; 5];
            server.read_exact(&mut got).await.unwrap();
            server.write_all(&got).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let writer = tokio::spawn(async move {
            write.write_all(b"hello").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
        writer.await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn the_split_write_half_still_joins_a_runt_into_a_whole_chunk() {
        async fn split_wire_len(writes: &[usize]) -> usize {
            let kind = parse_method("aes-128-gcm").unwrap();
            let key = SsKey::new(kind, "secret").unwrap();
            let (near, mut far) = tokio::io::duplex(1 << 22);
            let target = Address::new("example.test", 443);
            let client = Box::new(ClientStream::new(near, new_context(), &key, &target));
            let (read, mut write) = client.into_split();
            for &len in writes {
                write.write_all(&vec![7u8; len]).await.unwrap();
            }
            write.shutdown().await.unwrap();
            drop((read, write));
            let mut wire = Vec::new();
            far.read_to_end(&mut wire).await.unwrap();
            wire.len()
        }
        let chunk = 0x3FFF;
        let joined = split_wire_len(&[1000, 2 * chunk]).await;
        let split = split_wire_len(&[1000, chunk + 8, chunk - 8]).await;
        assert_eq!(split, joined);
    }
}

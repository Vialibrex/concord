//! mihomo's ShadowTLS server (`transport/shadowtls/server.go`, `v2.go`, `v3.go`).

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::io;
use std::net::IpAddr;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use concord_common::serve::HANDSHAKE_TIMEOUT;
use concord_common::sync::lock;
use concord_common::{BoxStream, PeekedStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::conn::{HMAC_HEADER, HMAC_SIZE, HmacSha1, new_hmac, v2_conn, v3_conn};
use super::frames::{APPLICATION_DATA, CHANGE_CIPHER_SPEC, FrameReader, HANDSHAKE, HEADER};
use super::hello::{server_name, signed_by};
use super::tap::{RANDOM_SIZE, SERVER_HELLO, SERVER_RANDOM_INDEX, kdf, server_hello_is_tls13};
use crate::http1::invalid;

/// `server.go:146-151`, `v2.go:208`.
const V2_FALLBACK_AFTER: usize = 2;
/// Go's `io.Copy` buffer: the client hashes whole writes (`v2.go:52-64`).
const V2_COPY: usize = 32 * 1024;
const V2_HASH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowTlsVersion {
    V1,
    V2,
    V3,
}

/// `wildcard-sni` (`server.go:263-273`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WildcardSni {
    #[default]
    Off,
    Authed,
    All,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandshakeTarget {
    pub server: String,
    pub proxy: Option<Arc<str>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowTlsUser {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ShadowTlsServerOptions {
    pub version: ShadowTlsVersion,
    pub password: String,
    pub users: Vec<ShadowTlsUser>,
    pub handshake: HandshakeTarget,
    pub handshake_for_server_name: HashMap<String, HandshakeTarget>,
    pub strict_mode: bool,
    pub wildcard_sni: WildcardSni,
}

/// A client past the handshake, with the v3 user it signed as.
pub struct Accepted {
    pub stream: BoxStream,
    pub user: Option<String>,
}

/// Opens a flow to a handshake server, as mihomo's `inner.HandleTcp` does.
pub type Dial<'a> = &'a (dyn Fn(&HandshakeTarget) -> io::Result<BoxStream> + Sync);

pub struct ShadowTlsServer {
    options: ShadowTlsServerOptions,
}

enum V2 {
    Hashed(Vec<u8>),
    Fallback,
}

/// `v2.go:39-80`: the hash before the last write still matches a client that read ahead.
struct WriteSums {
    mac: Option<HmacSha1>,
    previous: Option<[u8; V2_HASH]>,
    wrote: bool,
}

/// Whether a copy is in the middle of a write, where stopping would cut it.
#[derive(Default)]
struct Copying {
    stop: AtomicBool,
    writing: AtomicBool,
}

impl ShadowTlsServer {
    pub fn new(options: ShadowTlsServerOptions) -> Self {
        ShadowTlsServer { options }
    }

    /// `None` when the connection went to the handshake server. Only reading the ClientHello
    /// is bounded: past it whoever stalls is on a relay as a stranger is, and a bound would
    /// set a replayed signed hello apart.
    pub async fn accept(&self, client: TcpStream, dial: Dial<'_>) -> io::Result<Option<Accepted>> {
        match self.options.version {
            ShadowTlsVersion::V1 => self.v1(client, dial).await,
            ShadowTlsVersion::V2 => self.v2(client, dial).await,
            ShadowTlsVersion::V3 => self.v3(client, dial).await,
        }
    }

    /// `server.go:116-127`.
    async fn v1(&self, mut client: TcpStream, dial: Dial<'_>) -> io::Result<Option<Accepted>> {
        let handshake = dial(&self.options.handshake)?;
        let (mut from_handshake, mut to_handshake) = tokio::io::split(handshake);
        let (mut from_client, mut to_client) = client.split();
        tokio::try_join!(
            until_finished(&mut from_client, &mut to_handshake),
            until_finished(&mut from_handshake, &mut to_client),
        )?;
        Ok(Some(Accepted {
            stream: Box::new(client),
            user: None,
        }))
    }

    /// `server.go:129-178`.
    async fn v2(&self, mut client: TcpStream, dial: Dial<'_>) -> io::Result<Option<Accepted>> {
        let mut frames = FrameReader::new();
        let hello = read_hello(&mut frames, &mut client).await?;
        let target = server_name(&hello)
            .ok()
            .and_then(|name| self.options.handshake_for_server_name.get(&name))
            .unwrap_or(&self.options.handshake);
        let handshake = dial(target)?;
        let (mut from_handshake, mut to_handshake) = tokio::io::split(handshake);
        let sums = Mutex::new(WriteSums {
            mac: Some(new_hmac(self.options.password.as_bytes())),
            previous: None,
            wrote: false,
        });
        let copying = Copying::default();
        let (mut from_client, mut to_client) = client.split();
        let (decided, ended) = {
            let mut down = pin!(hashing_copy(
                &mut from_handshake,
                &mut to_client,
                &sums,
                &copying
            ));
            let mut ended = None;
            let decided = {
                let mut up = pin!(v2_until_hashed(
                    &mut frames,
                    &mut from_client,
                    &mut to_handshake,
                    &hello,
                    &sums
                ));
                loop {
                    tokio::select! {
                        decided = &mut up => break decided?,
                        copied = &mut down, if ended.is_none() => ended = Some(copied),
                    }
                }
            };
            if ended.is_none() {
                ended = finish_record(down.as_mut(), &copying).await;
            }
            (decided, ended)
        };
        let request = match decided {
            V2::Hashed(request) => request,
            V2::Fallback => {
                tracing::debug!("shadow-tls: no client hash, relaying");
                lock(&sums).mac = None;
                let up = async {
                    tokio::io::copy(&mut from_client, &mut to_handshake).await?;
                    to_handshake.shutdown().await
                };
                let down = async {
                    if !ended.transpose()?.unwrap_or(false) {
                        tokio::io::copy(&mut from_handshake, &mut to_client).await?;
                    }
                    to_client.shutdown().await
                };
                tokio::try_join!(up, down)?;
                return Ok(None);
            }
        };
        let stream = v2_conn(Box::new(client), None);
        Ok(Some(Accepted {
            stream: Box::new(PeekedStream::new(request, stream)),
            user: None,
        }))
    }

    /// `server.go:180-243`.
    async fn v3(&self, mut client: TcpStream, dial: Dial<'_>) -> io::Result<Option<Accepted>> {
        let mut frames = FrameReader::new();
        let hello = read_hello(&mut frames, &mut client).await?;
        let name = server_name(&hello)?;
        let user = self
            .options
            .users
            .iter()
            .find(|user| signed_by(&hello, &user.password));
        let target = self.v3_target(&name, user.is_some());
        let mut handshake = dial(&target)?;
        let Some(user) = user else {
            tracing::debug!("shadow-tls: client hello verify failed, relaying");
            handshake.write_all(&hello).await?;
            relay(client, handshake).await?;
            return Ok(None);
        };
        handshake.write_all(&hello).await?;
        let server_hello = read_frame(&mut FrameReader::new(), &mut handshake).await?;
        client.write_all(&server_hello).await?;
        let random = server_random(&server_hello);
        let tls13 = server_hello_is_tls13(&server_hello);
        let Some(random) = random.filter(|_| tls13 || !self.options.strict_mode) else {
            tracing::debug!("shadow-tls: the handshake server is not TLS 1.3, relaying");
            relay(client, handshake).await?;
            return Ok(None);
        };
        let password = user.password.as_bytes();
        let mut add = new_hmac(password);
        add.update(&random);
        add.update(b"S");
        let mut verify = new_hmac(password);
        verify.update(&random);
        verify.update(b"C");
        let mut modify = new_hmac(password);
        modify.update(&random);
        let (request, verify) = {
            let (mut from_handshake, mut to_handshake) = tokio::io::split(handshake);
            let (mut from_client, mut to_client) = client.split();
            let copying = Copying::default();
            let mut down = pin!(modifying_copy(
                &mut from_handshake,
                &mut to_client,
                kdf(password, &random),
                modify,
                &copying
            ));
            let signed = {
                let up = v3_until_signed(&mut frames, &mut from_client, &mut to_handshake, verify);
                tokio::select! {
                    signed = up => signed?,
                    ended = &mut down => {
                        let stopped = || invalid("shadow-tls: handshake server stopped");
                        return Err(ended.err().unwrap_or_else(stopped));
                    }
                }
            };
            finish_record(down.as_mut(), &copying).await;
            signed
        };
        let stream = v3_conn(Box::new(client), add, verify, None);
        Ok(Some(Accepted {
            stream: Box::new(PeekedStream::new(request, stream)),
            user: Some(user.name.clone()).filter(|name| !name.is_empty()),
        }))
    }

    /// An IP literal, which RFC 6066 §3 keeps out of a server name, takes no wildcard.
    fn v3_target(&self, name: &str, authenticated: bool) -> HandshakeTarget {
        if let Some(target) = self.options.handshake_for_server_name.get(name) {
            return target.clone();
        }
        let mut target = self.options.handshake.clone();
        let wildcard = self.options.wildcard_sni;
        let literal = name
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok();
        if !literal
            && (wildcard == WildcardSni::All || (authenticated && wildcard == WildcardSni::Authed))
        {
            target.server = if name.contains(':') {
                format!("[{name}]:443")
            } else {
                format!("{name}:443")
            };
        }
        target
    }
}

async fn read_hello(frames: &mut FrameReader, client: &mut TcpStream) -> io::Result<Vec<u8>> {
    timeout(HANDSHAKE_TIMEOUT, read_frame(frames, client))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    frames: &mut FrameReader,
    from: &mut R,
) -> io::Result<Vec<u8>> {
    poll_fn(|cx| frames.poll_frame(from, cx))
        .await?
        .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

fn server_random(frame: &[u8]) -> Option<[u8; RANDOM_SIZE]> {
    if frame.first() != Some(&HANDSHAKE) || frame.get(HEADER) != Some(&SERVER_HELLO) {
        return None;
    }
    frame
        .get(SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + RANDOM_SIZE)?
        .try_into()
        .ok()
}

/// Lets a copy finish the write it is in; one waiting to read stops where it is.
async fn finish_record<T>(copy: Pin<&mut impl Future<Output = T>>, copying: &Copying) -> Option<T> {
    copying.stop.store(true, Ordering::Release);
    if copying.writing.load(Ordering::Acquire) {
        return Some(copy.await);
    }
    None
}

/// `protocol.go:48-70`: records on until this side's Finished, the one after its CCS.
async fn until_finished<R, W>(from: &mut R, to: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frames = FrameReader::new();
    let mut changed = false;
    loop {
        let frame = read_frame(&mut frames, from).await?;
        to.write_all(&frame).await?;
        match frame.first().copied() {
            Some(HANDSHAKE) => {}
            Some(CHANGE_CIPHER_SPEC) if !changed => {
                changed = true;
                continue;
            }
            Some(CHANGE_CIPHER_SPEC) => {}
            other => {
                return Err(invalid(format!(
                    "shadow-tls: unexpected TLS record type: {}",
                    other.unwrap_or_default()
                )));
            }
        }
        if changed {
            return Ok(());
        }
    }
}

/// `v2.go:181-212`.
async fn v2_until_hashed<R, W>(
    frames: &mut FrameReader,
    from: &mut R,
    to: &mut W,
    hello: &[u8],
    sums: &Mutex<WriteSums>,
) -> io::Result<V2>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    to.write_all(hello).await?;
    let mut unhashed = 0;
    loop {
        let frame = read_frame(frames, from).await?;
        if frame.first() == Some(&APPLICATION_DATA) {
            let payload = frame.get(HEADER..).unwrap_or_default();
            if let Some((hash, request)) = payload.split_at_checked(V2_HASH)
                && lock(sums).matches(hash)
            {
                return Ok(V2::Hashed(request.to_vec()));
            }
            unhashed += 1;
        }
        to.write_all(&frame).await?;
        if unhashed > V2_FALLBACK_AFTER {
            return Ok(V2::Fallback);
        }
    }
}

impl WriteSums {
    fn wrote(&mut self, data: &[u8]) {
        let Some(mac) = self.mac.as_mut() else {
            return;
        };
        if self.wrote {
            self.previous = hash_of(mac);
        }
        mac.update(data);
        self.wrote = true;
    }

    fn matches(&self, hash: &[u8]) -> bool {
        let Some(mac) = self.mac.as_ref().filter(|_| self.wrote) else {
            return false;
        };
        let same = |sum: &[u8; V2_HASH]| verify_slices_are_equal(sum, hash).is_ok();
        hash_of(mac).is_some_and(|sum| same(&sum)) || self.previous.as_ref().is_some_and(same)
    }
}

fn hash_of(mac: &HmacSha1) -> Option<[u8; V2_HASH]> {
    mac.sum().get(..V2_HASH)?.try_into().ok()
}

/// Hashes what the handshake server writes, write by write; true when it ended.
async fn hashing_copy<R, W>(
    from: &mut R,
    to: &mut W,
    sums: &Mutex<WriteSums>,
    copying: &Copying,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; V2_COPY];
    loop {
        let read = from.read(&mut buf).await?;
        let Some(chunk) = buf.get(..read).filter(|chunk| !chunk.is_empty()) else {
            return Ok(true);
        };
        copying.writing.store(true, Ordering::Release);
        lock(sums).wrote(chunk);
        to.write_all(chunk).await?;
        copying.writing.store(false, Ordering::Release);
        if copying.stop.load(Ordering::Acquire) {
            return Ok(false);
        }
    }
}

/// `v3.go:281-303`.
async fn v3_until_signed<R, W>(
    frames: &mut FrameReader,
    from: &mut R,
    to: &mut W,
    verify: HmacSha1,
) -> io::Result<(Vec<u8>, HmacSha1)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let frame = read_frame(frames, from).await?;
        if frame.first() == Some(&APPLICATION_DATA)
            && let (Some(tag), Some(payload)) =
                (frame.get(HEADER..HMAC_HEADER), frame.get(HMAC_HEADER..))
            && !payload.is_empty()
        {
            let mut mac = verify.clone();
            mac.update(payload);
            let sum = mac.sum();
            if sum
                .get(..HMAC_SIZE)
                .is_some_and(|expected| verify_slices_are_equal(expected, tag).is_ok())
            {
                mac.update(tag);
                return Ok((payload.to_vec(), mac));
            }
        }
        to.write_all(&frame).await?;
    }
}

/// `v3.go:305-326`.
async fn modifying_copy<R, W>(
    from: &mut R,
    to: &mut W,
    key: [u8; 32],
    mut mac: HmacSha1,
    copying: &Copying,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frames = FrameReader::new();
    loop {
        let mut frame = read_frame(&mut frames, from).await?;
        copying.writing.store(true, Ordering::Release);
        if frame.first() == Some(&APPLICATION_DATA) {
            let payload = frame.get_mut(HEADER..).unwrap_or_default();
            for (byte, key) in payload.iter_mut().zip(key.iter().cycle()) {
                *byte ^= key;
            }
            mac.update(payload);
            let length = u16::try_from(payload.len() + HMAC_SIZE)
                .map_err(|_| invalid("shadow-tls: record too large"))?;
            let sum = mac.sum();
            let mut out = Vec::with_capacity(frame.len() + HMAC_SIZE);
            out.extend_from_slice(frame.get(..3).unwrap_or_default());
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(sum.get(..HMAC_SIZE).unwrap_or_default());
            out.extend_from_slice(frame.get(HEADER..).unwrap_or_default());
            to.write_all(&out).await?;
        } else {
            to.write_all(&frame).await?;
        }
        copying.writing.store(false, Ordering::Release);
        if copying.stop.load(Ordering::Acquire) {
            return Ok(());
        }
    }
}

/// mihomo's `N.RelayContext`.
async fn relay(mut client: TcpStream, mut handshake: BoxStream) -> io::Result<()> {
    tokio::io::copy_bidirectional(&mut client, &mut handshake).await?;
    Ok(())
}

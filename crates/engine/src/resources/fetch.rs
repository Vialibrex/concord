use std::io::{Seek as _, Write as _};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use concord_common::{CoreError, CoreOptions};
use concord_group::http::{HttpError, Streaming, Target, TlsSettings, connect};
use concord_group::{FetchError, FetchErrorKind, FetchHead, FetchRequest, FetchResponse, Fetcher};
use concord_platform::HomeDir;
use concord_platform::mmap::MappedFile;
use concord_tls::TrustStore;
use concord_tunnel::Tunnel;
use flate2::write::MultiGzDecoder;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::error::ResourceError;

const MAX_REDIRECTS: usize = 10;
const FAILED_BODY_NOTE: usize = 4 << 10;

/// Everything the core downloads goes through the tunnel as an inner flow, so a
/// provider can name the proxy it is fetched through.
pub(crate) struct TunnelFetcher {
    pub tunnel: Tunnel,
    pub options: Arc<ArcSwap<CoreOptions>>,
    /// The config in force's.
    pub identity: ArcSwap<Identity>,
}

/// What a download presents: a config's `global-ua` and the trust its custom certificates make.
pub(crate) struct Identity {
    pub user_agent: String,
    pub trust: Arc<TrustStore>,
}

/// Downloads as one identity rather than the config in force's: those a config makes while it
/// builds, before it is in force.
pub(crate) struct FetchAs<'a> {
    fetcher: &'a TunnelFetcher,
    identity: &'a Identity,
}

fn fetch_error(kind: FetchErrorKind, message: impl Into<String>) -> FetchError {
    FetchError {
        kind,
        message: message.into(),
    }
}

fn dial_error(err: &std::io::Error) -> FetchError {
    let kind = match (CoreError::of(err), err.kind()) {
        (Some(CoreError::IpNotFound(_)), _) => FetchErrorKind::Dns,
        (_, std::io::ErrorKind::TimedOut) => FetchErrorKind::Timeout,
        _ => FetchErrorKind::Connection,
    };
    fetch_error(kind, err.to_string())
}

fn http_error(err: HttpError) -> FetchError {
    let kind = match &err {
        HttpError::Tls(_) => FetchErrorKind::Tls,
        HttpError::Protocol(_) => FetchErrorKind::Connection,
        HttpError::Url(_) => FetchErrorKind::Other,
    };
    fetch_error(kind, err.to_string())
}

impl TunnelFetcher {
    pub(crate) fn fetch_as<'a>(&'a self, identity: &'a Identity) -> FetchAs<'a> {
        FetchAs {
            fetcher: self,
            identity,
        }
    }
}

impl FetchAs<'_> {
    /// Follows redirects to the response that is not one, under the request's deadline,
    /// and reads its body through `take`. A final status outside 2xx is logged with the hops
    /// before it and the start of its body, since the caller's error carries only the status.
    async fn fetch<T>(
        &self,
        request: &FetchRequest,
        take: impl AsyncFnOnce(&mut Body<'_>) -> Result<T, FetchError>,
    ) -> Result<(FetchHead, T), FetchError> {
        let deadline = Instant::now() + request.timeout;
        let mut url = request.url.clone();
        let (headers, gzip) = request_headers(&request.headers, &self.identity.user_agent);
        let limit = request
            .size_limit
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(usize::MAX);
        let tls = TlsSettings {
            trust: self.identity.trust.clone(),
            skip_cert_verify: self.fetcher.options.load().skip_cert_verify,
        };
        let mut hops = Vec::new();
        let exchange = async {
            for _ in 0..MAX_REDIRECTS {
                let target = Target::parse(&url).map_err(http_error)?;
                let stream = self
                    .fetcher
                    .tunnel
                    .dial_inner(&target.address(), request.via_proxy.as_deref())
                    .await
                    .map_err(|err| dial_error(&err))?;
                let mut connection = connect(stream, &target, &tls, self.fetcher.tunnel.tasks())
                    .await
                    .map_err(http_error)?;
                let mut response = connection
                    .open(http::Method::GET, &headers, Bytes::new(), limit)
                    .await
                    .map_err(http_error)?;
                hops.push(format!("{} {}", response.status, target.host));
                if response.status / 100 == 3
                    && let Some(location) = response
                        .headers
                        .get(http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                {
                    url = url::Url::parse(&url)
                        .and_then(|base| base.join(location))
                        .map_err(|err| fetch_error(FetchErrorKind::Other, err.to_string()))?
                        .to_string();
                    continue;
                }
                let gunzip = gzip
                    && response
                        .headers
                        .get(http::header::CONTENT_ENCODING)
                        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
                let head = FetchHead {
                    status: response.status,
                    headers: response
                        .headers
                        .iter()
                        .filter(|(name, _)| {
                            !gunzip
                                || (*name != http::header::CONTENT_ENCODING
                                    && *name != http::header::CONTENT_LENGTH)
                        })
                        .filter_map(|(name, value)| {
                            Some((name.to_string(), value.to_str().ok()?.to_string()))
                        })
                        .collect(),
                };
                let failed = !(200..=299).contains(&head.status);
                let mut body = Body::new(&mut response, gunzip, limit, failed);
                let taken = take(&mut body).await?;
                if let Some(start) = &body.start {
                    tracing::warn!("{}", failure_note(&hops, start));
                }
                drop(connection);
                return Ok((head, taken));
            }
            tracing::warn!("fetch redirected {}", hops.join(" -> "));
            Err(fetch_error(
                FetchErrorKind::Other,
                format!("stopped after {MAX_REDIRECTS} redirects"),
            ))
        };
        tokio::time::timeout_at(deadline, exchange)
            .await
            .map_err(|_| fetch_error(FetchErrorKind::Timeout, "context deadline exceeded"))?
    }
}

/// The request's own headers, with what Go's `Transport` and curl send when it names none:
/// the config's User-Agent, `Accept: */*`, and `Accept-Encoding: gzip`, which also says whether
/// the body is the fetch's to decompress. As in Go, a request that asks for an encoding itself
/// reads the body as sent.
fn request_headers(own: &[(String, String)], user_agent: &str) -> (Vec<(String, String)>, bool) {
    let named = |name: &str| own.iter().any(|(key, _)| key.eq_ignore_ascii_case(name));
    let mut headers = own.to_vec();
    if !named("user-agent") {
        headers.push(("User-Agent".to_string(), user_agent.to_string()));
    }
    if !named("accept") {
        headers.push(("Accept".to_string(), "*/*".to_string()));
    }
    let gzip = !named("accept-encoding") && !named("range");
    if gzip {
        headers.push(("Accept-Encoding".to_string(), "gzip".to_string()));
    }
    (headers, gzip)
}

/// A body as the caller reads it: gunzipped when the fetch asked for gzip and got it, held to
/// the request's size limit after decoding, with the start of a failed answer kept for the log.
pub(crate) struct Body<'a> {
    response: &'a mut Streaming,
    gunzip: Option<MultiGzDecoder<Vec<u8>>>,
    limit: usize,
    read: usize,
    start: Option<Vec<u8>>,
}

impl<'a> Body<'a> {
    fn new(response: &'a mut Streaming, gunzip: bool, limit: usize, failed: bool) -> Self {
        Body {
            response,
            gunzip: gunzip.then(|| MultiGzDecoder::new(Vec::new())),
            limit,
            read: 0,
            start: failed.then(Vec::new),
        }
    }

    /// The next piece of the body, `None` past its end.
    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, FetchError> {
        let corrupt = |err: std::io::Error| fetch_error(FetchErrorKind::Other, err.to_string());
        loop {
            let piece = match (
                self.response.chunk().await.map_err(http_error)?,
                &mut self.gunzip,
            ) {
                (Some(piece), None) => piece,
                (Some(piece), Some(decoder)) => {
                    decoder.write_all(&piece).map_err(corrupt)?;
                    Bytes::from(std::mem::take(decoder.get_mut()))
                }
                (None, _) => match self.gunzip.take() {
                    Some(decoder) => Bytes::from(decoder.finish().map_err(corrupt)?),
                    None => return Ok(None),
                },
            };
            if piece.is_empty() {
                continue;
            }
            self.read = self.read.saturating_add(piece.len());
            if self.read > self.limit {
                return Err(fetch_error(FetchErrorKind::Other, "length limit exceeded"));
            }
            if let Some(start) = &mut self.start {
                let room = FAILED_BODY_NOTE
                    .saturating_sub(start.len())
                    .min(piece.len());
                start.extend_from_slice(piece.get(..room).unwrap_or_default());
            }
            return Ok(Some(piece));
        }
    }
}

/// The hops of a download that ended outside 2xx and the start of its body, on one line:
/// control characters and runs of white space become one space.
fn failure_note(hops: &[String], body: &[u8]) -> String {
    let body = String::from_utf8_lossy(body)
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    format!("fetch answered {}; body: {body}", hops.join(" -> "))
}

#[async_trait]
impl Fetcher for TunnelFetcher {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.fetch_as(&self.identity.load_full()).get(request).await
    }

    async fn get_into(
        &self,
        request: FetchRequest,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<FetchHead, FetchError> {
        self.fetch_as(&self.identity.load_full())
            .get_into(request, sink)
            .await
    }
}

#[async_trait]
impl Fetcher for FetchAs<'_> {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let (head, body) = self
            .fetch(&request, async |response: &mut Body<'_>| {
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            })
            .await?;
        Ok(FetchResponse {
            status: head.status,
            headers: head.headers,
            body,
        })
    }

    async fn get_into(
        &self,
        request: FetchRequest,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<FetchHead, FetchError> {
        let (head, ()) = self
            .fetch(&request, async |response: &mut Body<'_>| {
                let written =
                    |err: std::io::Error| fetch_error(FetchErrorKind::Other, err.to_string());
                while let Some(chunk) = response.chunk().await? {
                    sink.write_all(&chunk).await.map_err(written)?;
                }
                sink.flush().await.map_err(written)
            })
            .await?;
        Ok(head)
    }
}

/// A plain GET that treats anything but 2xx as a failure, as `HTTPVehicle.Read` does.
pub(crate) async fn download(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
) -> Result<Vec<u8>, ResourceError> {
    let response = fetcher.get(request).await.map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&response.status) {
        return Err(ResourceError::Status(response.status));
    }
    Ok(response.body)
}

/// A body written to an unnamed file as it arrived, with its SHA-256, so that a large one is
/// never held whole.
pub(crate) struct Spilled {
    file: std::fs::File,
    pub(crate) digest: [u8; 32],
}

impl Spilled {
    /// The body, mapped where the platform allows rather than read onto the heap.
    pub(crate) fn bytes(&self) -> std::io::Result<MappedFile> {
        MappedFile::from_file(&self.file)
    }

    /// Copies the body to `path` as [HomeDir::write_atomic] writes a file.
    pub(crate) fn store(mut self, home: &HomeDir, path: impl AsRef<Path>) -> std::io::Result<()> {
        home.write_atomic_with(path, |out| std::io::copy(&mut self.file, out).map(drop))
    }
}

struct Hashing {
    file: tokio::fs::File,
    hasher: Sha256,
}

impl AsyncWrite for Hashing {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let written = ready!(Pin::new(&mut this.file).poll_write(cx, buf))?;
        this.hasher.update(buf.get(..written).unwrap_or_default());
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_shutdown(cx)
    }
}

/// As [download], into an unnamed file in `dir` rather than memory.
/// The SHA-256 of the file at `path`, read in pieces; none when it cannot be read.
pub(crate) fn file_digest(path: &Path) -> Option<[u8; 32]> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut piece = vec![0; 32 << 10];
    loop {
        match file.read(&mut piece) {
            Ok(0) => return Some(hasher.finalize().into()),
            Ok(read) => hasher.update(piece.get(..read)?),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

pub(crate) async fn download_spilled(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
    dir: &Path,
) -> Result<Spilled, ResourceError> {
    let local = |err: std::io::Error| ResourceError::Other(err.to_string());
    let file = tempfile::tempfile_in(dir).map_err(local)?;
    let mut sink = Hashing {
        file: tokio::fs::File::from_std(file),
        hasher: Sha256::new(),
    };
    let head = fetcher
        .get_into(request, &mut sink)
        .await
        .map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&head.status) {
        return Err(ResourceError::Status(head.status));
    }
    sink.flush().await.map_err(local)?;
    let mut file = sink.file.into_std().await;
    file.rewind().map_err(local)?;
    Ok(Spilled {
        file,
        digest: sink.hasher.finalize().into(),
    })
}

pub(super) fn touch(path: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(SystemTime::now()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_note_names_each_hop_and_the_start_of_the_body_on_one_line() {
        let hops = ["302 a.test".to_string(), "403 b.test".to_string()];
        let note = failure_note(&hops, b"<html>\r\n\t<b>no\x07</b>  \x00x</html>");
        assert_eq!(
            note,
            "fetch answered 302 a.test -> 403 b.test; body: <html> <b>no </b> x</html>"
        );
    }
}

use std::collections::VecDeque;
use std::io::{self, BufRead, Read};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};

use crate::rules::LOCAL_PIECE;

pub(crate) type Body = UnsyncBoxBody<Bytes, io::Error>;

/// The file at `path` read in [LOCAL_PIECE] pieces as it is sent, and its length.
pub(crate) async fn file_body(path: &std::path::Path) -> io::Result<(Body, u64)> {
    use futures_util::TryStreamExt;

    let meta = tokio::fs::symlink_metadata(path).await?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a regular file",
        ));
    }
    let file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    let pieces = tokio_util::io::ReaderStream::with_capacity(file, LOCAL_PIECE).map_ok(Frame::data);
    Ok((http_body_util::StreamBody::new(pieces).boxed_unsync(), len))
}

pub(crate) fn empty() -> Body {
    full(Bytes::new())
}

pub(crate) fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// `data` read whole, then the trailers that followed it.
pub(crate) fn full_with(data: impl Into<Bytes>, trailers: Option<HeaderMap>) -> Body {
    match trailers {
        None => full(data),
        Some(trailers) => WithTrailers {
            data: Some(data.into()),
            trailers: Some(trailers),
        }
        .boxed_unsync(),
    }
}

struct WithTrailers {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl HttpBody for WithTrailers {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if let Some(data) = self.data.take()
            && !data.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(Bytes::is_empty) && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len() as u64))
    }
}

pub(crate) fn from_incoming(body: Incoming) -> Body {
    body.map_err(io::Error::other).boxed_unsync()
}

struct ChunkQueue {
    buf: VecDeque<u8>,
    eof: bool,
}

impl ChunkQueue {
    fn new() -> Self {
        ChunkQueue {
            buf: VecDeque::new(),
            eof: false,
        }
    }
}

impl Read for ChunkQueue {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.buf.is_empty() {
            return if self.eof {
                Ok(0)
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            };
        }
        self.buf.read(out)
    }
}

impl BufRead for ChunkQueue {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let (front, _) = self.buf.as_slices();
        if front.is_empty() && !self.eof {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        Ok(front)
    }

    fn consume(&mut self, amt: usize) {
        drop(self.buf.drain(..amt));
    }
}

enum Decoder {
    Gzip(flate2::bufread::MultiGzDecoder<ChunkQueue>),
    Zlib(flate2::bufread::ZlibDecoder<ChunkQueue>),
}

impl Decoder {
    fn for_coding(coding: &str) -> Option<Decoder> {
        match coding {
            "gzip" | "x-gzip" => Some(Decoder::Gzip(flate2::bufread::MultiGzDecoder::new(
                ChunkQueue::new(),
            ))),
            "deflate" => Some(Decoder::Zlib(flate2::bufread::ZlibDecoder::new(
                ChunkQueue::new(),
            ))),
            _ => None,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        match self {
            Decoder::Gzip(decoder) => decoder.get_mut().buf.extend(chunk),
            Decoder::Zlib(decoder) => decoder.get_mut().buf.extend(chunk),
        }
    }

    fn mark_eof(&mut self) {
        match self {
            Decoder::Gzip(decoder) => decoder.get_mut().eof = true,
            Decoder::Zlib(decoder) => decoder.get_mut().eof = true,
        }
    }

    fn pull_into(&mut self, out: &mut Vec<u8>, max_total: usize) -> io::Result<usize> {
        let mut scratch = [0u8; 8192];
        let mut added = 0usize;
        while out.len() < max_total {
            let want = (max_total - out.len()).min(scratch.len());
            let res = match self {
                Decoder::Gzip(decoder) => decoder.read(&mut scratch[..want]),
                Decoder::Zlib(decoder) => decoder.read(&mut scratch[..want]),
            };
            match res {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&scratch[..n]);
                    added += n;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        Ok(added)
    }
}

/// A body whose first bytes were already read, followed by the rest of it,
/// decoded as it goes when a decoder is set.
struct Resumed {
    head: Option<Bytes>,
    body: Body,
    decoder: Option<Decoder>,
    trailers: Option<HeaderMap>,
    done: bool,
}

impl HttpBody for Resumed {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if let Some(head) = self.head.take()
            && !head.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        loop {
            if let Some(decoder) = self.decoder.as_mut() {
                let mut piece = Vec::new();
                match decoder.pull_into(&mut piece, LOCAL_PIECE) {
                    Ok(n) if n > 0 => {
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(piece)))));
                    }
                    Ok(_) => {}
                    Err(err) => {
                        self.done = true;
                        return Poll::Ready(Some(Err(err)));
                    }
                }
            }
            if self.done {
                return Poll::Ready(
                    self.trailers
                        .take()
                        .map(|trailers| Ok(Frame::trailers(trailers))),
                );
            }
            match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => match self.decoder.as_mut() {
                        None => return Poll::Ready(Some(Ok(Frame::data(data)))),
                        Some(decoder) => decoder.feed(&data),
                    },
                    Err(frame) => {
                        if let Ok(more) = frame.into_trailers() {
                            self.trailers.get_or_insert_default().extend(more);
                        }
                        if let Some(decoder) = self.decoder.as_mut() {
                            decoder.mark_eof();
                        }
                    }
                },
                Some(Err(err)) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(err)));
                }
                None => {
                    self.done = true;
                    if let Some(decoder) = self.decoder.as_mut() {
                        decoder.mark_eof();
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

pub(crate) enum Buffered {
    /// The data, and the trailers that followed it.
    Whole(Bytes, Option<HeaderMap>),
    /// Larger than the limit or in an encoding with no decoder: to send on as it
    /// came, already decoded if decoding had begun.
    Rest { body: Body, length: Option<u64> },
}

/// Reads a body whole and decoded. A gzip or deflate coding is removed from
/// `header`, and the length it left is unknown.
pub(crate) async fn buffer_body(
    header: &mut HeaderMap,
    body: Body,
    length: Option<u64>,
    limit: i64,
) -> io::Result<Buffered> {
    let cap = usize::try_from(limit).unwrap_or(0);
    if length.is_some_and(|length| length > cap as u64) {
        return Ok(Buffered::Rest { body, length });
    }
    let encoding = header
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mut decoder = None;
    let mut length = length;
    match encoding.as_str() {
        "" | "identity" => {}
        coding => match Decoder::for_coding(coding) {
            Some(found) => {
                decoder = Some(found);
                header.remove(http::header::CONTENT_ENCODING);
                length = None;
            }
            None => return Ok(Buffered::Rest { body, length }),
        },
    }
    let mut body = body;
    let mut out: Vec<u8> = Vec::new();
    let mut trailers: Option<HeaderMap> = None;
    while let Some(frame) = body.frame().await {
        let data = match frame?.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if let Ok(more) = frame.into_trailers() {
                    trailers.get_or_insert_default().extend(more);
                }
                continue;
            }
        };
        let max_total = cap.saturating_add(1);
        match decoder.as_mut() {
            Some(active) => {
                active.feed(&data);
                active.pull_into(&mut out, max_total)?;
            }
            None => out.extend_from_slice(&data),
        }
        if out.len() > cap {
            let rest = Resumed {
                head: Some(Bytes::from(out)),
                body,
                decoder,
                trailers,
                done: false,
            };
            return Ok(Buffered::Rest {
                body: rest.boxed_unsync(),
                length,
            });
        }
    }
    if let Some(mut active) = decoder {
        active.mark_eof();
        let max_total = cap.saturating_add(1);
        active.pull_into(&mut out, max_total)?;
        if out.len() > cap {
            let rest = Resumed {
                head: Some(Bytes::from(out)),
                body: empty(),
                decoder: Some(active),
                trailers,
                done: true,
            };
            return Ok(Buffered::Rest {
                body: rest.boxed_unsync(),
                length: None,
            });
        }
    }
    Ok(Buffered::Whole(Bytes::from(out), trailers))
}

pub(crate) type DataHook = Box<dyn FnMut(&Bytes) + Send>;
pub(crate) type EndHook = Box<dyn FnOnce() + Send>;

/// Watches the data of a body as it passes, and tells once when it ends, however it ends.
pub(crate) struct Tap {
    inner: Body,
    on_data: Option<DataHook>,
    on_end: Option<EndHook>,
}

impl Tap {
    pub fn new(inner: Body, on_data: Option<DataHook>, on_end: Option<EndHook>) -> Tap {
        Tap {
            inner,
            on_data,
            on_end,
        }
    }

    fn end(&mut self) {
        if let Some(on_end) = self.on_end.take() {
            on_end();
        }
    }
}

impl HttpBody for Tap {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let polled = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        match &polled {
            Some(Ok(frame)) => {
                if let (Some(data), Some(hook)) = (frame.data_ref(), self.on_data.as_mut()) {
                    hook(data);
                }
            }
            _ => self.end(),
        }
        Poll::Ready(polled)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.end();
    }
}

/// A body that fails with `error` when first read.
pub(crate) fn failing(error: io::Error) -> Body {
    let stream = futures_util::stream::once(async move { Err::<Frame<Bytes>, io::Error>(error) });
    http_body_util::StreamBody::new(stream).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use futures_util::StreamExt;

    use super::*;

    fn gzip(text: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text).unwrap();
        encoder.finish().unwrap()
    }

    fn deflate(text: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text).unwrap();
        encoder.finish().unwrap()
    }

    fn header(encoding: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        if !encoding.is_empty() {
            map.insert(http::header::CONTENT_ENCODING, encoding.parse().unwrap());
        }
        map
    }

    async fn drain(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn a_plain_body_is_read_whole() {
        let mut map = header("");
        let got = buffer_body(&mut map, full("hello"), Some(5), 100)
            .await
            .unwrap();
        assert!(matches!(got, Buffered::Whole(data, None) if data.as_ref() == b"hello"));
    }

    #[tokio::test]
    async fn the_trailers_after_a_body_read_whole_are_kept_and_sent_on() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let mut map = header("");
        let got = buffer_body(
            &mut map,
            full_with("hello", Some(trailers.clone())),
            None,
            100,
        )
        .await
        .unwrap();
        let Buffered::Whole(data, Some(kept)) = got else {
            panic!("no trailers");
        };
        assert_eq!((data.as_ref(), &kept), (&b"hello"[..], &trailers));
        let sent = full_with(data, Some(kept)).collect().await.unwrap();
        assert_eq!(sent.trailers(), Some(&trailers));
        assert_eq!(sent.to_bytes(), "hello");
    }

    #[tokio::test]
    async fn a_gzip_body_is_decoded_and_loses_its_coding() {
        let mut map = header("gzip");
        let got = buffer_body(&mut map, full(gzip(b"hello ad")), None, 100)
            .await
            .unwrap();
        assert!(matches!(got, Buffered::Whole(data, None) if data.as_ref() == b"hello ad"));
        assert!(map.get(http::header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn a_body_over_its_declared_length_passes_on_as_it_came() {
        let mut map = header("gzip");
        let got = buffer_body(&mut map, full("0123456789"), Some(10), 5)
            .await
            .unwrap();
        match got {
            Buffered::Rest { body, length } => {
                assert_eq!(length, Some(10));
                assert_eq!(drain(body).await, b"0123456789");
            }
            Buffered::Whole(..) => panic!("buffered"),
        }
        assert!(map.get(http::header::CONTENT_ENCODING).is_some());
    }

    #[tokio::test]
    async fn an_unknown_coding_passes_on_untouched() {
        let mut map = header("br");
        let got = buffer_body(&mut map, full("raw"), None, 100).await.unwrap();
        assert!(matches!(got, Buffered::Rest { length: None, .. }));
        assert!(map.get(http::header::CONTENT_ENCODING).is_some());
    }

    #[tokio::test]
    async fn a_decoded_body_over_the_limit_continues_decoded() {
        let text = b"0123456789".repeat(1000);
        let mut map = header("gzip");
        let got = buffer_body(&mut map, full(gzip(&text)), None, 100)
            .await
            .unwrap();
        match got {
            Buffered::Rest { body, length } => {
                assert_eq!(length, None);
                assert_eq!(drain(body).await, text);
            }
            Buffered::Whole(..) => panic!("buffered"),
        }
    }

    #[tokio::test]
    async fn a_corrupt_gzip_body_is_an_error() {
        let mut map = header("gzip");
        assert!(
            buffer_body(&mut map, full("not gzip at all, really"), None, 100)
                .await
                .is_err()
        );
    }

    /// Buffers a deflate body that ends in trailers past `cap`; returns whether the
    /// trailers were read before `buffer_body` returned, the data it then yields, and
    /// its trailers, which must come last.
    async fn fallback_with_trailers(text: &[u8], cap: i64) -> (bool, Vec<u8>, HeaderMap) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut trailers = HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("kept"));
        let frames = [
            Frame::data(Bytes::from(deflate(text))),
            Frame::trailers(trailers),
        ];
        let read = Arc::new(AtomicBool::new(false));
        let flag = read.clone();
        let stream = futures_util::stream::iter(frames).map(move |frame| {
            flag.fetch_or(frame.is_trailers(), Ordering::SeqCst);
            Ok::<_, io::Error>(frame)
        });
        let body = http_body_util::StreamBody::new(stream).boxed_unsync();
        let Buffered::Rest { mut body, .. } = buffer_body(&mut header("deflate"), body, None, cap)
            .await
            .unwrap()
        else {
            panic!("expected a fallback");
        };
        let read_early = read.load(Ordering::SeqCst);
        let mut decoded = Vec::new();
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            match frame.unwrap().into_data() {
                Ok(data) => {
                    assert!(trailers.is_none(), "data after the trailers");
                    decoded.extend_from_slice(&data);
                }
                Err(frame) => trailers = frame.into_trailers().ok(),
            }
        }
        (read_early, decoded, trailers.expect("no trailers"))
    }

    #[tokio::test]
    async fn streaming_fallback_sends_trailers_after_the_decoded_data() {
        let text = b"0123456789".repeat(6000);
        let (read_early, decoded, trailers) = fallback_with_trailers(&text, 100).await;
        assert!(!read_early);
        assert_eq!(decoded, text);
        assert_eq!(trailers["x-trailer"], "kept");
    }

    #[tokio::test]
    async fn eof_fallback_keeps_the_collected_trailers() {
        let text = b"abcdefghij".repeat(2000);
        let (read_early, decoded, trailers) = fallback_with_trailers(&text, 8192).await;
        assert!(read_early);
        assert_eq!(decoded, text);
        assert_eq!(trailers["x-trailer"], "kept");
    }

    #[tokio::test]
    async fn the_tap_reports_data_and_its_end_once() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let seen = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let (s, e) = (seen.clone(), ended.clone());
        let tap = Tap::new(
            full("abcd"),
            Some(Box::new(move |data| {
                s.fetch_add(data.len(), Ordering::SeqCst);
            })),
            Some(Box::new(move || {
                e.fetch_add(1, Ordering::SeqCst);
            })),
        );
        assert_eq!(drain(tap.boxed_unsync()).await, b"abcd");
        assert_eq!(
            (seen.load(Ordering::SeqCst), ended.load(Ordering::SeqCst)),
            (4, 1)
        );
    }
}

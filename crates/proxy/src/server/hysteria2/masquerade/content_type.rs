//! The `Content-Type` Go's `serveContent` gives a file (`fs.go:272-292`): its extension in
//! the standard library's built-in table, Go 1.27.3's (`mime/type.go` `builtinTypesLower`,
//! the toolchain the mihomo 1.19.33 reference is built with), never the system's
//! `mime.types`, then a shortened `DetectContentType`.

use std::path::Path;

/// `sniffLen` (`sniff.go:13`).
pub(super) const SNIFF_LEN: usize = 512;

const BY_EXTENSION: &[(&str, &str)] = &[
    ("ai", "application/postscript"),
    ("apk", "application/vnd.android.package-archive"),
    ("apng", "image/apng"),
    ("avif", "image/avif"),
    ("bin", "application/octet-stream"),
    ("bmp", "image/bmp"),
    ("com", "application/octet-stream"),
    ("css", "text/css; charset=utf-8"),
    ("csv", "text/csv; charset=utf-8"),
    ("doc", "application/msword"),
    (
        "docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    ("ehtml", "text/html; charset=utf-8"),
    ("eml", "message/rfc822"),
    ("eps", "application/postscript"),
    ("exe", "application/octet-stream"),
    ("flac", "audio/flac"),
    ("gif", "image/gif"),
    ("gz", "application/gzip"),
    ("htm", "text/html; charset=utf-8"),
    ("html", "text/html; charset=utf-8"),
    ("ico", "image/vnd.microsoft.icon"),
    ("ics", "text/calendar; charset=utf-8"),
    ("jfif", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("jpg", "image/jpeg"),
    ("js", "text/javascript; charset=utf-8"),
    ("json", "application/json"),
    ("m4a", "audio/mp4"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("mp3", "audio/mpeg"),
    ("mp4", "video/mp4"),
    ("oga", "audio/ogg"),
    ("ogg", "audio/ogg"),
    ("ogv", "video/ogg"),
    ("opus", "audio/ogg"),
    ("pdf", "application/pdf"),
    ("pjp", "image/jpeg"),
    ("pjpeg", "image/jpeg"),
    ("png", "image/png"),
    ("ppt", "application/vnd.ms-powerpoint"),
    (
        "pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    ("ps", "application/postscript"),
    ("rdf", "application/rdf+xml"),
    ("rtf", "application/rtf"),
    ("shtml", "text/html; charset=utf-8"),
    ("svg", "image/svg+xml"),
    ("text", "text/plain; charset=utf-8"),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("txt", "text/plain; charset=utf-8"),
    ("vtt", "text/vtt; charset=utf-8"),
    ("wasm", "application/wasm"),
    ("wav", "audio/wav"),
    ("weba", "audio/webm"),
    ("webm", "video/webm"),
    ("webp", "image/webp"),
    ("xbl", "text/xml; charset=utf-8"),
    ("xbm", "image/x-xbitmap"),
    ("xht", "application/xhtml+xml"),
    ("xhtml", "application/xhtml+xml"),
    ("xls", "application/vnd.ms-excel"),
    (
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    ("xml", "text/xml; charset=utf-8"),
    ("xsl", "text/xml; charset=utf-8"),
    ("zip", "application/zip"),
];

/// `mime.TypeByExtension`, which also takes the extension in lower case.
pub(super) fn by_extension(name: &Path) -> Option<&'static str> {
    let extension = name.extension()?.to_str()?.to_ascii_lowercase();
    BY_EXTENSION
        .iter()
        .find(|(known, _)| *known == extension)
        .map(|(_, content_type)| *content_type)
}

/// The tags `DetectContentType` takes for HTML, each followed by a space or `>`.
const HTML_TAGS: &[&[u8]] = &[
    b"<!DOCTYPE HTML",
    b"<HTML",
    b"<HEAD",
    b"<SCRIPT",
    b"<IFRAME",
    b"<H1",
    b"<DIV",
    b"<FONT",
    b"<TABLE",
    b"<A",
    b"<STYLE",
    b"<TITLE",
    b"<B",
    b"<BODY",
    b"<BR",
    b"<P",
    b"<!--",
];

const MAGIC: &[(&[u8], &str)] = &[
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x1f\x8b\x08", "application/x-gzip"),
    (b"PK\x03\x04", "application/zip"),
];

/// `DetectContentType` (`sniff.go:21-38`) for the HTML tags, `<?xml`, the magic numbers
/// above, WebP and UTF-8 text; Go's other signatures (fonts, audio, video, archives beyond
/// zip and gzip) come out as `application/octet-stream`.
pub(super) fn sniff(data: &[u8]) -> &'static str {
    let data = data.get(..SNIFF_LEN).unwrap_or(data);
    let start = data
        .iter()
        .position(|byte| !matches!(byte, b'\t' | b'\n' | b'\x0c' | b'\r' | b' '))
        .unwrap_or(data.len());
    let text = data.get(start..).unwrap_or_default();
    let html = HTML_TAGS.iter().any(|tag| {
        let (Some(head), Some(after)) = (text.get(..tag.len()), text.get(tag.len())) else {
            return false;
        };
        head.eq_ignore_ascii_case(tag) && matches!(after, b' ' | b'>')
    });
    if html {
        return "text/html; charset=utf-8";
    }
    if text.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    if let Some((_, content_type)) = MAGIC.iter().find(|(magic, _)| data.starts_with(magic)) {
        return content_type;
    }
    if data.starts_with(b"RIFF") && data.get(8..14) == Some(b"WEBPVP".as_slice()) {
        return "image/webp";
    }
    let binary = data
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f));
    if binary {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extension_in_any_case_names_its_type_and_an_unknown_one_none() {
        assert_eq!(
            by_extension(Path::new("a/INDEX.HTML")),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(by_extension(Path::new("logo.svg")), Some("image/svg+xml"));
        assert_eq!(by_extension(Path::new("notes.md")), None);
        assert_eq!(by_extension(Path::new("README")), None);
    }

    #[test]
    fn sniffing_takes_html_after_whitespace_magic_numbers_and_text() {
        assert_eq!(sniff(b"\n  <html><body>"), "text/html; charset=utf-8");
        assert_eq!(sniff(b"<!-- note -->"), "text/html; charset=utf-8");
        assert_eq!(sniff(b"<hr>"), "text/plain; charset=utf-8");
        assert_eq!(sniff(b"<?xml version"), "text/xml; charset=utf-8");
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\nrest"), "image/png");
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), "image/webp");
        assert_eq!(sniff(b"plain words"), "text/plain; charset=utf-8");
        assert_eq!(sniff(b"\x00\x01\x02"), "application/octet-stream");
    }
}

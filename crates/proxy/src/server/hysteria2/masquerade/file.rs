//! Go's `http.FileServer(http.Dir(root))` (`fs.go` `serveFile`, `serveContent`),
//! with the root and every path under it confined to the home directory: a path through a
//! symlink is not found, where Go follows it. Several ranges are answered as none, with the
//! whole file, where Go sends `multipart/byteranges`.

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use concord_common::Tasks;
use concord_platform::HomeDir;
use http::{Method, Request, StatusCode, header};
use percent_encoding::percent_decode_str;
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::content_type::{SNIFF_LEN, by_extension, sniff};
use super::{Body, HTTP_DATE, Reply, http_date};

const INDEX: &str = "/index.html";

pub(in crate::server::hysteria2) struct Files {
    root: PathBuf,
    home: Arc<HomeDir>,
}

impl Files {
    pub(super) fn new(root: &str, home: &Arc<HomeDir>) -> io::Result<Self> {
        Ok(Files {
            root: home.confine_profile_file(root)?,
            home: home.clone(),
        })
    }

    /// `fileHandler.ServeHTTP` and `serveFile` with its canonical-path redirects.
    pub(super) async fn answer(&self, request: &Request<()>, tasks: Tasks) -> Reply {
        let raw = request.uri().path();
        let decoded = percent_decode_str(raw).decode_utf8_lossy();
        let url = if decoded.starts_with('/') {
            decoded.into_owned()
        } else {
            format!("/{decoded}")
        };
        if url.ends_with(INDEX) {
            return local_redirect(request.uri().query(), "./".to_owned());
        }
        let Some(found) = self.open(tasks.clone(), clean(&url)).await else {
            return Reply::error(StatusCode::NOT_FOUND, "404 page not found");
        };
        let mut opened = match found {
            Ok(opened) => opened,
            Err(err) => return open_error(&err),
        };
        if let Opened::Dir { .. } = opened {
            if !url.ends_with('/') {
                return local_redirect(request.uri().query(), format!("{}/", base(&url)));
            }
            let index = format!("{}{INDEX}", target_name(&url));
            if let Some(Ok(index)) = self.open(tasks, index).await {
                opened = index;
            }
        } else if url.ends_with('/') {
            let base = base(&url);
            if base == "/" || base == "." {
                return Reply::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "http: attempting to traverse a non-directory",
                );
            }
            return local_redirect(request.uri().query(), format!("../{base}"));
        }
        let modified = opened
            .meta()
            .modified()
            .ok()
            .filter(|time| *time != SystemTime::UNIX_EPOCH);
        let (target, file, size) = match opened {
            Opened::File { path, file, meta } => (path, file, meta.len()),
            Opened::Dir { path, .. } => {
                if if_modified_since(request, modified) == Cond::False {
                    return Reply::new(StatusCode::NOT_MODIFIED);
                }
                return listing(&path, modified).await;
            }
        };
        let range = match conditions(request, modified) {
            Ok(range) => range,
            Err(reply) => return *reply,
        };
        serve_file(
            target,
            tokio::fs::File::from_std(file),
            size,
            modified,
            range,
        )
        .await
    }

    /// `Dir.Open` and a `Stat` of what it opened, on the blocking pool with the home
    /// directory's checks: `None` for a name Go's `filepath.Localize` refuses or that the home
    /// directory does not allow, both of which answer 404.
    async fn open(&self, tasks: Tasks, name: String) -> Option<io::Result<Opened>> {
        let relative = name.trim_start_matches('/').to_owned();
        let unsafe_name = relative.contains('\0')
            || (cfg!(windows)
                && (relative.contains(['\\', ':']) || relative.split('/').any(device_name)));
        if unsafe_name {
            return None;
        }
        let (home, root) = (self.home.clone(), self.root.clone());
        let opening = tasks.spawn_blocking(move || {
            let path = home.confine_profile_file(root.join(relative)).ok()?;
            Some(Opened::open(path))
        });
        opening
            .await
            .unwrap_or_else(|err| Some(Err(io::Error::other(err))))
    }
}

/// A Windows device name as `Dir.Open`'s `Localize` refuses it, the standard library's from
/// Go 1.23 (`internal/filepath/path_go123.go`; Go 1.27.3 `internal/filepathlite/
/// path_windows.go:98-162`), with an extension too: Go asks Windows whether `CON.txt` is
/// still a device, which it is before Windows 11, and opening one could block a pool thread.
fn device_name(element: &str) -> bool {
    let base = element
        .split(['.', ':'])
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let upper = base.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => match upper.split_at_checked(3) {
            Some(("COM" | "LPT", number)) => {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                    || matches!(number, "\u{b9}" | "\u{b2}" | "\u{b3}")
            }
            _ => false,
        },
    }
}

/// What `Dir.Open` opened: a file with its handle, or a directory it could read.
enum Opened {
    File {
        path: PathBuf,
        file: std::fs::File,
        meta: std::fs::Metadata,
    },
    Dir {
        path: PathBuf,
        meta: std::fs::Metadata,
    },
}

impl Opened {
    /// `os.Open` then `Stat` on what it opened, so a name it may not read is refused, as a
    /// directory it may not list is.
    fn open(path: PathBuf) -> io::Result<Self> {
        let meta = std::fs::metadata(&path)?;
        if meta.is_dir() {
            std::fs::read_dir(&path)?;
            return Ok(Opened::Dir { path, meta });
        }
        let file = std::fs::File::open(&path)?;
        let meta = file.metadata()?;
        Ok(Opened::File { path, file, meta })
    }

    fn meta(&self) -> &std::fs::Metadata {
        match self {
            Opened::File { meta, .. } | Opened::Dir { meta, .. } => meta,
        }
    }
}

/// `dirList` of a directory, or Go's error when reading it fails.
async fn listing(dir: &Path, modified: Option<SystemTime>) -> Reply {
    match list(dir).await {
        Ok(listing) => Reply::new(StatusCode::OK)
            .last_modified(modified)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::Bytes(Bytes::from(listing))),
        Err(_) => Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Error reading directory"),
    }
}

/// `path.Clean` of a path that starts with `/`.
fn clean(url: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in url.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The directory name `serveFile` looks for `index.html` under: the cleaned path without a
/// trailing slash.
fn target_name(url: &str) -> String {
    clean(url).trim_end_matches('/').to_owned()
}

/// `path.Base`.
fn base(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.is_empty() {
        return if url.is_empty() {
            ".".into()
        } else {
            "/".into()
        };
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}

/// `localRedirect`: a relative 301, escaped slashes and all, where Go 1.27.3 answers a path
/// with one 404.
fn local_redirect(query: Option<&str>, mut to: String) -> Reply {
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        to.push('?');
        to.push_str(query);
    }
    Reply::new(StatusCode::MOVED_PERMANENTLY).header(header::LOCATION, &to)
}

/// `toHTTPError` after `mapOpenError`, which takes a path through a file for one that does
/// not exist.
fn open_error(err: &io::Error) -> Reply {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
            Reply::error(StatusCode::NOT_FOUND, "404 page not found")
        }
        io::ErrorKind::PermissionDenied => Reply::error(StatusCode::FORBIDDEN, "403 Forbidden"),
        _ => Reply::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 Internal Server Error",
        ),
    }
}

/// `dirList`: the entries sorted by name, a directory's with a slash.
async fn list(dir: &Path) -> io::Result<String> {
    let mut read = tokio::fs::read_dir(dir.to_path_buf()).await?;
    let mut names = Vec::new();
    while let Some(entry) = read.next_entry().await? {
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().await?.is_dir() {
            name.push('/');
        }
        names.push(name);
    }
    names.sort();
    let mut page = String::from(
        "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n",
    );
    for name in names {
        page.push_str(&format!(
            "<a href=\"{}\">{}</a>\n",
            href(&name),
            html(&name)
        ));
    }
    page.push_str("</pre>\n");
    Ok(page)
}

/// `url.URL{Path: name}.String()`: escaped as a path, and behind `./` when a colon comes
/// before any slash, so that it does not read as a scheme.
fn href(name: &str) -> String {
    let mut out = String::new();
    if let Some(colon) = name.find(':')
        && !name[..colon].contains('/')
    {
        out.push_str("./");
    }
    for byte in name.bytes() {
        let kept = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            );
        if kept {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `htmlReplacer`.
fn html(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

const RFC850: &[FormatItem<'static>] = format_description!(
    "[weekday repr:long], [day]-[month repr:short]-[year] [hour]:[minute]:[second] GMT"
);
const ANSI_C: &[FormatItem<'static>] = format_description!(
    "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
);

/// `http.ParseTime`, in seconds since the epoch.
fn parse_time(text: &str) -> Option<i64> {
    let parse = |text: &str, format| {
        time::PrimitiveDateTime::parse(text, format)
            .ok()
            .map(|time| time.assume_utc().unix_timestamp())
    };
    parse(text, HTTP_DATE)
        .or_else(|| parse(&rfc850_full_year(text)?, RFC850))
        .or_else(|| parse(text, ANSI_C))
}

/// RFC 850's two-digit year as Go's `time.Parse` reads `06`: 69 to 99 in the 1900s, the
/// rest in the 2000s. The `time` crate parses no two-digit year to a full one.
fn rfc850_full_year(text: &str) -> Option<String> {
    let (head, rest) = text.rsplit_once('-')?;
    let (year, tail) = rest.split_at_checked(2)?;
    let year: u16 = year.parse().ok()?;
    let year = if year >= 69 { 1900 + year } else { 2000 + year };
    Some(format!("{head}-{year}{tail}"))
}

fn seconds(time: SystemTime) -> Option<i64> {
    Some(OffsetDateTime::from(time).unix_timestamp())
}

fn header_text(request: &Request<()>, name: header::HeaderName) -> &str {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn gets(request: &Request<()>) -> bool {
    request.method() == Method::GET || request.method() == Method::HEAD
}

/// The entity tags of a list, or `*` alone, as `scanETag` reads them; `None` at the first
/// that does not parse, where Go stops.
fn etags(list: &str) -> Vec<Option<&str>> {
    list.split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(|tag| {
            let opaque = tag.strip_prefix("W/").unwrap_or(tag);
            (tag == "*" || (opaque.len() >= 2 && opaque.starts_with('"') && opaque.ends_with('"')))
                .then_some(tag)
        })
        .collect()
}

/// `checkIfMatch` with no entity tag of its own: only `*` matches.
fn if_match(request: &Request<()>) -> Cond {
    let list = header_text(request, header::IF_MATCH);
    if list.is_empty() {
        return Cond::None;
    }
    for tag in etags(list) {
        match tag {
            Some("*") => return Cond::True,
            Some(_) => {}
            None => break,
        }
    }
    Cond::False
}

fn if_unmodified_since(request: &Request<()>, modified: Option<SystemTime>) -> Cond {
    let (Some(since), Some(modified)) = (
        parse_time(header_text(request, header::IF_UNMODIFIED_SINCE)),
        modified.and_then(seconds),
    ) else {
        return Cond::None;
    };
    if modified <= since {
        Cond::True
    } else {
        Cond::False
    }
}

/// `checkIfNoneMatch` with no entity tag of its own: only `*` matches.
fn if_none_match(request: &Request<()>) -> Cond {
    let list = header_text(request, header::IF_NONE_MATCH);
    if list.is_empty() {
        return Cond::None;
    }
    for tag in etags(list) {
        match tag {
            Some("*") => return Cond::False,
            Some(_) => {}
            None => break,
        }
    }
    Cond::True
}

fn if_modified_since(request: &Request<()>, modified: Option<SystemTime>) -> Cond {
    if !gets(request) {
        return Cond::None;
    }
    let (Some(since), Some(modified)) = (
        parse_time(header_text(request, header::IF_MODIFIED_SINCE)),
        modified.and_then(seconds),
    ) else {
        return Cond::None;
    };
    if modified <= since {
        Cond::False
    } else {
        Cond::True
    }
}

/// `checkIfRange`: an entity tag never matches, a date must equal the modification time.
fn if_range(request: &Request<()>, modified: Option<SystemTime>) -> Cond {
    if !gets(request) {
        return Cond::None;
    }
    let given = header_text(request, header::IF_RANGE);
    if given.is_empty() {
        return Cond::None;
    }
    if given.trim_start_matches("W/").starts_with('"') {
        return Cond::False;
    }
    match (parse_time(given), modified.and_then(seconds)) {
        (Some(date), Some(modified)) if date == modified => Cond::True,
        _ => Cond::False,
    }
}

fn not_modified(modified: Option<SystemTime>) -> Reply {
    Reply::new(StatusCode::NOT_MODIFIED).last_modified(modified)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    start: u64,
    length: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum RangeError {
    Invalid,
    NoOverlap,
}

/// `parseRange`, which reads every range, with no cap on how many as Go 1.27.3 has: the one
/// range to serve, or none when there are none or several, which get the whole file. Only
/// the first is kept, so a header of many ranges holds no list of them.
fn parse_range(text: &str, size: u64) -> Result<Option<Range>, RangeError> {
    if text.is_empty() {
        return Ok(None);
    }
    let Some(specs) = text.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let number = |text: &str| text.parse::<i64>().ok().filter(|n| *n >= 0);
    let mut first = None;
    let mut count = 0usize;
    let mut no_overlap = false;
    for spec in specs
        .split(',')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
    {
        let Some((start, end)) = spec.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (start.trim(), end.trim());
        if start.is_empty() {
            if end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let suffix = number(end)
                .ok_or(RangeError::Invalid)?
                .unsigned_abs()
                .min(size);
            count += 1;
            first = first.or(Some(Range {
                start: size - suffix,
                length: suffix,
            }));
            continue;
        }
        let start = number(start).ok_or(RangeError::Invalid)?.unsigned_abs();
        if start >= size {
            no_overlap = true;
            continue;
        }
        let last = if end.is_empty() {
            size - 1
        } else {
            let end = end
                .parse::<i64>()
                .ok()
                .filter(|end| *end >= 0 && start <= end.unsigned_abs())
                .ok_or(RangeError::Invalid)?;
            end.unsigned_abs().min(size - 1)
        };
        count += 1;
        first = first.or(Some(Range {
            start,
            length: last - start + 1,
        }));
    }
    if no_overlap && count == 0 {
        return Err(RangeError::NoOverlap);
    }
    Ok(if count == 1 { first } else { None })
}

/// The conditions of `serveContent`: the reply they decide on, or the `Range` header left
/// to serve.
fn conditions(request: &Request<()>, modified: Option<SystemTime>) -> Result<String, Box<Reply>> {
    let mut precondition = if_match(request);
    if precondition == Cond::None {
        precondition = if_unmodified_since(request, modified);
    }
    if precondition == Cond::False {
        return Err(Box::new(
            Reply::new(StatusCode::PRECONDITION_FAILED).last_modified(modified),
        ));
    }
    match if_none_match(request) {
        Cond::False if gets(request) => return Err(Box::new(not_modified(modified))),
        Cond::False => {
            let failed = Reply::new(StatusCode::PRECONDITION_FAILED).last_modified(modified);
            return Err(Box::new(failed));
        }
        Cond::None if if_modified_since(request, modified) == Cond::False => {
            return Err(Box::new(not_modified(modified)));
        }
        _ => {}
    }
    let mut range = header_text(request, header::RANGE).to_owned();
    if !range.is_empty() && if_range(request, modified) == Cond::False {
        range.clear();
    }
    Ok(range)
}

/// The rest of `serveContent` for a file of `size` bytes, from owned values only: a borrow of
/// the request held across its awaits keeps rustc from proving the request task `Send`.
async fn serve_file(
    path: PathBuf,
    mut file: tokio::fs::File,
    size: u64,
    modified: Option<SystemTime>,
    range: String,
) -> Reply {
    let content_type = match by_extension(&path) {
        Some(known) => known,
        None => {
            let mut head = vec![0u8; SNIFF_LEN];
            let mut filled = 0;
            while filled < head.len() {
                let Some(unread) = head.get_mut(filled..) else {
                    break;
                };
                match file.read(unread).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => filled += n,
                }
            }
            if file.seek(SeekFrom::Start(0)).await.is_err() {
                return Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "seeker can't seek");
            }
            sniff(head.get(..filled).unwrap_or_default())
        }
    };
    let range = match parse_range(&range, size) {
        Ok(range) => range,
        Err(RangeError::NoOverlap) if size == 0 => None,
        Err(RangeError::NoOverlap) => {
            return Reply::error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "invalid range: failed to overlap",
            )
            .header(header::CONTENT_RANGE, &format!("bytes */{size}"));
        }
        Err(RangeError::Invalid) => {
            return Reply::error(StatusCode::RANGE_NOT_SATISFIABLE, "invalid range");
        }
    };
    let mut reply = Reply::new(StatusCode::OK)
        .last_modified(modified)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::ACCEPT_RANGES, "bytes");
    let mut length = size;
    if let Some(range) = range {
        if file.seek(SeekFrom::Start(range.start)).await.is_err() {
            return Reply::error(StatusCode::RANGE_NOT_SATISFIABLE, "seek failed");
        }
        length = range.length;
        reply.status = StatusCode::PARTIAL_CONTENT;
        reply = reply.header(header::CONTENT_RANGE, &content_range(range, size));
    }
    reply
        .header(header::CONTENT_LENGTH, &length.to_string())
        .body(Body::File { file, length })
}

/// `httpRange.contentRange` in Go's signed arithmetic: an empty range of an empty file reads
/// `bytes 0--1/0`.
fn content_range(range: Range, size: u64) -> String {
    let last = i128::from(range.start) + i128::from(range.length) - 1;
    format!("bytes {}-{last}/{size}", range.start)
}

impl Reply {
    fn last_modified(self, modified: Option<SystemTime>) -> Self {
        match modified.and_then(http_date) {
            Some(date) => self.header(header::LAST_MODIFIED, &date),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_as_go_reads_them() {
        let one = |start, length| Ok(Some(Range { start, length }));
        assert_eq!(parse_range("", 10), Ok(None));
        assert_eq!(parse_range("bytes=2-4", 10), one(2, 3));
        assert_eq!(parse_range("bytes=-3", 10), one(7, 3));
        assert_eq!(parse_range("bytes=-30", 10), one(0, 10));
        assert_eq!(parse_range("bytes=8-", 10), one(8, 2));
        assert_eq!(parse_range("bytes=8-99", 10), one(8, 2));
        assert_eq!(parse_range("bytes= 0-0 , 9-", 10), Ok(None));
        assert_eq!(parse_range("bytes=10-", 10), Err(RangeError::NoOverlap));
        assert_eq!(parse_range("bytes=10-,2-3", 10), one(2, 2));
        assert_eq!(parse_range("items=0-1", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("bytes=4-2", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("bytes=--2", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("bytes=x", 10), Err(RangeError::Invalid));
    }

    #[test]
    fn a_header_of_many_ranges_is_read_to_its_end() {
        let many = vec!["0-0"; 1000].join(",");
        assert_eq!(parse_range(&format!("bytes={many}"), 10), Ok(None));
        assert_eq!(
            parse_range(&format!("bytes={many},x"), 10),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn a_suffix_range_of_an_empty_file_reads_as_go_writes_it() {
        let range = Range {
            start: 0,
            length: 0,
        };
        assert_eq!(parse_range("bytes=-5", 0), Ok(Some(range)));
        assert_eq!(content_range(range, 0), "bytes 0--1/0");
        let middle = Range {
            start: 2,
            length: 3,
        };
        assert_eq!(content_range(middle, 10), "bytes 2-4/10");
    }

    #[test]
    fn windows_device_names_are_told_apart_as_localize_tells_them() {
        for name in [
            "CON",
            "nul",
            "Aux.txt",
            "com1",
            "LPT9.log",
            "COM\u{b9}",
            "conin$",
            "PRN  ",
        ] {
            assert!(device_name(name), "{name}");
        }
        for name in ["CONSOLE", "COM0", "LPT10", "con_", "index.html", "NULL"] {
            assert!(!device_name(name), "{name}");
        }
    }

    #[test]
    fn paths_clean_and_name_their_base_as_go_does() {
        assert_eq!(clean("/a/./b/../c//d/"), "/a/c/d");
        assert_eq!(clean("/../.."), "/");
        assert_eq!(base("/a/b/"), "b");
        assert_eq!(base("/"), "/");
        assert_eq!(base("/x"), "x");
    }

    #[test]
    fn a_listing_escapes_names_as_a_path_and_as_html() {
        assert_eq!(href("a b?.txt"), "a%20b%3F.txt");
        assert_eq!(href("c:d"), "./c:d");
        assert_eq!(href("dir/"), "dir/");
        assert_eq!(html("<a&'\">"), "&lt;a&amp;&#39;&#34;&gt;");
    }

    #[test]
    fn dates_read_in_go_s_three_layouts() {
        let at = 784_111_777;
        assert_eq!(parse_time("Sun, 06 Nov 1994 08:49:37 GMT"), Some(at));
        assert_eq!(parse_time("Sunday, 06-Nov-94 08:49:37 GMT"), Some(at));
        assert_eq!(parse_time("Sun Nov  6 08:49:37 1994"), Some(at));
        assert_eq!(parse_time("yesterday"), None);
        let time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(784_111_777);
        assert_eq!(
            http_date(time).as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
    }
}

//! What a host asks of the MITM capture across connections: the API builds it, the MITM
//! engine answers it.

/// How an exchange ended, as the capture's status filter and counts name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusClass {
    Informational,
    Success,
    Redirect,
    ClientError,
    ServerError,
    /// No response: the request failed, was aborted or the connection broke.
    Failed,
    /// Still waiting for its response.
    Pending,
}

impl StatusClass {
    pub fn of(status: i32, error: &str, pending: bool) -> Self {
        if !error.is_empty() {
            return StatusClass::Failed;
        }
        match status / 100 {
            1 => StatusClass::Informational,
            2 => StatusClass::Success,
            3 => StatusClass::Redirect,
            4 => StatusClass::ClientError,
            5 => StatusClass::ServerError,
            _ if pending => StatusClass::Pending,
            _ => StatusClass::Failed,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            StatusClass::Informational => "1xx",
            StatusClass::Success => "2xx",
            StatusClass::Redirect => "3xx",
            StatusClass::ClientError => "4xx",
            StatusClass::ServerError => "5xx",
            StatusClass::Failed => "failed",
            StatusClass::Pending => "pending",
        }
    }

    /// What the rate counts as an error.
    pub fn is_error(self) -> bool {
        matches!(
            self,
            StatusClass::ClientError | StatusClass::ServerError | StatusClass::Failed
        )
    }
}

/// What a response holds, read from its `Content-Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentKind {
    Json,
    Html,
    Script,
    Css,
    Image,
    Font,
    Media,
    Text,
    /// Anything else, and a response without a type or not answered yet.
    Other,
}

impl ContentKind {
    /// `mime` is the type without its parameters, in lower case.
    pub fn of(mime: &str) -> Self {
        let (top, sub) = mime.split_once('/').unwrap_or((mime, ""));
        match (top, sub) {
            (_, "json") | (_, "ld+json") => ContentKind::Json,
            (_, sub) if sub.ends_with("+json") => ContentKind::Json,
            ("text", "html") | ("application", "xhtml+xml") => ContentKind::Html,
            (
                "text" | "application",
                "javascript" | "ecmascript" | "x-javascript" | "x-ecmascript",
            ) => ContentKind::Script,
            ("text", "css") => ContentKind::Css,
            ("image", _) => ContentKind::Image,
            ("font", _) => ContentKind::Font,
            ("application", sub) if sub.starts_with("font-") || sub.starts_with("x-font-") => {
                ContentKind::Font
            }
            ("application", "vnd.ms-fontobject") => ContentKind::Font,
            ("audio" | "video", _) => ContentKind::Media,
            ("text", _) | ("application", "xml") => ContentKind::Text,
            (_, sub) if sub.ends_with("+xml") => ContentKind::Text,
            _ => ContentKind::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ContentKind::Json => "json",
            ContentKind::Html => "html",
            ContentKind::Script => "script",
            ContentKind::Css => "css",
            ContentKind::Image => "image",
            ContentKind::Font => "font",
            ContentKind::Media => "media",
            ContentKind::Text => "text",
            ContentKind::Other => "other",
        }
    }
}

/// Each list left empty and each field left `None` lets every exchange through; a list
/// keeps the exchanges that match any of its items.
#[derive(Clone, Debug, Default)]
pub struct ExchangeFilter {
    pub statuses: Vec<StatusClass>,
    /// Compared without case.
    pub methods: Vec<String>,
    pub kinds: Vec<ContentKind>,
    /// Compared without case.
    pub hosts: Vec<String>,
    /// The process a connection lists, as `connection.watch` gives it; empty for none.
    pub apps: Vec<String>,
    pub rewritten: Option<bool>,
    /// Taking at least this long, a pending exchange by how long it has waited so far.
    pub slow_ms: Option<i64>,
    /// Found without case in the URL, method, content type, error or app.
    pub text: Option<String>,
    /// Started at or after this time, in Unix milliseconds.
    pub from_ms: Option<i64>,
    /// Started before this time, in Unix milliseconds.
    pub to_ms: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeQuery {
    pub filter: ExchangeFilter,
    /// Only exchanges whose id is below this one.
    pub before: Option<i64>,
    /// At most this many exchanges; none: every match.
    pub limit: Option<usize>,
    /// Only exchanges added or changed after this version of the capture.
    pub since: Option<u64>,
    pub facets: bool,
    /// Count the matches by the second they started in, from this time on (Unix milliseconds).
    pub rate_from_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_wins_over_its_status_and_no_answer_yet_is_pending() {
        assert_eq!(StatusClass::of(502, "reset", false), StatusClass::Failed);
        assert_eq!(StatusClass::of(0, "", true), StatusClass::Pending);
        assert_eq!(StatusClass::of(0, "", false), StatusClass::Failed);
        assert_eq!(StatusClass::of(204, "", false), StatusClass::Success);
        assert_eq!(StatusClass::of(404, "", false), StatusClass::ClientError);
        assert!(StatusClass::of(503, "", false).is_error());
        assert!(!StatusClass::of(304, "", false).is_error());
    }

    #[test]
    fn content_types_fall_into_their_kinds() {
        for (mime, kind) in [
            ("application/json", ContentKind::Json),
            ("application/problem+json", ContentKind::Json),
            ("text/html", ContentKind::Html),
            ("text/javascript", ContentKind::Script),
            ("application/javascript", ContentKind::Script),
            ("text/css", ContentKind::Css),
            ("image/webp", ContentKind::Image),
            ("font/woff2", ContentKind::Font),
            ("application/font-woff", ContentKind::Font),
            ("video/mp4", ContentKind::Media),
            ("text/plain", ContentKind::Text),
            ("application/atom+xml", ContentKind::Text),
            ("application/octet-stream", ContentKind::Other),
            ("", ContentKind::Other),
        ] {
            assert_eq!(ContentKind::of(mime), kind, "{mime}");
        }
    }
}

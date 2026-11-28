use super::super::Masquerade;
use super::{R, skip};

/// mihomo parses the URL with Go's `url.Parse` and refuses the listener for any scheme but
/// `file`, `http` and `https` (`server.go:121-154`); `file` serves the URL's path.
pub(super) fn masquerade(text: &str) -> R<Option<Masquerade>> {
    if text.is_empty() {
        return Ok(None);
    }
    let scheme = text.split_once(':').map_or("", |(scheme, _)| scheme);
    match scheme.to_ascii_lowercase().as_str() {
        "file" => {
            let rest = &text[scheme.len() + 1..];
            // Go's URL keeps an opaque `file:site` out of the path, which leaves it empty.
            let path = match rest.strip_prefix("//") {
                Some(authority) => authority.find('/').map_or("", |slash| &authority[slash..]),
                None if rest.starts_with('/') => rest,
                None => "",
            };
            let path = path.split(['?', '#']).next().unwrap_or_default();
            let Ok(path) = percent_encoding::percent_decode_str(path).decode_utf8() else {
                return skip(format!("parse masquerade URL: {text}"));
            };
            if path.is_empty() {
                return skip("masquerade file URL names no directory");
            }
            Ok(Some(Masquerade::File(path.into_owned())))
        }
        "http" | "https" => match text.parse::<http::Uri>() {
            Ok(uri) if uri.authority().is_some() => Ok(Some(Masquerade::Proxy(uri))),
            _ => skip(format!("parse masquerade URL: {text}")),
        },
        _ => skip(format!("unknown masquerade URL scheme: {scheme}")),
    }
}

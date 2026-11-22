use concord_config::mitm::text::canonical_header;
use concord_config::mitm::{DataType, MULTILINE};
use http::header::HeaderMap;

use super::{BodyAction, BodyRewrite, HeaderEdit, HeaderRewrite, MapLocal, UrlRewrite};
use crate::heads::HeadConditions;
use crate::pattern::Pattern;
use crate::view::{
    BodyReplacementView, BodyRewriteView, HeaderRewriteView, HeaderView, LineView, MapLocalView,
    Phase, UrlRewriteView,
};

fn source(pattern: &Pattern) -> String {
    pattern.source().to_string()
}

fn header_text(value: &http::HeaderValue) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

fn body_regex(pattern: &Pattern) -> &str {
    pattern
        .source()
        .strip_prefix(MULTILINE)
        .unwrap_or(pattern.source())
}

impl HeadConditions {
    pub(crate) fn sources(&self) -> (Option<String>, Option<String>) {
        (
            self.request.as_ref().map(source),
            self.response.as_ref().map(source),
        )
    }
}

impl UrlRewrite {
    pub(crate) fn view(&self) -> LineView {
        LineView::UrlRewrite(UrlRewriteView {
            pattern: source(&self.pattern),
            action: self.action,
            replacement: (!self.action.rejects()).then(|| self.replacement.clone()),
            request_head: self.head.as_ref().map(source),
        })
    }
}

impl HeaderRewrite {
    pub(crate) fn view(&self) -> LineView {
        let (request_head, response_head) = self.conditions.sources();
        let mut view = HeaderRewriteView {
            phase: Phase::of(self.response),
            pattern: source(&self.pattern),
            request_head,
            response_head,
            action: self.edit.action(),
            name: None,
            value: None,
            regex: None,
            replacement: None,
        };
        match &self.edit {
            HeaderEdit::Add(name, text) | HeaderEdit::Replace(name, text) => {
                view.name = Some(canonical_header(name.as_str()));
                view.value = Some(header_text(text));
            }
            HeaderEdit::Del(name) => view.name = Some(canonical_header(name.as_str())),
            HeaderEdit::ReplaceRegex(name, regex, replacement) => {
                view.name = Some(canonical_header(name.as_str()));
                view.regex = Some(source(regex));
                view.replacement = Some(replacement.clone());
            }
            HeaderEdit::Text(regex, replacement) => {
                view.regex = Some(source(regex));
                view.replacement = Some(replacement.clone());
            }
        }
        LineView::HeaderRewrite(view)
    }

    /// The edit as its line writes it after the URL pattern, for the capture's action detail.
    pub(crate) fn note(&self) -> String {
        let keyword = self.edit.action().name();
        match &self.edit {
            HeaderEdit::Add(name, text) | HeaderEdit::Replace(name, text) => format!(
                "{keyword} {} {}",
                canonical_header(name.as_str()),
                header_text(text)
            ),
            HeaderEdit::Del(name) => format!("{keyword} {}", canonical_header(name.as_str())),
            HeaderEdit::ReplaceRegex(name, regex, replacement) => format!(
                "{keyword} {} {} {replacement}",
                canonical_header(name.as_str()),
                regex.source()
            ),
            HeaderEdit::Text(regex, replacement) => {
                format!("{keyword} {} {replacement}", regex.source())
            }
        }
    }
}

impl BodyRewrite {
    pub(crate) fn view(&self) -> LineView {
        let (request_head, response_head) = self.conditions.sources();
        let (replacements, jq) = match &self.action {
            BodyAction::Replace(pairs) => (
                pairs
                    .iter()
                    .map(|pair| BodyReplacementView {
                        regex: body_regex(&pair.pattern).to_string(),
                        replacement: pair.with.clone(),
                    })
                    .collect(),
                None,
            ),
            BodyAction::Jq(jq) => (Vec::new(), Some(jq.code().to_string())),
        };
        LineView::BodyRewrite(BodyRewriteView {
            phase: Phase::of(self.response),
            pattern: source(&self.pattern),
            request_head,
            response_head,
            replacements,
            jq,
        })
    }

    /// The rewrite as its line writes it after the URL pattern, a jq one led by `jq`, for the
    /// capture's action detail.
    pub(crate) fn note(&self) -> String {
        match &self.action {
            BodyAction::Replace(pairs) => pairs
                .iter()
                .map(|pair| format!("{} {}", body_regex(&pair.pattern), pair.with))
                .collect::<Vec<_>>()
                .join(" "),
            BodyAction::Jq(jq) => format!("jq {}", jq.code()),
        }
    }
}

/// `data_type` and `data` as the line gave them; `header` holds the line's own headers, without
/// the content type the data implies.
pub(super) fn map_local_view(
    rule: &MapLocal,
    data_type: DataType,
    data: &str,
    request: bool,
    header: &HeaderMap,
) -> LineView {
    let content_type = rule
        .header
        .get(http::header::CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    LineView::MapLocal(MapLocalView {
        pattern: source(&rule.pattern),
        request_head: rule.conditions.request.as_ref().map(source),
        data_type,
        data: data.to_string(),
        status: (!request).then(|| rule.status.as_u16()),
        headers: header
            .iter()
            .map(|(name, value)| HeaderView {
                name: canonical_header(name.as_str()),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            })
            .collect(),
        content_type,
    })
}

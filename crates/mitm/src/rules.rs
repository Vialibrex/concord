use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;

use concord_config::mitm::text::{decode_base64, quote};
use concord_config::mitm::{
    BodyActionDef, BodyRewriteDef, HeaderEditDef, HeaderRewriteDef, LineError, MapLocalBody,
    MapLocalDef, UrlRewriteDef,
};
use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};

use crate::heads::{HeadConditions, Heads};
use crate::jq::{Jq, JqOutcome};
use crate::pattern::Pattern;
use crate::script::{Script, ScriptKind};
use crate::view::{HeaderAction, LineView};

pub(crate) use concord_config::mitm::UrlAction;

mod index;
mod views;

const TINY_GIF_BASE64: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

/// The piece a map-local file is answered in. A file no larger than one piece stays in memory:
/// answering it from disk would take its whole size per answer anyway.
pub(crate) const LOCAL_PIECE: usize = 32 << 10;

/// A `map-local` or `request-body-mock` body.
#[derive(Debug, Clone)]
pub enum LocalBody {
    Bytes(Bytes),
    /// A file in the resources directory larger than [LOCAL_PIECE], read at each answer.
    File(PathBuf),
}

#[cfg(test)]
impl LocalBody {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            LocalBody::Bytes(bytes) => bytes,
            LocalBody::File(_) => &[],
        }
    }
}

#[derive(Debug)]
pub struct UrlRewrite {
    pattern: Pattern,
    /// Quantumult X's `url-and-header`: matched against the request head once the URL matches.
    head: Option<Pattern>,
    pub replacement: String,
    pub action: UrlAction,
    /// The module whose line it is; none for the profile's own.
    pub(crate) module: Option<Arc<str>>,
}

#[derive(Debug)]
enum HeaderEdit {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Replace(HeaderName, HeaderValue),
    ReplaceRegex(HeaderName, Pattern, String),
    /// Quantumult X's `request-header` and `response-header`: a replacement over the whole
    /// head, its first line included.
    Text(Pattern, String),
}

#[derive(Debug)]
pub struct HeaderRewrite {
    response: bool,
    pattern: Pattern,
    conditions: HeadConditions,
    edit: HeaderEdit,
    /// The module whose line it is; none for the profile's own.
    pub(crate) module: Option<Arc<str>>,
}

#[derive(Debug)]
struct BodyReplacement {
    pattern: Pattern,
    with: String,
}

#[derive(Debug)]
enum BodyAction {
    Replace(Vec<BodyReplacement>),
    Jq(Jq),
}

#[derive(Debug)]
pub struct BodyRewrite {
    response: bool,
    pattern: Pattern,
    conditions: HeadConditions,
    action: BodyAction,
    /// The module whose line it is; none for the profile's own.
    pub(crate) module: Option<Arc<str>>,
}

#[derive(Debug)]
pub struct MapLocal {
    pattern: Pattern,
    conditions: HeadConditions,
    pub status: StatusCode,
    pub header: HeaderMap,
    pub body: LocalBody,
    /// The module whose line it is; none for the profile's own.
    pub(crate) module: Option<Arc<str>>,
}

#[derive(Debug, Default)]
pub struct Rules {
    pub(crate) url_rewrites: Vec<UrlRewrite>,
    pub(crate) header_rewrites: Vec<HeaderRewrite>,
    pub(crate) body_rewrites: Vec<Arc<BodyRewrite>>,
    pub(crate) map_locals: Vec<MapLocal>,
    /// Loon's `mock-request-body`: bodies a request goes upstream with instead of its own.
    pub(crate) request_mocks: Vec<MapLocal>,
    pub(crate) scripts: Vec<Arc<Script>>,
    indexes: index::Indexes,
}

impl UrlRewrite {
    pub(crate) fn source(&self) -> &str {
        self.pattern.source()
    }
}

impl MapLocal {
    pub(crate) fn source(&self) -> &str {
        self.pattern.source()
    }
}

pub fn tiny_gif() -> Vec<u8> {
    decode_base64(TINY_GIF_BASE64).unwrap_or_default()
}

pub(crate) fn compile_url_rewrite(def: &UrlRewriteDef) -> Result<UrlRewrite, LineError> {
    Ok(UrlRewrite {
        pattern: Pattern::new(&def.pattern)?,
        head: def.head.as_deref().map(Pattern::new).transpose()?,
        replacement: def.replacement.clone(),
        action: def.action,
        module: None,
    })
}

pub(crate) fn compile_header_rewrite(def: &HeaderRewriteDef) -> Result<HeaderRewrite, LineError> {
    let edit = match &def.edit {
        HeaderEditDef::Add(name, value) => HeaderEdit::Add(name.clone(), value.clone()),
        HeaderEditDef::Del(name) => HeaderEdit::Del(name.clone()),
        HeaderEditDef::Replace(name, value) => HeaderEdit::Replace(name.clone(), value.clone()),
        HeaderEditDef::ReplaceRegex(name, pattern, with) => {
            HeaderEdit::ReplaceRegex(name.clone(), Pattern::new(pattern)?, with.clone())
        }
        HeaderEditDef::Text(pattern, with) => {
            HeaderEdit::Text(Pattern::new(pattern)?, with.clone())
        }
    };
    Ok(HeaderRewrite {
        response: def.response,
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        edit,
        module: None,
    })
}

impl HeaderEdit {
    fn action(&self) -> HeaderAction {
        match self {
            HeaderEdit::Add(..) => HeaderAction::Add,
            HeaderEdit::Del(_) => HeaderAction::Del,
            HeaderEdit::Replace(..) => HeaderAction::Replace,
            HeaderEdit::ReplaceRegex(..) => HeaderAction::ReplaceRegex,
            HeaderEdit::Text(..) => HeaderAction::TextReplace,
        }
    }
}

impl HeaderRewrite {
    /// The pattern and replacement of a rule that rewrites the whole head, which its caller
    /// applies as only it knows the first line.
    pub(crate) fn whole_head(&self) -> Option<(&Pattern, &str)> {
        match &self.edit {
            HeaderEdit::Text(pattern, replacement) => Some((pattern, replacement)),
            _ => None,
        }
    }

    pub(crate) fn apply(&self, header: &mut HeaderMap) -> bool {
        match &self.edit {
            HeaderEdit::Add(name, value) => {
                header.append(name.clone(), value.clone());
            }
            HeaderEdit::Del(name) => return header.remove(name).is_some(),
            HeaderEdit::Replace(name, value) => {
                if !header.contains_key(name) {
                    return false;
                }
                header.insert(name.clone(), value.clone());
            }
            HeaderEdit::ReplaceRegex(name, regex, replacement) => {
                if !header.contains_key(name) {
                    return false;
                }
                let values: Vec<HeaderValue> = header
                    .get_all(name)
                    .iter()
                    .map(|value| {
                        value
                            .to_str()
                            .ok()
                            .and_then(|text| regex.replace(text, replacement, true))
                            .and_then(|text| HeaderValue::from_str(&text).ok())
                            .unwrap_or_else(|| value.clone())
                    })
                    .collect();
                header.remove(name);
                for value in values {
                    header.append(name.clone(), value);
                }
            }
            HeaderEdit::Text(..) => return false,
        }
        true
    }
}

pub(crate) fn compile_body_rewrite(
    def: &BodyRewriteDef,
    resources: &Path,
) -> Result<BodyRewrite, LineError> {
    let action = match &def.action {
        BodyActionDef::Replace(pairs) => BodyAction::Replace(
            pairs
                .iter()
                .map(|(pattern, with)| {
                    Ok(BodyReplacement {
                        pattern: Pattern::multiline(pattern)?,
                        with: with.clone(),
                    })
                })
                .collect::<Result<_, LineError>>()?,
        ),
        BodyActionDef::Jq(expression) => BodyAction::Jq(Jq::compile(expression)?),
        BodyActionDef::JqFile(name) => {
            let code = read_resource(resources, "jq file", name)?;
            let code = String::from_utf8(code).map_err(|_| {
                LineError::resource(format!("jq file {} is not UTF-8", quote(name)))
            })?;
            BodyAction::Jq(Jq::compile(&code)?)
        }
    };
    Ok(BodyRewrite {
        response: def.response,
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        action,
        module: None,
    })
}

impl BodyRewrite {
    pub(crate) fn apply(&self, body: String) -> String {
        match &self.action {
            BodyAction::Replace(replacements) => {
                replacements.iter().fold(body, |body, replacement| {
                    replacement
                        .pattern
                        .replace(&body, &replacement.with, true)
                        .unwrap_or(body)
                })
            }
            BodyAction::Jq(jq) => match jq.run(&body) {
                JqOutcome::Rewritten(rewritten) => rewritten,
                JqOutcome::NotJson => {
                    tracing::debug!("[MITM] jq rewrite skipped: the body is not JSON");
                    body
                }
                JqOutcome::Empty => body,
                JqOutcome::Failed(err) => {
                    tracing::warn!("[MITM] jq rewrite failed: {err}");
                    body
                }
            },
        }
    }
}

fn is_local(name: &str) -> bool {
    if name.is_empty() || name.contains('\\') {
        return false;
    }
    let mut depth: i32 = 0;
    for component in Path::new(name).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    depth > 0
}

pub(crate) fn read_resource(dir: &Path, param: &str, name: &str) -> Result<Vec<u8>, LineError> {
    let (path, _) = resource_file(dir, param, name)?;
    std::fs::read(&path)
        .map_err(|_| LineError::resource(format!("{param} {} cannot be read", quote(name))))
}

/// What compiling a section would take from one of its files.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResourceSeen {
    /// The SHA-256 of a file the compile reads whole.
    Content([u8; 32]),
    /// A `map-local` file larger than [LOCAL_PIECE]: each answer reads it from disk, so its
    /// content is not part of what the compile made.
    ReadAtAnswer,
}

/// What [read_resource] finds of `name` now, hashed piece by piece, or why it cannot be read.
pub(crate) fn resource_digest(dir: &Path, name: &str) -> Result<ResourceSeen, LineError> {
    let (path, _) = resource_file(dir, "file", name)?;
    digest_file(&path)
        .map(ResourceSeen::Content)
        .map_err(|_| LineError::resource(format!("file {} cannot be read", quote(name))))
}

/// As [resource_digest] for a raw `map-local` file, whose content counts only while
/// [local_file] keeps it in memory.
pub(crate) fn local_file_seen(dir: &Path, name: &str) -> Result<ResourceSeen, LineError> {
    let (path, len) = resource_file(dir, "data", name)?;
    let unreadable = |_| LineError::resource(format!("data {} cannot be read", quote(name)));
    if len <= LOCAL_PIECE as u64 {
        return digest_file(&path)
            .map(ResourceSeen::Content)
            .map_err(unreadable);
    }
    std::fs::File::open(&path).map_err(unreadable)?;
    Ok(ResourceSeen::ReadAtAnswer)
}

fn digest_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut piece = vec![0; LOCAL_PIECE];
    loop {
        match std::io::Read::read(&mut file, &mut piece) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(read) => hasher.update(piece.get(..read).unwrap_or_default()),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// The path and length of a regular file in the resources directory.
fn resource_file(dir: &Path, param: &str, name: &str) -> Result<(PathBuf, u64), LineError> {
    if name.contains("://") {
        return Err(LineError::resource(format!(
            "{param} {} has not been downloaded",
            quote(name)
        )));
    }
    if !is_local(name) {
        return Err(LineError::resource(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        )));
    }
    let map_io = |err: std::io::Error| {
        let reason = match err.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            _ => "cannot be read".to_string(),
        };
        LineError::resource(format!("{param} {}: {reason}", quote(name)))
    };
    let canonical_dir = std::fs::canonicalize(dir).map_err(map_io)?;
    let path = dir.join(name);
    let canonical_path = std::fs::canonicalize(&path).map_err(map_io)?;
    if !canonical_path.starts_with(&canonical_dir) {
        return Err(LineError::resource(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        )));
    }
    let info = std::fs::metadata(&canonical_path).map_err(map_io)?;
    if !info.is_file() {
        return Err(LineError::resource(format!(
            "{param} {} is not a regular file",
            quote(name)
        )));
    }
    Ok((path, info.len()))
}

fn local_file(dir: &Path, name: &str) -> Result<LocalBody, LineError> {
    let (path, len) = resource_file(dir, "data", name)?;
    let unreadable = |_| LineError::resource(format!("data {} cannot be read", quote(name)));
    if len <= LOCAL_PIECE as u64 {
        return std::fs::read(&path)
            .map(|bytes| LocalBody::Bytes(bytes.into()))
            .map_err(unreadable);
    }
    std::fs::File::open(&path).map_err(unreadable)?;
    Ok(LocalBody::File(path))
}

/// A `map-local` or `request-body-mock` line's rule, its body read from the resources
/// directory when the line names a file.
pub(crate) fn compile_map_local(
    def: &MapLocalDef,
    resources: &Path,
) -> Result<(MapLocal, LineView), LineError> {
    let body = match &def.body {
        MapLocalBody::Text => LocalBody::Bytes(Bytes::copy_from_slice(def.data.as_bytes())),
        MapLocalBody::TinyGif => LocalBody::Bytes(tiny_gif().into()),
        MapLocalBody::Base64(bytes) => LocalBody::Bytes(bytes.clone().into()),
        MapLocalBody::File { base64: false } => local_file(resources, &def.data)?,
        MapLocalBody::File { base64: true } => {
            let text = read_resource(resources, "data", &def.data)?;
            let text = String::from_utf8_lossy(&text);
            LocalBody::Bytes(
                decode_base64(text.trim())
                    .map_err(|err| err.within("data"))?
                    .into(),
            )
        }
    };
    let mut header = def.header.clone();
    if !header.contains_key(CONTENT_TYPE) {
        header.insert(CONTENT_TYPE, HeaderValue::from_static(def.content_type));
    }
    let rule = MapLocal {
        pattern: Pattern::new(&def.pattern)?,
        conditions: HeadConditions::compile(&def.conditions)?,
        status: def.status,
        header,
        body,
        module: None,
    };
    let data = match def.body {
        MapLocalBody::TinyGif => "",
        _ => &def.data,
    };
    let view = views::map_local_view(&rule, def.body.data_type(), data, def.request, &def.header);
    Ok((rule, view))
}

#[cfg(test)]
pub(crate) fn parse_url_rewrite(line: &str) -> Result<UrlRewrite, LineError> {
    compile_url_rewrite(&concord_config::mitm::parse_url_rewrite(line)?)
}

#[cfg(test)]
pub(crate) fn parse_header_rewrite(line: &str) -> Result<HeaderRewrite, LineError> {
    compile_header_rewrite(&concord_config::mitm::parse_header_rewrite(line)?)
}

#[cfg(test)]
pub(crate) fn parse_body_rewrite(line: &str) -> Result<BodyRewrite, LineError> {
    compile_body_rewrite(
        &concord_config::mitm::parse_body_rewrite(line)?,
        Path::new(""),
    )
}

#[cfg(test)]
pub(crate) fn parse_map_local(
    line: &str,
    resources: &Path,
    request: bool,
) -> Result<(MapLocal, LineView), LineError> {
    compile_map_local(
        &concord_config::mitm::parse_map_local(line, request)?,
        resources,
    )
}

fn first_local<'r>(
    mut rules: impl Iterator<Item = &'r MapLocal>,
    url: &str,
    heads: &Heads<'_>,
) -> Option<&'r MapLocal> {
    rules.find(|rule| rule.pattern.is_match(url) && heads.allow(&rule.conditions))
}

pub(crate) use index::{RequestScan, ResponsePlan};

impl Rules {
    pub(crate) fn acts_on_requests(&self) -> bool {
        !self.url_rewrites.is_empty()
            || !self.header_rewrites.is_empty()
            || !self.body_rewrites.is_empty()
            || !self.map_locals.is_empty()
            || !self.request_mocks.is_empty()
            || self.scripts.iter().any(|script| {
                matches!(
                    script.kind,
                    ScriptKind::HttpRequest | ScriptKind::HttpResponse
                )
            })
    }

    pub(crate) fn rewrite_url_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<(&UrlRewrite, String)> {
        for &idx in &scan.url_rewrites {
            let Some(rule) = self.url_rewrites.get(idx as usize) else {
                continue;
            };
            if !rule.pattern.is_match(url) || !heads.request_allows(rule.head.as_ref()) {
                continue;
            }
            if rule.action.rejects() {
                return Some((rule, String::new()));
            }
            let replaced = rule.pattern.replace(url, &rule.replacement, false)?;
            return Some((rule, replaced));
        }
        None
    }

    pub(crate) fn map_local_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<&MapLocal> {
        first_local(
            scan.map_locals
                .iter()
                .filter_map(|&idx| self.map_locals.get(idx as usize)),
            url,
            heads,
        )
    }

    pub(crate) fn request_mock_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<&MapLocal> {
        first_local(
            scan.request_mocks
                .iter()
                .filter_map(|&idx| self.request_mocks.get(idx as usize)),
            url,
            heads,
        )
    }

    pub(crate) fn request_header_rewrites_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Vec<&HeaderRewrite> {
        scan.headers
            .iter()
            .filter_map(|&idx| self.header_rewrites.get(idx as usize))
            .filter(|rule| rule.pattern.is_match(url) && heads.allow(&rule.conditions))
            .collect()
    }

    pub(crate) fn request_body_rewrites_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Vec<Arc<BodyRewrite>> {
        scan.bodies
            .iter()
            .filter_map(|&idx| self.body_rewrites.get(idx as usize))
            .filter(|rule| rule.pattern.is_match(url) && heads.allow(&rule.conditions))
            .cloned()
            .collect()
    }

    pub(crate) fn request_script_from(
        &self,
        scan: &RequestScan,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<&std::sync::Arc<Script>> {
        scan.scripts
            .iter()
            .filter_map(|&idx| self.scripts.get(idx as usize))
            .find(|script| script.matches_http(url, false) && heads.allow(&script.conditions))
    }

    pub(crate) fn response_plan_rewrites_body(&self, plan: &ResponsePlan) -> bool {
        !plan.bodies.is_empty()
            || plan.scripts.first().is_some_and(|&idx| {
                self.scripts
                    .get(idx as usize)
                    .is_some_and(|script| script.requires_body)
            })
    }

    pub(crate) fn response_rules_from(
        &self,
        plan: &ResponsePlan,
        heads: &Heads<'_>,
    ) -> (
        Vec<&HeaderRewrite>,
        Vec<Arc<BodyRewrite>>,
        Option<&std::sync::Arc<Script>>,
    ) {
        let headers = plan
            .headers
            .iter()
            .filter_map(|&idx| self.header_rewrites.get(idx as usize))
            .filter(|rule| heads.allow(&rule.conditions))
            .collect();
        let bodies = plan
            .bodies
            .iter()
            .filter_map(|&idx| self.body_rewrites.get(idx as usize))
            .filter(|rule| heads.allow(&rule.conditions))
            .cloned()
            .collect();
        let script = plan
            .scripts
            .iter()
            .filter_map(|&idx| self.scripts.get(idx as usize))
            .find(|script| heads.allow(&script.conditions));
        (headers, bodies, script)
    }

    #[cfg(test)]
    pub(crate) fn rewrite_url(
        &self,
        url: &str,
        heads: &Heads<'_>,
    ) -> Option<(&UrlRewrite, String)> {
        let scan = self.scan_request(url);
        self.rewrite_url_from(&scan, url, heads)
    }

    #[cfg(test)]
    pub(crate) fn map_local(&self, url: &str, heads: &Heads<'_>) -> Option<&MapLocal> {
        let scan = self.scan_request(url);
        self.map_local_from(&scan, url, heads)
    }

    #[cfg(test)]
    pub(crate) fn request_mock(&self, url: &str, heads: &Heads<'_>) -> Option<&MapLocal> {
        let scan = self.scan_request(url);
        self.request_mock_from(&scan, url, heads)
    }

    /// The header rewrites for an exchange, picked before any of them runs so that each
    /// condition reads the head as the phase began.
    #[cfg(test)]
    pub(crate) fn header_rewrites_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Vec<&HeaderRewrite> {
        if response {
            let plan = self.prepare_response(url);
            self.response_rules_from(&plan, heads).0
        } else {
            let scan = self.scan_request(url);
            self.request_header_rewrites_from(&scan, url, heads)
        }
    }

    #[cfg(test)]
    pub(crate) fn body_rewrites_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Vec<Arc<BodyRewrite>> {
        if response {
            let plan = self.prepare_response(url);
            self.response_rules_from(&plan, heads).1
        } else {
            let scan = self.scan_request(url);
            self.request_body_rewrites_from(&scan, url, heads)
        }
    }

    /// The first script whose URL and conditions match; one whose conditions do not
    /// leaves the turn to the next.
    #[cfg(test)]
    pub(crate) fn script_for(
        &self,
        url: &str,
        response: bool,
        heads: &Heads<'_>,
    ) -> Option<&std::sync::Arc<Script>> {
        if response {
            let plan = self.prepare_response(url);
            self.response_rules_from(&plan, heads).2
        } else {
            let scan = self.scan_request(url);
            self.request_script_from(&scan, url, heads)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(line: &str) -> (UrlAction, String) {
        let rule = parse_url_rewrite(line).unwrap_or_else(|err| panic!("{line}: {err}"));
        (rule.action, rule.replacement)
    }

    #[test]
    fn url_rewrite_reads_surge_loon_and_quantumult_x() {
        let cases = [
            (r"^https?://ad\.test/ _ reject", UrlAction::Reject, ""),
            (
                r"^https?://ad\.test/ reject-dict",
                UrlAction::RejectDict,
                "",
            ),
            (
                r"^https?://ad\.test/ url reject-img",
                UrlAction::RejectImg,
                "",
            ),
            (
                r"^https?://ad\.test/ url 302 https://b.test/",
                UrlAction::Redirect302,
                "https://b.test/",
            ),
            (
                r"^https?://ad\.test/ 302 https://b.test/",
                UrlAction::Redirect302,
                "https://b.test/",
            ),
            (
                r"^http://a\.test/(.*) http://b.test/$1 307",
                UrlAction::Redirect307,
                "http://b.test/$1",
            ),
            (
                r"^http://a\.test http://b.test",
                UrlAction::Header,
                "http://b.test",
            ),
            (
                r"^http://a\.test http://b.test header",
                UrlAction::Header,
                "http://b.test",
            ),
        ];
        for (line, action, replacement) in cases {
            assert_eq!(rewrite(line), (action, replacement.to_string()), "{line}");
        }
    }

    #[test]
    fn url_rewrite_rejects_bad_lines() {
        for line in [
            "^a",
            "^a b c d",
            "^a b nope",
            "^a _ 302",
            "(unclosed b",
            "^a \"b",
        ] {
            assert!(parse_url_rewrite(line).is_err(), "{line}");
        }
    }

    fn rewrite_with<'r>(
        rules: &'r Rules,
        url: &str,
        head: impl Fn() -> String,
    ) -> Option<(&'r UrlRewrite, String)> {
        rules.rewrite_url(url, &Heads::new(Some(&head), None))
    }

    fn local(line: &str, resources: &Path) -> Result<MapLocal, LineError> {
        parse_map_local(line, resources, false).map(|(rule, _)| rule)
    }

    fn rules_with(urls: &[&str]) -> Rules {
        let mut rules = Rules::default();
        for line in urls {
            rules.url_rewrites.push(parse_url_rewrite(line).unwrap());
        }
        rules
    }

    #[test]
    fn rewrite_url_replaces_the_match_and_stops_at_the_first_rule() {
        let rules = rules_with(&[
            r"^http://www\.a\.test http://www.b.test",
            r"^http://www\.a\.test _ reject",
            r"^https://a\.test/(\w+)/(\d+) https://b.test/$2/$1 302",
        ]);
        let (rule, replaced) =
            rewrite_with(&rules, "http://www.a.test/search?q=x", String::new).unwrap();
        assert_eq!(rule.action, UrlAction::Header);
        assert_eq!(replaced, "http://www.b.test/search?q=x");
        let (_, replaced) = rewrite_with(&rules, "https://a.test/item/42", String::new).unwrap();
        assert_eq!(replaced, "https://b.test/42/item");
        assert!(rewrite_with(&rules, "https://c.test/", String::new).is_none());
    }

    #[test]
    fn url_and_header_checks_the_head_after_the_url() {
        let rules = rules_with(&[
            r"^http:\/\/.+\/amdc\/mobileDispatch %E8%8F%9C%E9%B8%9F%E8%A3%B9%E8%A3%B9* url-and-header reject",
            r#"^http://example\.com/resource1/1/ "\r\nUser-Agent: example-agent" url-and-header reject-dict"#,
            r"^http://example\.com/resource1/1/ ^POST url-and-header 302 http://example.com/post",
        ]);
        let head = |method: &str, agent: &str| {
            let text = format!(
                "{method} /amdc/mobileDispatch HTTP/1.1\r\nHost: a.test\r\nUser-Agent: {agent}\r\n\r\n"
            );
            move || text.clone()
        };
        let cainiao = "%E8%8F%9C%E9%B8%9F%E8%A3%B9%E8%A3%B9/8.8.1 CFNetwork/1410";
        let (rule, _) = rewrite_with(
            &rules,
            "http://1.2.3.4/amdc/mobileDispatch",
            head("GET", cainiao),
        )
        .unwrap();
        assert_eq!(rule.action, UrlAction::Reject);
        assert!(
            rewrite_with(
                &rules,
                "http://1.2.3.4/amdc/mobileDispatch",
                head("GET", "Other/1")
            )
            .is_none()
        );
        let url = "http://example.com/resource1/1/x";
        let (rule, _) = rewrite_with(&rules, url, head("GET", "example-agent")).unwrap();
        assert_eq!(rule.action, UrlAction::RejectDict);
        let (rule, replaced) = rewrite_with(&rules, url, head("POST", "curl")).unwrap();
        assert_eq!(
            (rule.action, replaced.as_str()),
            (UrlAction::Redirect302, "http://example.com/postx")
        );
        assert!(rewrite_with(&rules, url, head("GET", "curl")).is_none());
        let unbuilt = || -> String { panic!("the head is built only after the URL matches") };
        assert!(rewrite_with(&rules, "https://other.test/", unbuilt).is_none());
        for line in [r"^a ^POST url-and-header", r"^a (bad url-and-header reject"] {
            assert!(parse_url_rewrite(line).is_err(), "{line}");
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn header_rewrite_actions() {
        let lines = [
            r"http-request ^https://a\.test header-add X-Added one",
            r"^https://a\.test header-add User-Agent Mozilla/5.0 (iPhone; CPU OS 18_0)",
            r"http-request ^https://a\.test header-del Cookie",
            r"http-request ^https://a\.test header-replace Accept text/html",
            r"http-request ^https://a\.test header-replace Missing value",
            r"http-request ^https://a\.test header-replace-regex Referer http https",
            r"http-response ^https://a\.test header-del Set-Cookie",
        ];
        let mut rules = Rules::default();
        for line in lines {
            rules
                .header_rewrites
                .push(parse_header_rewrite(line).unwrap_or_else(|e| panic!("{line}: {e}")));
        }
        let mut header = headers(&[
            ("cookie", "a=b"),
            ("accept", "*/*"),
            ("referer", "http://a.test/x"),
            ("set-cookie", "c=d"),
        ]);
        let picked = rules.header_rewrites_for("https://a.test/", false, &Heads::new(None, None));
        assert_eq!(
            picked
                .into_iter()
                .filter(|rule| rule.apply(&mut header))
                .count(),
            5
        );
        let get = |name: &str| {
            header
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(get("x-added").as_deref(), Some("one"));
        assert_eq!(
            get("user-agent").as_deref(),
            Some("Mozilla/5.0 (iPhone; CPU OS 18_0)")
        );
        assert_eq!(get("accept").as_deref(), Some("text/html"));
        assert_eq!(get("referer").as_deref(), Some("https://a.test/x"));
        assert_eq!(get("set-cookie").as_deref(), Some("c=d"));
        assert_eq!(get("cookie"), None);
        assert_eq!(header.len(), 5);
    }

    #[test]
    fn head_conditions_read_each_head_once_and_only_past_the_url() {
        let lines = [
            r"http-response ^https://a\.test/ response-head ^HTTP/\S+\s200\s request-head ^POST\s header-add X-A 1",
            r"http-response ^https://a\.test/ request-head ^POST\s header-add X-B 1",
            r"http-response ^https://b\.test/ request-head ^GET header-add X-C 1",
            r"http-response ^https://a\.test/ header-del X-D",
        ];
        let mut rules = Rules::default();
        for line in lines {
            rules
                .header_rewrites
                .push(parse_header_rewrite(line).unwrap_or_else(|e| panic!("{line}: {e}")));
        }
        let built = std::cell::Cell::new(0);
        let picked = |request: &str, response: &str| {
            let request = || {
                built.set(built.get() + 1);
                request.to_string()
            };
            let response = || response.to_string();
            rules
                .header_rewrites_for(
                    "https://a.test/x",
                    true,
                    &Heads::new(Some(&request), Some(&response)),
                )
                .len()
        };
        assert_eq!(
            picked("POST /x HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"),
            3
        );
        assert_eq!(
            built.get(),
            1,
            "two conditions on the request head read it once"
        );
        assert_eq!(
            picked("POST /x HTTP/1.1\r\n\r\n", "HTTP/2.0 404 Not Found\r\n\r\n"),
            2
        );
        assert_eq!(
            picked("GET /x HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"),
            1
        );
        assert_eq!(
            rules
                .header_rewrites_for("https://a.test/x", true, &Heads::new(None, None))
                .len(),
            3,
            "a head not known yet lets its condition pass"
        );
        built.set(0);
        let request = || {
            built.set(built.get() + 1);
            String::new()
        };
        rules.header_rewrites_for("https://c.test/", true, &Heads::new(Some(&request), None));
        assert_eq!(
            built.get(),
            0,
            "no rule matched the URL, so no head is written"
        );
    }

    #[test]
    fn head_conditions_and_whole_head_rewrites_parse() {
        let rule = parse_header_rewrite(
            r#"^https://a\.test/ header-text-replace "(\r\n)User-Agent:[^\r]*(\r\n)" "$1User-Agent: app$2""#,
        )
        .unwrap();
        assert!(rule.whole_head().is_some());
        assert!(!rule.apply(&mut HeaderMap::new()));
        for line in [
            r"http-request ^a response-head x header-add X 1",
            r"http-response ^a request-head",
            r"http-response ^a request-head a request-head b header-del X",
            r"http-response ^a request-head ( header-del X",
            r"^a header-text-replace only",
            r"^a header-text-replace a b c",
        ] {
            assert!(parse_header_rewrite(line).is_err(), "{line}");
        }
        let body = parse_body_rewrite(r"http-response ^a request-head ^POST\s a b").unwrap();
        assert!(body.conditions.request.is_some());
        let jq = parse_body_rewrite(
            r#"http-response-jq ^a response-head "^HTTP/\S+ 200 " request-head ^POST '.ad = false'"#,
        )
        .unwrap();
        assert!(jq.conditions.response.is_some() && jq.conditions.request.is_some());
        assert_eq!(jq.apply(r#"{"ad":true}"#.to_string()), r#"{"ad":false}"#);
        for line in [
            r"http-request ^a response-head x a b",
            r"http-response ^a request-head x",
            r"http-request-jq ^a response-head x '.a'",
        ] {
            assert!(parse_body_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn local_answers_read_a_request_head_condition() {
        let nowhere = Path::new("/nonexistent-resources");
        let mut rules = Rules::default();
        rules.map_locals.push(
            local(
                r#"^https://a\.test/ request-head ^POST\s data-type=text data="{}""#,
                nowhere,
            )
            .unwrap(),
        );
        let post = || "POST / HTTP/1.1\r\n\r\n".to_string();
        let get = || "GET / HTTP/1.1\r\n\r\n".to_string();
        assert!(
            rules
                .map_local("https://a.test/", &Heads::new(Some(&post), None))
                .is_some()
        );
        assert!(
            rules
                .map_local("https://a.test/", &Heads::new(Some(&get), None))
                .is_none()
        );
        for line in [
            r"^a response-head x data-type=text data=x",
            r"^a request-head x",
        ] {
            assert!(local(line, nowhere).is_err(), "{line}");
        }
        assert!(
            parse_map_local(r"^a data-type=text data=x status-code=500", nowhere, true).is_err()
        );
        assert!(parse_map_local(r"^a data-type=text data=x", nowhere, true).is_ok());
    }

    #[test]
    fn header_rewrite_keeps_framing_headers() {
        for line in [
            r"^https://a\.test header-del Content-Length",
            r"http-response ^https://a\.test header-replace transfer-encoding chunked",
        ] {
            assert!(parse_header_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn body_rewrite_chains_pairs() {
        let rule = parse_body_rewrite(
            r#"http-response ^https://a\.test "\"ad\":true" "\"ad\":false" ^line$ replaced"#,
        )
        .unwrap();
        let got = rule.apply("{\"ad\":true}\nline\nkeep line".to_string());
        assert_eq!(got, "{\"ad\":false}\nreplaced\nkeep line");
        for line in [
            "http-response ^a only",
            "http-response-jq ^a '.a ='",
            "http-response-jq ^a",
            "sideways ^a b c",
        ] {
            assert!(parse_body_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_parameters() {
        let nowhere = Path::new("/nonexistent-resources");
        let rule = local(
            r#"^https://a\.test/json data-type=text data="{\"ok\":1}" status-code=500 header="Content-Type:application/json|X-A:b""#,
            nowhere,
        )
        .unwrap();
        assert_eq!(rule.body.bytes(), br#"{"ok":1}"#);
        assert_eq!(rule.status.as_u16(), 500);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        assert_eq!(rule.header.get("x-a").unwrap(), "b");
        let gif = local(r"^https://a\.test/gif data-type=tiny-gif", nowhere).unwrap();
        assert_eq!(gif.header.get("content-type").unwrap(), "image/gif");
        assert!(!gif.body.bytes().is_empty());
        let encoded = local(
            r#"^https://a\.test/b data-type=base64 data="dGVzdA==" header=WC1COiBj"#,
            nowhere,
        )
        .unwrap();
        assert_eq!(encoded.body.bytes(), b"test");
        assert_eq!(encoded.header.get("x-b").unwrap(), "c");
        for line in [
            r#"^https://a\.test/x data="missing.json""#,
            r"^https://a\.test/x data-type=text status-code=99",
            r"^https://a\.test/x data-type=base64 data=%%%",
            r"^https://a\.test/x novalue",
        ] {
            assert!(local(line, nowhere).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_keeps_a_file_of_one_piece_in_memory_and_leaves_a_larger_one_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small"), vec![b's'; LOCAL_PIECE]).unwrap();
        std::fs::write(dir.path().join("large"), vec![b'l'; LOCAL_PIECE + 1]).unwrap();

        let small = local(r#"^https://a\.test/x data="small""#, dir.path()).unwrap();
        assert_eq!(small.body.bytes().len(), LOCAL_PIECE);
        let large = local(r#"^https://a\.test/x data="large""#, dir.path()).unwrap();
        assert!(
            matches!(&large.body, LocalBody::File(path) if *path == dir.path().join("large")),
            "{:?}",
            large.body
        );
    }

    #[test]
    fn a_file_is_hashed_piece_by_piece_and_a_large_map_local_file_not_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..LOCAL_PIECE * 3 + 7)
            .map(|at| (at % 251) as u8)
            .collect();
        std::fs::write(dir.path().join("large"), &content).unwrap();
        std::fs::write(dir.path().join("small"), b"small").unwrap();
        let whole: [u8; 32] = Sha256::digest(&content).into();
        assert_eq!(
            resource_digest(dir.path(), "large"),
            Ok(ResourceSeen::Content(whole))
        );
        assert_eq!(
            local_file_seen(dir.path(), "large"),
            Ok(ResourceSeen::ReadAtAnswer)
        );
        assert_eq!(
            local_file_seen(dir.path(), "small"),
            Ok(ResourceSeen::Content(Sha256::digest(b"small").into()))
        );
        assert!(local_file_seen(dir.path(), "gone").is_err());
    }

    #[test]
    fn map_local_serves_files_from_the_resources_directory_only() {
        let home = tempfile::tempdir().unwrap();
        let resources = home.path().join("resources");
        std::fs::create_dir_all(resources.join("sub")).unwrap();
        std::fs::write(resources.join("a.json"), br#"{"ok":1}"#).unwrap();
        std::fs::write(resources.join("sub/b"), b"raw").unwrap();
        std::fs::write(home.path().join("secret.txt"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(home.path().join("secret.txt"), resources.join("link.txt"))
            .unwrap();

        let rule = local(r#"^https://a\.test/x data="a.json""#, &resources).unwrap();
        assert_eq!(rule.body.bytes(), br#"{"ok":1}"#);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        let rule = local(
            r#"^https://a\.test/x data-type=file data="sub/b" header="Content-Type:text/x""#,
            &resources,
        )
        .unwrap();
        assert_eq!(rule.body.bytes(), b"raw");
        assert_eq!(rule.header.get("content-type").unwrap(), "text/x");

        let via_parent = local(
            r#"^https://a\.test/x data-type=file data="sub/../a.json""#,
            &resources,
        )
        .unwrap();
        assert_eq!(via_parent.body.bytes(), br#"{"ok":1}"#);

        #[cfg(unix)]
        {
            std::fs::hard_link(resources.join("a.json"), resources.join("hard.json")).unwrap();
            let hard = local(
                r#"^https://a\.test/x data-type=file data="hard.json""#,
                &resources,
            )
            .unwrap();
            assert_eq!(hard.body.bytes(), br#"{"ok":1}"#);

            std::os::unix::fs::symlink(resources.join("sub"), resources.join("dirlink")).unwrap();
            let via_link = local(
                r#"^https://a\.test/x data-type=file data="dirlink/b""#,
                &resources,
            )
            .unwrap();
            assert_eq!(via_link.body.bytes(), b"raw");
        }

        let secret = home.path().join("secret.txt").display().to_string();
        for data in [
            "../secret.txt",
            "sub/../../secret.txt",
            &secret,
            r"sub\b",
            "link.txt",
            "sub",
            "",
        ] {
            let line = format!(r#"^https://a\.test/x data-type=file data="{data}""#);
            let err = local(&line, &resources).expect_err(data);
            assert!(
                !err.message.contains(&resources.display().to_string()),
                "{data}: {err}"
            );
            assert_eq!(
                err.kind,
                concord_config::mitm::IssueKind::Resource,
                "{data}"
            );
        }
    }
}

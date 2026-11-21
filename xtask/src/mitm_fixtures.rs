//! Holds MITM and module sources, tests and fixtures to names nobody owns. A host in a tracked file
//! whose path has `mitm` or `module` in it must be a reserved name (`a.test`, `example.com`) unless
//! `xtask/mitm-hosts.txt` lists the path, the host and the reason; in Rust only string literals and
//! comments are read. The marks published third-party modules carry and the notices that come with
//! them (`SOURCES.md`, `LICENSE-*` under test data) fail anywhere in that scope.

use std::path::Path;
use std::process::Command;

const SELF: &str = "xtask/src/mitm_fixtures.rs";
const ALLOW_FILE: &str = "xtask/mitm-hosts.txt";

const TLDS: &[&str] = &[
    "com", "net", "org", "cn", "io", "tv", "me", "co", "cc", "info", "biz", "app", "dev", "xyz",
    "top", "site", "online", "jp", "hk", "tw", "kr", "uk", "de", "ru", "fr", "sg", "us", "ca",
    "au", "im", "gg", "link", "cloud", "fun", "live", "shop", "club", "tech", "store", "ws", "la",
    "edu", "gov", "asia", "pro", "ink", "work", "art", "wang", "ltd", "xin", "eu",
];
const RESERVED_TLDS: &[&str] = &["test", "example", "invalid", "localhost", "local"];
const RESERVED_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];

/// Authors and channels the headers of published third-party modules carry.
const MARKERS: &[&str] = &[
    "fmz200",
    "chavyleung",
    "zirawell",
    "kokoryh",
    "luestr",
    "app2smile",
    "maasea",
    "keywos",
    "blackmatrix7",
    "ifflagged",
    "ddgksf2013",
    "lodepuly",
    "wool_scripts",
    "tg-channel",
    "tg-group",
    "可莉",
    "奶思",
];

struct Allowed {
    path: String,
    host: String,
}

fn is_scoped(path: &str) -> bool {
    !path.starts_with("vendor/")
        && path.split('/').any(|part| {
            let part = part.to_ascii_lowercase();
            part.contains("mitm") || part.contains("module")
        })
}

fn is_notice(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.contains("tests/data/") && (name == "SOURCES.md" || name.starts_with("LICENSE"))
}

fn read_allowed(text: &str) -> Result<Vec<Allowed>, String> {
    let mut allowed = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (entry, why) = line.split_once('#').unwrap_or((line, ""));
        let mut words = entry.split_whitespace();
        match (words.next(), words.next(), words.next(), why.trim()) {
            (Some(path), Some(host), None, why) if !why.is_empty() => allowed.push(Allowed {
                path: path.to_string(),
                host: host.to_ascii_lowercase(),
            }),
            _ => {
                return Err(format!(
                    "{ALLOW_FILE}:{}: write `<path> <host> # why`",
                    index + 1
                ));
            }
        }
    }
    Ok(allowed)
}

/// The string literals and comments of Rust `source`, each with the byte it starts at.
fn rust_texts(source: &str) -> Vec<(usize, &str)> {
    let bytes = source.as_bytes();
    let mut texts = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &source[i..];
        if rest.starts_with("//") {
            let end = rest.find('\n').map_or(source.len(), |n| i + n);
            texts.push((i, &source[i..end]));
            i = end;
        } else if rest.starts_with("/*") {
            let end = rest[2..].find("*/").map_or(source.len(), |n| i + 2 + n);
            texts.push((i, &source[i..end]));
            i = end + 2;
        } else if let Some(hashes) = raw_string_hashes(source, i) {
            let open = i + 2 + hashes;
            let close = format!("\"{}", "#".repeat(hashes));
            let end = source[open..]
                .find(&close)
                .map_or(source.len(), |n| open + n);
            texts.push((i, &source[open..end]));
            i = end + close.len();
        } else if bytes[i] == b'"' {
            let mut end = i + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            let end = end.min(bytes.len());
            texts.push((i, &source[i + 1..end]));
            i = end + 1;
        } else if bytes[i] == b'\'' {
            i += char_literal_len(rest).unwrap_or(1);
        } else {
            i += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    texts
}

/// The `#`s of a raw string `r#"…"#` that starts at `at`, if one does.
fn raw_string_hashes(source: &str, at: usize) -> Option<usize> {
    let rest = source[at..].strip_prefix('r')?;
    let before = source[..at].chars().next_back();
    if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let hashes = rest.len() - rest.trim_start_matches('#').len();
    rest[hashes..].starts_with('"').then_some(hashes)
}

/// The length of a char literal at the start of `rest`; a lifetime is not one.
fn char_literal_len(rest: &str) -> Option<usize> {
    let body = &rest[1..];
    let len = if let Some(escaped) = body.strip_prefix('\\') {
        let first = escaped.chars().next()?.len_utf8();
        1 + first + escaped[first..].find('\'')?
    } else {
        body.chars().next()?.len_utf8()
    };
    (body.as_bytes().get(len) == Some(&b'\'')).then_some(len + 2)
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

/// A dotted name ending in a top-level domain, from a run of name characters.
fn host_of(run: &str) -> Option<String> {
    let name = run.trim_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    let valid = labels.len() > 1
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    (valid && TLDS.contains(labels.last()?)).then(|| name.to_string())
}

/// Each host in `text`, with regex and string escapes before its dots undone, and each one a
/// regex group of labels such as `(api|cdn)\.a\.com` spells out.
fn hosts_in(text: &str) -> Vec<String> {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && matches!(chars.peek(), Some('\\' | '.')) {
            continue;
        }
        plain.push(c.to_ascii_lowercase());
    }
    let plain = plain.replace("[.]", ".");
    let bytes = plain.as_bytes();
    let mut hosts = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !is_name_byte(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_name_byte(bytes[end]) {
            end += 1;
        }
        let braced = (start > 0 && matches!(bytes[start - 1], b'{' | b'}'))
            || bytes.get(end).is_some_and(|b| matches!(b, b'{' | b'}'));
        if !braced && let Some(host) = host_of(&plain[start..end]) {
            hosts.push(host);
        }
        start = end;
    }
    for (at, _) in plain.match_indices(").") {
        let Some(open) = plain[..at].rfind('(') else {
            continue;
        };
        let group = plain[open + 1..at].trim_start_matches("?:");
        if group.is_empty()
            || !group
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"|-".contains(&b))
        {
            continue;
        }
        let tail = &plain[at + 2..];
        let len = tail.bytes().take_while(|b| is_name_byte(*b)).count();
        let Some(suffix) = host_of(&format!("x.{}", &tail[..len])) else {
            continue;
        };
        for label in group.split('|') {
            hosts.push(format!("{label}{}", &suffix[1..]));
        }
    }
    hosts
}

fn is_reserved(host: &str) -> bool {
    let tld = host.rsplit('.').next().unwrap_or(host);
    RESERVED_TLDS.contains(&tld)
        || RESERVED_DOMAINS
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

fn passes(host: &str, path: &str, allowed: &[Allowed]) -> bool {
    is_reserved(host)
        || allowed.iter().any(|entry| {
            entry.path == path
                && (host == entry.host || host.ends_with(&format!(".{}", entry.host)))
        })
}

fn file_problems(path: &str, source: &str, allowed: &[Allowed]) -> Vec<String> {
    let mut problems = Vec::new();
    let texts = if path.ends_with(".rs") {
        rust_texts(source)
    } else {
        vec![(0, source)]
    };
    for (start, text) in texts {
        let first = source[..start].matches('\n').count() + 1;
        for (index, line) in text.lines().enumerate() {
            for host in hosts_in(line) {
                if !passes(&host, path, allowed) {
                    problems.push(format!(
                        "{path}:{}: `{host}` is a real host; use a reserved name such as a.test or \
                         example.com, or list it in {ALLOW_FILE} with the reason",
                        first + index
                    ));
                }
            }
        }
    }
    let lower = source.to_lowercase();
    for marker in MARKERS {
        if let Some(at) = lower.find(marker) {
            problems.push(format!(
                "{path}:{}: `{marker}` marks a published third-party module; write a neutral \
                 sample instead",
                lower[..at].matches('\n').count() + 1
            ));
        }
    }
    problems
}

fn tracked(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(output.status.success(), "git ls-files failed");
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect()
}

fn check(root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join(ALLOW_FILE))
        .map_err(|err| format!("{ALLOW_FILE}: {err}"))?;
    let allowed = read_allowed(&text)?;
    let mut problems = Vec::new();
    let mut read = Vec::new();
    for path in tracked(root) {
        if path == SELF || path == ALLOW_FILE || !is_scoped(&path) {
            continue;
        }
        if is_notice(&path) {
            problems.push(format!("{path}: test data carries no third-party notices"));
            continue;
        }
        let Ok(source) = std::fs::read_to_string(root.join(&path)) else {
            continue;
        };
        problems.extend(file_problems(&path, &source, &allowed));
        read.push(path);
    }
    for entry in &allowed {
        if !read.contains(&entry.path) {
            problems.push(format!(
                "{ALLOW_FILE} names {}, which the check does not read",
                entry.path
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(source: &str) -> Vec<String> {
        file_problems("crates/mitm/src/x.rs", source, &[])
    }

    #[test]
    fn mitm_sources_and_fixtures_hold_only_reserved_hosts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn reserved_hosts_and_code_that_only_looks_like_one_pass() {
        let source = r##"
            let app = self.app; let c = 'a'; fn f<'a>(x: &'a str) {}
            let module = r#"hostname = a.test, *.example.com, api.example.net, b.localhost
            ^https?:\/\/a\.test\/ad reject"#;
            let url = format!("https://www.site{n}.test/");
        "##;
        assert_eq!(problems(source), Vec::<String>::new());
    }

    #[test]
    fn a_real_host_is_reported_in_a_string_a_regex_or_a_comment() {
        assert_eq!(
            problems(r#"let a = "DOMAIN,ads.real.com,REJECT";"#).len(),
            1
        );
        assert_eq!(
            problems(r#"let a = r"^https:\/\/api\.real\.cn\/ad";"#).len(),
            1
        );
        assert_eq!(
            problems(r#"let a = "^https:\\/\\/api\\.real\\.cn";"#).len(),
            1
        );
        assert_eq!(problems("// from https://raw.real.io/x.sgmodule").len(), 1);
        assert_eq!(
            problems(r#"let a = "always-real-ip = *.srv.real.net";"#).len(),
            1
        );
        let grouped = problems(r#"let a = r"^https:\/\/(api|cdn)\.real\.com\/";"#).join("\n");
        assert!(grouped.contains("`api.real.com`") && grouped.contains("`cdn.real.com`"));
    }

    #[test]
    fn a_listed_host_passes_in_its_path_with_its_subdomains() {
        let allowed = read_allowed("crates/mitm/src/x.rs real.ws # a reason\n").unwrap();
        let source = r#"let a = "https://link.real.ws/x";"#;
        assert!(file_problems("crates/mitm/src/x.rs", source, &allowed).is_empty());
        assert_eq!(
            file_problems("crates/mitm/src/y.rs", source, &allowed).len(),
            1
        );
        assert!(read_allowed("crates/mitm/src/x.rs real.ws\n").is_err());
    }

    #[test]
    fn a_published_module_mark_or_notice_is_reported() {
        assert_eq!(problems(r##"let a = "#!author=fmz200";"##).len(), 1);
        assert!(is_notice("crates/config/tests/data/modules/LICENSE-x"));
        assert!(is_notice("crates/config/tests/data/modules/SOURCES.md"));
        assert!(is_scoped("crates/config/tests/data/modules/x.sgmodule"));
        assert!(!is_scoped("vendor/mitm/x.rs"));
    }
}

use std::borrow::Cow;
use std::fmt::Write as _;

use fancy_regex::{Assertion, Expr, Regex};
use regex_syntax::ast::{self, Ast, ClassSetItem, Flag, FlagsItemKind, GroupKind, Visitor};
use regex_syntax::hir::translate::Translator;
use regex_syntax::hir::{Class, Hir, HirKind};
use regex_syntax::utf8::Utf8Sequences;

use super::issue::{IssueKind, LineError};

const DELEGATE_NFA_SIZE_LIMIT: usize = 10 * 1024 * 1024;
#[cfg(target_pointer_width = "64")]
const BUILDER_STATE_BYTES: usize = 32;
#[cfg(not(target_pointer_width = "64"))]
const BUILDER_STATE_BYTES: usize = 16;
const TRANSITION_BYTES: usize = 8;
const STATE_ID_BYTES: usize = 4;

/// Returns the cooked `regex`-crate pattern iff `fancy-regex` delegates `source` wholly to
/// `regex-automata` with identical semantics (no lookaround, backreference, atomic group, etc.).
pub fn delegatable_regex(source: &str) -> Option<String> {
    parse_delegatable(source, false).map(|(cooked, _)| cooked)
}

/// Like [delegatable_regex], and additionally guarantees that `fancy_regex::Regex::new(source)`
/// stays within `regex-automata`'s default 10 MiB NFA size limit on both forward and reverse
/// Thompson NFAs so callers can skip eager `fancy_regex::Regex::new` validation without changing
/// compile-time error behavior.
pub fn delegatable_within_nfa_limit(source: &str) -> Option<String> {
    let (cooked, hir) = parse_delegatable(source, true)?;
    (nfa_memory_upper_bound(&hir) <= DELEGATE_NFA_SIZE_LIMIT).then_some(cooked)
}

fn parse_delegatable(source: &str, reject_zero_repeat: bool) -> Option<(String, Hir)> {
    let tree = Expr::parse_tree(source).ok()?;
    if !is_pure_regex(&tree.expr) || (reject_zero_repeat && has_zero_repeat(&tree.expr)) {
        return None;
    }
    let mut cooked = String::with_capacity(source.len());
    tree.expr.to_str(&mut cooked, 0);
    let hir = regex_syntax::parse(&cooked).ok()?;
    Some((cooked, hir))
}

/// Necessary for the HIR upper bound: `regex-syntax` folds `{0}` to `Hir::empty()` (`B` bytes),
/// whereas `fancy-regex` enables `enable_preserve_zero_rep_captures` (`Capture(Empty)` = `3*B`).
fn has_zero_repeat(expr: &Expr) -> bool {
    match expr {
        Expr::Repeat { hi: 0, .. } => true,
        Expr::Repeat { child, .. } => has_zero_repeat(child),
        Expr::Group(child) => has_zero_repeat(child),
        Expr::Concat(parts) | Expr::Alt(parts) => parts.iter().any(has_zero_repeat),
        _ => false,
    }
}

/// Strict upper bound on `regex_automata::nfa::thompson::Builder::memory_usage()` for compiling a
/// single pattern (covering both forward and non-shrunk reverse NFAs, `LiteralTrie`, and outer
/// unanchored prefix / implicit capture / match states).
fn nfa_memory_upper_bound(hir: &Hir) -> usize {
    hir_nfa_upper_bound(hir).saturating_add(8 * BUILDER_STATE_BYTES + 4 * STATE_ID_BYTES)
}

fn hir_nfa_upper_bound(hir: &Hir) -> usize {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => BUILDER_STATE_BYTES,
        HirKind::Literal(lit) => lit
            .0
            .len()
            .max(1)
            .saturating_mul(2 * BUILDER_STATE_BYTES + TRANSITION_BYTES + STATE_ID_BYTES),
        HirKind::Class(Class::Bytes(cls)) => (2 * BUILDER_STATE_BYTES)
            .saturating_add(cls.ranges().len().saturating_mul(TRANSITION_BYTES)),
        HirKind::Class(Class::Unicode(cls)) => {
            if cls.is_ascii() {
                return (2 * BUILDER_STATE_BYTES)
                    .saturating_add(cls.ranges().len().saturating_mul(TRANSITION_BYTES));
            }
            let mut bytes = 2 * BUILDER_STATE_BYTES;
            for range in cls.iter() {
                for seq in Utf8Sequences::new(range.start(), range.end()) {
                    bytes = bytes.saturating_add(
                        seq.len()
                            .saturating_mul(BUILDER_STATE_BYTES + TRANSITION_BYTES)
                            .saturating_add(STATE_ID_BYTES),
                    );
                }
            }
            bytes
        }
        HirKind::Capture(cap) => {
            (2 * BUILDER_STATE_BYTES).saturating_add(hir_nfa_upper_bound(&cap.sub))
        }
        HirKind::Concat(parts) => {
            if parts.is_empty() {
                return BUILDER_STATE_BYTES;
            }
            parts.iter().fold(0usize, |acc, part| {
                acc.saturating_add(hir_nfa_upper_bound(part))
            })
        }
        HirKind::Alternation(parts) => match parts.len() {
            0 => BUILDER_STATE_BYTES,
            1 => parts
                .first()
                .map_or(BUILDER_STATE_BYTES, hir_nfa_upper_bound),
            k => parts.iter().fold(
                (2 * BUILDER_STATE_BYTES).saturating_add(k.saturating_mul(STATE_ID_BYTES)),
                |acc, part| acc.saturating_add(hir_nfa_upper_bound(part)),
            ),
        },
        HirKind::Repetition(rep) => {
            let sub = hir_nfa_upper_bound(&rep.sub);
            match (rep.min, rep.max) {
                (0, Some(1)) => sub
                    .saturating_add(2 * BUILDER_STATE_BYTES)
                    .saturating_add(2 * STATE_ID_BYTES),
                (0, None) => sub
                    .saturating_add(3 * BUILDER_STATE_BYTES)
                    .saturating_add(4 * STATE_ID_BYTES),
                (1, None) => sub
                    .saturating_add(BUILDER_STATE_BYTES)
                    .saturating_add(2 * STATE_ID_BYTES),
                (min, None) => (min as usize)
                    .saturating_mul(sub)
                    .saturating_add(BUILDER_STATE_BYTES)
                    .saturating_add(2 * STATE_ID_BYTES),
                (min, Some(max)) if min == max => (min as usize).saturating_mul(sub),
                (min, Some(max)) => {
                    let opt = (max - min) as usize;
                    (max as usize)
                        .saturating_mul(sub)
                        .saturating_add(
                            opt.saturating_mul(BUILDER_STATE_BYTES + 2 * STATE_ID_BYTES),
                        )
                        .saturating_add(2 * BUILDER_STATE_BYTES)
                }
            }
        }
    }
}

fn is_pure_regex(expr: &Expr) -> bool {
    match expr {
        Expr::Empty | Expr::Any { .. } | Expr::Literal { .. } | Expr::Delegate { .. } => true,
        Expr::Assertion(assertion) => matches!(
            assertion,
            Assertion::StartText
                | Assertion::EndText
                | Assertion::StartLine { .. }
                | Assertion::EndLine { .. }
                | Assertion::WordBoundary
                | Assertion::NotWordBoundary
                | Assertion::LeftWordBoundary
                | Assertion::RightWordBoundary
        ),
        Expr::Concat(parts) | Expr::Alt(parts) => parts.iter().all(is_pure_regex),
        Expr::Group(sub) => is_pure_regex(sub),
        Expr::Repeat { child, .. } => is_pure_regex(child),
        _ => false,
    }
}

/// A line's regex as fancy-regex takes it. ICU (Apple's NSRegularExpression) and ECMAScript
/// read `\cX` as the control character X & 0x1F, which fancy-regex rejects as an escape.
pub fn regex_source(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains("\\c") {
        return Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('c') => match chars.next_if(char::is_ascii_alphabetic) {
                Some(letter) => {
                    let _ = write!(out, "\\x{:02X}", u32::from(letter) & 0x1F);
                }
                None => out.push_str("\\c"),
            },
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    Cow::Owned(out)
}

/// Checks a line's regex, building it only when [parses] refuses it, for fancy-regex's own
/// message: the rule that runs it builds its own on first use.
pub fn check_pattern(pattern: &str) -> Result<(), LineError> {
    compile(pattern)
}

/// The flag a body regex is compiled with, so that it matches line by line.
pub const MULTILINE: &str = "(?m)";

pub fn multiline(pattern: &str) -> String {
    format!("{MULTILINE}{pattern}")
}

/// As [check_pattern] for a body regex.
pub fn check_multiline(pattern: &str) -> Result<(), LineError> {
    compile(&multiline(pattern))
}

fn compile(source: &str) -> Result<(), LineError> {
    let source = regex_source(source);
    if parses(&source) {
        return Ok(());
    }
    Regex::new(&source)
        .map(drop)
        .map_err(|err| LineError::new(IssueKind::Pattern, err.to_string()))
}

/// Whether both parsers take a regex, as fancy-regex's source: parsing is a small part of
/// building one, and a module lists thousands. One they pass whose build still fails, past a
/// size limit, matches nothing.
pub fn parses(source: &str) -> bool {
    Expr::parse_tree(source).is_ok() && syntax_parses(&super::relax(source))
}

/// Whether `regex_syntax::parse` takes `source`. Its second step, from syntax tree to HIR, fails
/// only on a Unicode property it does not know or where Unicode mode is turned off, given the
/// crate's default features; it is most of the work, case folding above all, so a tree with
/// neither skips it.
pub(crate) fn syntax_parses(source: &str) -> bool {
    let Ok(tree) = ast::parse::Parser::new().parse(source) else {
        return false;
    };
    ast::visit(&tree, CannotFail).is_ok() || Translator::new().translate(source, &tree).is_ok()
}

/// Stops at the first part of a tree whose translation can fail.
struct CannotFail;

impl Visitor for CannotFail {
    type Output = ();
    type Err = ();

    fn finish(self) -> Result<(), ()> {
        Ok(())
    }

    fn visit_pre(&mut self, ast: &Ast) -> Result<(), ()> {
        let flags = match ast {
            Ast::ClassUnicode(_) => return Err(()),
            Ast::Flags(set) => &set.flags,
            Ast::Group(group) => match &group.kind {
                GroupKind::NonCapturing(flags) => flags,
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        let unicode = FlagsItemKind::Flag(Flag::Unicode);
        if flags.items.iter().any(|item| item.kind == unicode) {
            return Err(());
        }
        Ok(())
    }

    fn visit_class_set_item_pre(&mut self, item: &ClassSetItem) -> Result<(), ()> {
        match item {
            ClassSetItem::Unicode(_) => Err(()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both users put the cooked sources of a run of patterns into one `RegexSet`.
    #[test]
    fn a_delegated_pattern_matches_in_a_set_as_fancy_regex_matches_it() {
        let patterns = [
            r"(?i)^https://a\.test/path",
            r"(?i)kelvin",
            r"(?i)ſtart",
            r"(?i)STRASSE",
            r"(?i:é)T",
            r"(?i)[a-c]+x",
            r"(?m)^second",
            r"(?m)line$",
            r"^line2",
            r"line1$",
            r"(?m)\Aline1",
            r"(?m)line2\z",
            r"(?s)path.second",
            r"path.second",
            r"(?ms)^line1.line2$",
            r"(?m)^$",
            r"(?mR)^line2$",
            r"\bbar\b",
            r"\Bbar",
            r"\b{start}foo",
            r"foo\b{end}",
            r"\b{start}bar\b{end}",
            r"\w+é",
            r"(?x) a \. test  # comment",
            r"\d{2,}",
            r"\h+",
            r"\H+",
            r"(?i)\h+",
            r"(?i)\H+",
            r"(?i)\p{Lu}",
            r"(?i)\p{Lu}+",
            r"\N+",
            r"(?s)a\Nb",
            r"a\Ob",
            r"\O+",
            r"(?R)a.b",
            r"(?sR)a.b",
            r"(?U)a.+b",
            r"(?U)a.+?b",
            r"(?x)[a b]+",
            r"(?x)[a\tb]",
        ];
        let texts = [
            "https://a.test/path\nsecond line",
            "HTTPS://A.TEST/PATH",
            "https://a.test/\u{212A}elvin",
            "KELVIN",
            "START",
            "strasse",
            "ÉT",
            "ABCX",
            "line1\nline2\n",
            "line1\r\nline2\r\n",
            "line1\n\nline2",
            "foo bar",
            "foobar",
            "barfoo bar_",
            "café",
            "a.test",
            "12",
            "",
            "09afAF",
            "gGzZ",
            " \t",
            "a",
            "A",
            "é",
            "É",
            "ß",
            "a\nb",
            "a\rb",
            "a\r\nb",
            "axb",
            "ab",
            "axxb",
            "a b",
            "a\tb",
        ];
        let left: Vec<&str> = patterns
            .iter()
            .filter(|source| delegatable_regex(source).is_none())
            .copied()
            .collect();
        assert!(left.is_empty(), "not delegated: {left:?}");
        assert_eq!(delegatable_regex(r"(?-u:\w)+"), None);
        let cooked: Vec<String> = patterns
            .iter()
            .filter_map(|source| delegatable_regex(source))
            .collect();
        let set = regex::RegexSet::new(&cooked).unwrap();
        let fancy: Vec<fancy_regex::Regex> = patterns
            .iter()
            .map(|source| fancy_regex::Regex::new(source).unwrap())
            .collect();
        for text in texts {
            let in_set = set.matches(text);
            for (at, (source, regex)) in patterns.iter().zip(&fancy).enumerate() {
                assert_eq!(
                    in_set.matched(at),
                    regex.is_match(text).unwrap(),
                    "{source} on {text:?}"
                );
            }
        }
    }

    #[test]
    fn a_control_escape_compiles() {
        check_pattern(r"(?i:^https?:\/\/res\.a\.test\/ad.\cnews\/)").unwrap();
        check_pattern(r"[\cA-\cZ]").unwrap();
        check_multiline(r"^\cJ").unwrap();
    }

    #[test]
    fn a_syntax_tree_reads_as_regex_syntax_reads_it() {
        for source in [
            r"(?i)^https?:\/\/a\.test\/\w+[\s\S]*\d",
            r"(?i:[^x])(?-i)K",
            r"\p{Greek}\pL[\p{Lu}&&\P{Ll}]",
            r"\p{Nope}",
            r"[a\p{Nope}]",
            r"(?i)\pQ",
            r"(?-u)\xFF",
            r"(?-u:.)",
            r"(?i-u)[^a]",
            r"(?-u)[a-z]\w",
            r"(?u)\w",
            r"[[:alpha:]--[a-c]]",
            "(a",
            "[z-a]",
            r"\d{2,1}",
            r"(?<n>a)(?:b)",
        ] {
            let want = regex_syntax::parse(source).is_ok();
            assert_eq!(syntax_parses(source), want, "{source}");
        }
    }

    #[test]
    fn nfa_upper_bound_is_a_true_upper_bound_and_never_accepts_failing_fancy_regex() {
        let fixed = [
            r"^https?://([a-z0-9-]+\.)*ads0\.example\.com/",
            r"/api/v\d+/track42\?",
            r"(?i)\.example\.net/.*\.(gif|png)$",
            r"(?i)\p{Lu}+",
            r"\p{Greek}{2,5}",
            r"(?:\w{3,6}){2,4}",
            r"(foo|bar|baz|qux|quux){1,4}",
            r"[^\n\r]{1,20}",
            r"(?-u:[\x80-\xFF]+)",
            r"[ab]*[cd]*[ab]*",
            r"a*[bc]{0,3}a*",
            r"(?i)[ab]*[cd]*[ab]*",
            r"(?:a|ab|abc)",
            r"(?:foo|foobar|food)",
            r"(?:http|https|https://a|https://ab)",
            r"(a){0}",
            r"(?:\w{500}){500}",
            r"(?:a{1000}){1000}",
            r"^https://cdn\.test/(?!static/)",
            r"(",
            r"\p{Nope}",
        ];
        assert!(delegatable_within_nfa_limit(r"(?:\w{500}){500}").is_none());
        assert!(delegatable_within_nfa_limit(r"(?:a{1000}){1000}").is_none());
        assert!(delegatable_within_nfa_limit(r"(a){0}").is_none());
        assert!(delegatable_within_nfa_limit(r"^https://cdn\.test/(?!static/)").is_none());
        assert!(delegatable_within_nfa_limit("(").is_none());

        let atoms = [
            "a",
            "abc",
            "/",
            r"\.",
            r"\d",
            r"\w",
            r"\s",
            r"[a-z0-9-]",
            r"[^\n]",
            r"\p{Greek}",
            r"(?i)ab",
            r"(?i)\p{Lu}",
            r"(?-u:[a-z\x80-\xFF])",
            r"(foo|bar|baz)",
            r"(?:x|yy|zzz)",
            r"\b",
            "^",
            "$",
        ];
        let quantifiers = ["", "?", "*", "+", "{2}", "{1,4}", "{2,5}", "{3,8}"];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || -> usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as usize
        };

        let mut generated: Vec<String> = fixed.iter().map(|s| (*s).to_string()).collect();
        for _ in 0..320 {
            let parts = 1 + next() % 4;
            let mut pat = String::new();
            for _ in 0..parts {
                let atom = atoms[next() % atoms.len()];
                let q = quantifiers[next() % quantifiers.len()];
                if q.is_empty() || matches!(atom, r"\b" | "^" | "$") {
                    pat.push_str(atom);
                } else {
                    pat.push_str("(?:");
                    pat.push_str(atom);
                    pat.push(')');
                    pat.push_str(q);
                }
            }
            if next() % 5 == 0 {
                let outer_q = ["{2,3}", "{3,5}", "{1,4}", "*"][next() % 4];
                pat = format!("(?:{pat}){outer_q}");
            }
            generated.push(pat);
        }

        let mut accepted = 0usize;
        for source in &generated {
            let Some(cooked) = delegatable_within_nfa_limit(source) else {
                continue;
            };
            accepted += 1;
            assert!(
                Regex::new(source).is_ok(),
                "delegatable_within_nfa_limit accepted pattern rejected by fancy_regex: {source}"
            );
            let hir = regex_syntax::parse(&cooked).unwrap();
            let bound = nfa_memory_upper_bound(&hir);
            assert!(bound <= DELEGATE_NFA_SIZE_LIMIT);
            assert!(
                fancy_regex::RegexBuilder::new(source)
                    .delegate_size_limit(bound)
                    .build()
                    .is_ok(),
                "nfa_memory_upper_bound ({bound} B) underestimated fancy-regex delegate NFA for {source}"
            );
            assert!(
                regex::RegexBuilder::new(&cooked)
                    .size_limit(bound)
                    .build()
                    .is_ok(),
                "nfa_memory_upper_bound ({bound} B) underestimated actual NFA for {source}"
            );
        }
        assert!(
            accepted >= 250,
            "expected >= 250 accepted patterns, got {accepted}"
        );
    }

    /// Case folding and the Perl classes skip translation only while regex-syntax's
    /// `unicode-case` and `unicode-perl` features are on; without them translating these fails.
    #[test]
    fn case_folding_and_perl_classes_skip_translation_only_while_it_cannot_fail() {
        for source in [r"(?i)k\w\d\s", r"(?i:[a-z\w])", r"(?i)[^\d]\S\W\D"] {
            let tree = ast::parse::Parser::new().parse(source).unwrap();
            assert!(ast::visit(&tree, CannotFail).is_ok(), "{source}");
            let translated = Translator::new().translate(source, &tree);
            assert!(translated.is_ok(), "{source}: {translated:?}");
            assert!(syntax_parses(source), "{source}");
        }
    }
}

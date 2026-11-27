use std::borrow::Cow;
use std::fmt::Write as _;

use fancy_regex::{Assertion, Expr, Regex};
use regex_syntax::ast::{self, Ast, ClassSetItem, Flag, FlagsItemKind, GroupKind, Visitor};
use regex_syntax::hir::translate::Translator;

use super::issue::{IssueKind, LineError};

/// Returns the cooked `regex`-crate pattern iff `fancy-regex` delegates `source` wholly to
/// `regex-automata` with identical semantics (no lookaround, backreference, atomic group, etc.).
pub fn delegatable_regex(source: &str) -> Option<String> {
    let tree = Expr::parse_tree(source).ok()?;
    if !is_pure_regex(&tree.expr) {
        return None;
    }
    let mut cooked = String::with_capacity(source.len());
    tree.expr.to_str(&mut cooked, 0);
    regex_syntax::parse(&cooked).ok()?;
    Some(cooked)
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

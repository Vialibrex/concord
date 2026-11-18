use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use regex_syntax::hir::Look;
use regex_syntax::hir::literal::Extractor;

use super::Rules;
use crate::pattern::Pattern;

/// Which rules of a list a URL may match. A pattern anchored at the start whose literal
/// prefixes form a finite set is looked up by those prefixes; any other is tried every time.
/// It only narrows the list: each candidate's own pattern still decides.
#[derive(Debug)]
pub(crate) struct UrlIndex {
    prefixes: Option<AhoCorasick>,
    longest: usize,
    owners: Vec<usize>,
    always: Vec<usize>,
}

impl UrlIndex {
    pub(crate) fn new<'p>(patterns: impl IntoIterator<Item = Option<&'p Pattern>>) -> UrlIndex {
        let mut literals = Vec::new();
        let mut owners = Vec::new();
        let mut always = Vec::new();
        for (index, pattern) in patterns.into_iter().enumerate() {
            match pattern.and_then(|pattern| prefixes(pattern.source())) {
                Some(found) => {
                    owners.extend(std::iter::repeat_n(index, found.len()));
                    literals.extend(found);
                }
                None => always.push(index),
            }
        }
        let longest = literals.iter().map(Vec::len).max().unwrap_or(0);
        let prefixes = if literals.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&literals)
                .ok()
        };
        if prefixes.is_none() {
            always.append(&mut owners);
            always.sort_unstable();
            always.dedup();
        }
        UrlIndex {
            prefixes,
            longest,
            owners,
            always,
        }
    }

    /// In list order.
    pub(crate) fn candidates(&self, url: &str) -> Vec<usize> {
        let mut found = self.always.clone();
        if let Some(prefixes) = &self.prefixes {
            let head = url.get(..self.longest).unwrap_or(url);
            found.extend(
                prefixes
                    .find_overlapping_iter(head)
                    .filter(|hit| hit.start() == 0)
                    .filter_map(|hit| self.owners.get(hit.pattern().as_usize())),
            );
            found.sort_unstable();
            found.dedup();
        }
        found
    }

    #[cfg(test)]
    pub(crate) fn always(&self) -> &[usize] {
        &self.always
    }
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;

/// None when a match need not start with one of a finite set of literals.
fn prefixes(source: &str) -> Option<Vec<Vec<u8>>> {
    let hir = regex_syntax::parse(source).ok()?;
    if !hir.properties().look_set_prefix().contains(Look::Start) {
        return None;
    }
    let seq = Extractor::new().extract(&hir);
    let literals = seq.literals()?;
    if literals.is_empty() || literals.iter().any(|literal| literal.as_bytes().is_empty()) {
        return None;
    }
    Some(
        literals
            .iter()
            .map(|literal| literal.as_bytes().to_vec())
            .collect(),
    )
}

#[derive(Debug, Default)]
pub(crate) struct Indexes {
    url_rewrites: OnceLock<UrlIndex>,
    header_rewrites: OnceLock<UrlIndex>,
    body_rewrites: OnceLock<UrlIndex>,
    map_locals: OnceLock<UrlIndex>,
    request_mocks: OnceLock<UrlIndex>,
    scripts: OnceLock<UrlIndex>,
}

fn pick<'r, T>(
    slot: &OnceLock<UrlIndex>,
    rules: &'r [T],
    pattern: impl Fn(&T) -> Option<&Pattern>,
    url: &str,
) -> impl Iterator<Item = &'r T> {
    slot.get_or_init(|| UrlIndex::new(rules.iter().map(pattern)))
        .candidates(url)
        .into_iter()
        .filter_map(|index| rules.get(index))
}

impl Rules {
    #[cfg(test)]
    pub(crate) fn index_of_url_rewrites(&self) -> &UrlIndex {
        let _ = self.url_rewrite_candidates("");
        self.indexes.url_rewrites.get().expect("built above")
    }

    /// Builds every list's index now, so that the first request does not.
    pub(crate) fn index(&self) {
        let _ = self.url_rewrite_candidates("");
        let _ = self.header_rewrite_candidates("");
        let _ = self.body_rewrite_candidates("");
        let _ = self.map_local_candidates("");
        let _ = self.request_mock_candidates("");
        let _ = self.script_candidates("");
    }

    pub(crate) fn url_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::UrlRewrite> {
        pick(
            &self.indexes.url_rewrites,
            &self.url_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn header_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::HeaderRewrite> {
        pick(
            &self.indexes.header_rewrites,
            &self.header_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn body_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &std::sync::Arc<super::BodyRewrite>> {
        pick(
            &self.indexes.body_rewrites,
            &self.body_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn map_local_candidates(&self, url: &str) -> impl Iterator<Item = &super::MapLocal> {
        pick(
            &self.indexes.map_locals,
            &self.map_locals,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn request_mock_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::MapLocal> {
        pick(
            &self.indexes.request_mocks,
            &self.request_mocks,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn script_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &std::sync::Arc<crate::script::Script>> {
        pick(
            &self.indexes.scripts,
            &self.scripts,
            |script| script.pattern(),
            url,
        )
    }
}

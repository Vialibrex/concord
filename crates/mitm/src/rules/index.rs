use std::collections::HashMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use concord_config::mitm::{ScriptKind, delegatable_regex, regex_source, relax};
use regex::RegexSet;
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use super::Rules;
use crate::pattern::Pattern;

/// Which rules of a list a URL may match. Each pattern is looked up by a few literals one of
/// which every match holds, the set that tells URLs apart best; when they start the pattern
/// after `^`, only at the start of the URL. Patterns without a discriminating literal are
/// grouped into a `RegexSet` when `fancy-regex` delegates them wholly to the `regex` engine;
/// only genuine backtracking/lookaround patterns without literals fall back to linear scan.
/// The index only narrows the list: each candidate's own pattern still decides.
#[derive(Debug)]
pub(crate) struct UrlIndex {
    /// Literals as written, and the ASCII-lowercased ones of case-insensitive patterns: an
    /// automaton that ignores case costs several times as much to build.
    exact: Option<Literals>,
    folded: Option<Literals>,
    regex_set: Option<RegexSet>,
    regex_set_owners: Vec<usize>,
    always_fancy: Vec<usize>,
    #[cfg(test)]
    no_literal: Vec<usize>,
}

/// Literals and, per literal, its rule and whether it has to start the URL.
type Gathered = (Vec<Vec<u8>>, Vec<(usize, bool)>);

#[derive(Debug)]
struct Literals {
    automaton: AhoCorasick,
    /// Per literal: the rule it stands for, and whether it has to start the URL.
    owners: Vec<(usize, bool)>,
}

impl Literals {
    fn build(literals: &[Vec<u8>], owners: Vec<(usize, bool)>, fold: bool) -> Option<Literals> {
        if literals.is_empty() {
            return None;
        }
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(fold)
            .build(literals)
            .ok()?;
        Some(Literals { automaton, owners })
    }

    fn collect(&self, url: &str, out: &mut Vec<usize>) {
        for hit in self.automaton.find_overlapping_iter(url) {
            if let Some(&(index, anchored)) = self.owners.get(hit.pattern().as_usize())
                && (!anchored || hit.start() == 0)
            {
                out.push(index);
            }
        }
    }

    #[cfg(test)]
    fn heap_bytes(&self) -> usize {
        self.automaton.memory_usage()
            + self.owners.capacity() * std::mem::size_of::<(usize, bool)>()
    }
}

impl UrlIndex {
    pub(crate) fn new<'p>(patterns: impl IntoIterator<Item = Option<&'p Pattern>>) -> UrlIndex {
        let mut literals: [Gathered; 2] = Default::default();
        let mut set_sources = Vec::new();
        let mut regex_set_owners = Vec::new();
        let mut always_fancy = Vec::new();
        #[cfg(test)]
        let mut no_literal = Vec::new();

        for (index, pattern) in patterns.into_iter().enumerate() {
            let Some(pattern) = pattern else {
                always_fancy.push(index);
                #[cfg(test)]
                no_literal.push(index);
                continue;
            };
            let source = regex_source(pattern.source());
            match lookup(&relax(&source)) {
                Some(Lookup {
                    found,
                    anchored,
                    folded,
                }) => {
                    let (into, owners) = &mut literals[usize::from(folded)];
                    owners.extend(std::iter::repeat_n((index, anchored), found.len()));
                    into.extend(found);
                }
                None => {
                    #[cfg(test)]
                    no_literal.push(index);
                    match delegatable_regex(&source) {
                        Some(cooked) => {
                            set_sources.push(cooked);
                            regex_set_owners.push(index);
                        }
                        None => always_fancy.push(index),
                    }
                }
            }
        }

        let [exact, folded] = [false, true].map(|fold| {
            let (found, owners) = std::mem::take(&mut literals[usize::from(fold)]);
            let unbuilt: Vec<usize> = owners.iter().map(|(index, _)| *index).collect();
            let built = Literals::build(&found, owners, fold);
            if built.is_none() {
                always_fancy.extend(unbuilt);
            }
            built
        });
        always_fancy.sort_unstable();
        always_fancy.dedup();

        let built_set = if set_sources.is_empty() {
            None
        } else {
            RegexSet::new(&set_sources).ok()
        };
        if built_set.is_none() && !regex_set_owners.is_empty() {
            always_fancy.append(&mut regex_set_owners);
            always_fancy.sort_unstable();
            always_fancy.dedup();
        }

        UrlIndex {
            exact,
            folded,
            regex_set: built_set,
            regex_set_owners,
            always_fancy,
            #[cfg(test)]
            no_literal,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_none()
            && self.folded.is_none()
            && self.regex_set.is_none()
            && self.always_fancy.is_empty()
    }

    /// In list order.
    #[cfg(test)]
    pub(crate) fn candidates(&self, url: &str) -> Vec<usize> {
        let mut found = Vec::new();
        self.collect_candidates(url, &mut found);
        found
    }

    /// Appends candidate indices in ascending list order without allocating when none match.
    pub(crate) fn collect_candidates(&self, url: &str, out: &mut Vec<usize>) {
        if self.is_empty() {
            return;
        }
        out.extend_from_slice(&self.always_fancy);
        if let Some(set) = &self.regex_set {
            for hit in set.matches(url) {
                if let Some(&index) = self.regex_set_owners.get(hit) {
                    out.push(index);
                }
            }
        }
        for literals in [&self.exact, &self.folded].into_iter().flatten() {
            literals.collect(url, out);
        }
        if out.len() > 1 {
            out.sort_unstable();
            out.dedup();
        }
    }

    #[cfg(test)]
    pub(crate) fn always(&self) -> &[usize] {
        &self.no_literal
    }

    #[cfg(test)]
    pub(crate) fn always_fancy(&self) -> &[usize] {
        &self.always_fancy
    }

    /// The rules looked up by literals as written (`folded` false) or ASCII-lowercased.
    #[cfg(test)]
    pub(crate) fn literal_owners(&self, folded: bool) -> Vec<usize> {
        let literals = if folded { &self.folded } else { &self.exact };
        let mut owners: Vec<usize> = literals
            .iter()
            .flat_map(|literals| literals.owners.iter().map(|(index, _)| *index))
            .collect();
        owners.dedup();
        owners
    }

    #[cfg(test)]
    pub(crate) fn regex_set_owners(&self) -> &[usize] {
        &self.regex_set_owners
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        [&self.exact, &self.folded]
            .into_iter()
            .flatten()
            .map(Literals::heap_bytes)
            .sum::<usize>()
            + self.regex_set_owners.capacity() * std::mem::size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod corpus_tests;

/// Literals a match must hold, and whether they are prefixes it must start with.
struct Lookup {
    found: Vec<Vec<u8>>,
    anchored: bool,
    /// The literals are ASCII-lowercased, to be looked up ignoring ASCII case.
    folded: bool,
}

/// More alternatives than this are cheaper to try than to look up.
const MOST: usize = 32;

fn lookup(source: &str) -> Option<Lookup> {
    let hir = regex_syntax::parse(source).ok()?;
    let anchored = hir.properties().look_set_prefix().contains(Look::Start);
    let folded = asks_case_insensitive(source);
    let (found, at_start) = required(&hir, folded)?;
    Some(Lookup {
        found,
        anchored: anchored && at_start,
        folded,
    })
}

/// Whether a group of `source` turns on the `i` flag. Either answer keeps every match: literals
/// as written still list each case a case-insensitive class allows, and folded ones are looked
/// up ignoring case.
fn asks_case_insensitive(source: &str) -> bool {
    source.match_indices("(?").any(|(at, _)| {
        source
            .get(at + 2..)
            .unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_alphabetic)
            .any(|flag| flag == 'i')
    })
}

/// The bytes of the weakest literal that tell one URL from another: nearly every URL has a
/// scheme (`http`/`https`) and `://`, so only what follows them counts.
fn strength(found: &[Vec<u8>]) -> usize {
    found
        .iter()
        .map(|literal| {
            let scheme = literal
                .windows(3)
                .rposition(|window| window == b"://")
                .map_or(0, |at| at + 3);
            let rest = &literal[scheme..];
            if scheme == 0 && (rest == b"http" || rest == b"https") {
                return 0;
            }
            rest.len()
        })
        .min()
        .unwrap_or(0)
}

fn fold_ascii_bytes(bytes: &[u8], fold: bool) -> Vec<u8> {
    if fold {
        bytes.iter().map(u8::to_ascii_lowercase).collect()
    } else {
        bytes.to_vec()
    }
}

/// Every string `hir` matches, ASCII-lowercased when `fold` (while keeping distinct non-ASCII
/// UTF-8 case-folding variants such as Kelvin sign `K` and long s `ſ` so the
/// ASCII-case-insensitive Aho-Corasick automaton remains a strict superset of Unicode regex
/// matches).
fn exact(hir: &Hir, fold: bool) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(vec![Vec::new()]),
        HirKind::Literal(literal) => Some(vec![fold_ascii_bytes(&literal.0, fold)]),
        HirKind::Class(class) => {
            let mut found: Vec<Vec<u8>> = Vec::new();
            match class {
                Class::Unicode(class) => {
                    for range in class.iter() {
                        for c in range.start()..=range.end() {
                            let mut buf = [0u8; 4];
                            let bytes = fold_ascii_bytes(c.encode_utf8(&mut buf).as_bytes(), fold);
                            if !found.contains(&bytes) {
                                found.push(bytes);
                                if found.len() > FEW {
                                    return None;
                                }
                            }
                        }
                    }
                }
                Class::Bytes(class) => {
                    for range in class.iter() {
                        for b in range.start()..=range.end() {
                            let lowered = if fold { b.to_ascii_lowercase() } else { b };
                            if !found.iter().any(|item| item.as_slice() == [lowered]) {
                                found.push(vec![lowered]);
                                if found.len() > FEW {
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
            Some(found)
        }
        HirKind::Capture(capture) => exact(&capture.sub, fold),
        HirKind::Repetition(repetition) if repetition.min == 0 && repetition.max == Some(1) => {
            let mut found = exact(&repetition.sub, fold)?;
            found.push(Vec::new());
            found.sort_unstable();
            found.dedup();
            Some(found)
        }
        HirKind::Alternation(branches) => {
            let mut found = Vec::new();
            for branch in branches {
                found.extend(exact(branch, fold)?);
            }
            found.sort_unstable();
            found.dedup();
            (found.len() <= MOST).then_some(found)
        }
        HirKind::Concat(parts) => parts.iter().try_fold(vec![Vec::new()], |found, part| {
            product(&found, &exact(part, fold)?)
        }),
        HirKind::Repetition(_) => None,
    }
}

/// Each of `left` followed by each of `right`, while they are at most [MOST].
fn product(left: &[Vec<u8>], right: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if left.len() * right.len() > MOST {
        return None;
    }
    let mut found = Vec::with_capacity(left.len() * right.len());
    for head in left {
        for tail in right {
            let mut literal = head.clone();
            literal.extend_from_slice(tail);
            found.push(literal);
        }
    }
    found.sort_unstable();
    found.dedup();
    Some(found)
}

/// Literals one of which every match of `hir` contains, the strongest set found, and whether
/// a match starts with them.
fn required(hir: &Hir, fold: bool) -> Option<(Vec<Vec<u8>>, bool)> {
    let usable = |found: &[Vec<u8>]| {
        !found.is_empty() && found.iter().all(|literal| !literal.is_empty()) && strength(found) > 0
    };
    if let Some(found) = exact(hir, fold).filter(|found| usable(found)) {
        return Some((found, true));
    }
    match hir.kind() {
        HirKind::Capture(capture) => required(&capture.sub, fold),
        HirKind::Repetition(repetition) if repetition.min >= 1 => required(&repetition.sub, fold),
        HirKind::Alternation(branches) => {
            let mut found = Vec::new();
            let mut at_start = true;
            for branch in branches {
                let (branch, start) = required(branch, fold)?;
                found.extend(branch);
                at_start &= start;
            }
            found.sort_unstable();
            found.dedup();
            (found.len() <= MOST && usable(&found)).then_some((found, at_start))
        }
        HirKind::Concat(parts) => {
            let mut best: Option<(Vec<Vec<u8>>, bool)> = None;
            let mut keep = |found: Vec<Vec<u8>>, at_start: bool| {
                if usable(&found)
                    && best
                        .as_ref()
                        .is_none_or(|(kept, _)| strength(&found) > strength(kept))
                {
                    best = Some((found, at_start));
                }
            };
            let mut run: Vec<Vec<u8>> = vec![Vec::new()];
            let mut run_at_start = true;
            for part in parts {
                if let Some(part_exact) = exact(part, fold) {
                    match product(&run, &part_exact) {
                        Some(longer) => run = longer,
                        None => {
                            keep(std::mem::replace(&mut run, part_exact), run_at_start);
                            run_at_start = false;
                        }
                    }
                    continue;
                }
                keep(std::mem::replace(&mut run, vec![Vec::new()]), run_at_start);
                if let Some((found, _)) = required(part, fold) {
                    keep(found, false);
                }
                run_at_start = false;
            }
            keep(run, run_at_start);
            best
        }
        _ => None,
    }
}

/// A character class of more than this many characters is not spelled out.
const FEW: usize = 10;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReqRuleRef {
    Header(u32),
    UrlRewrite(u32),
    MapLocal(u32),
    RequestMock(u32),
    Body(u32),
    Script(u32),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RespRuleRef {
    Header(u32),
    Body(u32),
    Script(u32),
}

/// Candidate rule indices found by one scan of the unified request-phase index.
#[derive(Debug, Default)]
pub(crate) struct RequestScan {
    pub(crate) headers: Vec<u32>,
    pub(crate) url_rewrites: Vec<u32>,
    pub(crate) map_locals: Vec<u32>,
    pub(crate) request_mocks: Vec<u32>,
    pub(crate) bodies: Vec<u32>,
    pub(crate) scripts: Vec<u32>,
}

/// URL-matched response-phase rules, shared between the pre-request body check and response phase.
#[derive(Debug, Default)]
pub(crate) struct ResponsePlan {
    pub(crate) headers: Vec<u32>,
    pub(crate) bodies: Vec<u32>,
    pub(crate) scripts: Vec<u32>,
    pub(crate) needs_sent_headers: bool,
}

#[derive(Debug)]
struct CompiledIndexes {
    req_index: UrlIndex,
    req_refs: Vec<ReqRuleRef>,
    resp_index: UrlIndex,
    resp_refs: Vec<RespRuleRef>,
    rule_scripts: HashMap<Box<str>, usize>,
    dns_scripts: HashMap<Box<str>, usize>,
    #[cfg(test)]
    per_kind: [UrlIndex; 6],
}

#[derive(Debug, Default)]
pub(crate) struct Indexes {
    compiled: OnceLock<CompiledIndexes>,
}

impl Rules {
    fn compiled(&self) -> &CompiledIndexes {
        self.indexes.compiled.get_or_init(|| self.build_indexes())
    }

    fn build_indexes(&self) -> CompiledIndexes {
        let mut req_refs = Vec::new();
        let mut req_patterns: Vec<Option<&Pattern>> = Vec::new();
        let mut resp_refs = Vec::new();
        let mut resp_patterns: Vec<Option<&Pattern>> = Vec::new();

        for (i, rule) in self.header_rewrites.iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            if rule.response {
                resp_refs.push(RespRuleRef::Header(idx));
                resp_patterns.push(Some(&rule.pattern));
            } else {
                req_refs.push(ReqRuleRef::Header(idx));
                req_patterns.push(Some(&rule.pattern));
            }
        }
        for (i, rule) in self.url_rewrites.iter().enumerate() {
            req_refs.push(ReqRuleRef::UrlRewrite(u32::try_from(i).unwrap_or(u32::MAX)));
            req_patterns.push(Some(&rule.pattern));
        }
        for (i, rule) in self.map_locals.iter().enumerate() {
            req_refs.push(ReqRuleRef::MapLocal(u32::try_from(i).unwrap_or(u32::MAX)));
            req_patterns.push(Some(&rule.pattern));
        }
        for (i, rule) in self.request_mocks.iter().enumerate() {
            req_refs.push(ReqRuleRef::RequestMock(
                u32::try_from(i).unwrap_or(u32::MAX),
            ));
            req_patterns.push(Some(&rule.pattern));
        }
        for (i, rule) in self.body_rewrites.iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            if rule.response {
                resp_refs.push(RespRuleRef::Body(idx));
                resp_patterns.push(Some(&rule.pattern));
            } else {
                req_refs.push(ReqRuleRef::Body(idx));
                req_patterns.push(Some(&rule.pattern));
            }
        }

        let mut rule_scripts = HashMap::new();
        let mut dns_scripts = HashMap::new();
        for (i, script) in self.scripts.iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            match script.kind {
                ScriptKind::HttpRequest => {
                    req_refs.push(ReqRuleRef::Script(idx));
                    req_patterns.push(script.pattern());
                }
                ScriptKind::HttpResponse => {
                    resp_refs.push(RespRuleRef::Script(idx));
                    resp_patterns.push(script.pattern());
                }
                ScriptKind::Rule => {
                    rule_scripts
                        .entry(Box::from(script.name.as_str()))
                        .or_insert(i);
                }
                ScriptKind::Dns => {
                    dns_scripts
                        .entry(Box::from(script.name.as_str()))
                        .or_insert(i);
                }
                ScriptKind::Cron | ScriptKind::Event | ScriptKind::Generic => {}
            }
        }

        let req_index = UrlIndex::new(req_patterns);
        let resp_index = UrlIndex::new(resp_patterns);

        #[cfg(test)]
        let per_kind = [
            UrlIndex::new(self.url_rewrites.iter().map(|rule| Some(&rule.pattern))),
            UrlIndex::new(self.header_rewrites.iter().map(|rule| Some(&rule.pattern))),
            UrlIndex::new(self.body_rewrites.iter().map(|rule| Some(&rule.pattern))),
            UrlIndex::new(self.map_locals.iter().map(|rule| Some(&rule.pattern))),
            UrlIndex::new(self.request_mocks.iter().map(|rule| Some(&rule.pattern))),
            UrlIndex::new(
                self.scripts
                    .iter()
                    .filter(|s| {
                        matches!(s.kind, ScriptKind::HttpRequest | ScriptKind::HttpResponse)
                    })
                    .map(|s| s.pattern()),
            ),
        ];

        CompiledIndexes {
            req_index,
            req_refs,
            resp_index,
            resp_refs,
            rule_scripts,
            dns_scripts,
            #[cfg(test)]
            per_kind,
        }
    }

    #[cfg(test)]
    pub(crate) fn index_of_url_rewrites(&self) -> &UrlIndex {
        &self.compiled().per_kind[0]
    }

    #[cfg(test)]
    fn lists(&self) -> [(&'static str, usize, &UrlIndex); 6] {
        let compiled = self.compiled();
        let http_scripts = self
            .scripts
            .iter()
            .filter(|s| matches!(s.kind, ScriptKind::HttpRequest | ScriptKind::HttpResponse))
            .count();
        [
            (
                "url-rewrite",
                self.url_rewrites.len(),
                &compiled.per_kind[0],
            ),
            (
                "header-rewrite",
                self.header_rewrites.len(),
                &compiled.per_kind[1],
            ),
            (
                "body-rewrite",
                self.body_rewrites.len(),
                &compiled.per_kind[2],
            ),
            ("map-local", self.map_locals.len(), &compiled.per_kind[3]),
            (
                "request-mock",
                self.request_mocks.len(),
                &compiled.per_kind[4],
            ),
            ("script", http_scripts, &compiled.per_kind[5]),
        ]
    }

    #[cfg(test)]
    pub(crate) fn index_report(&self) -> Vec<(&'static str, usize, usize, usize)> {
        self.lists()
            .into_iter()
            .map(|(name, total, index)| (name, total, index.always().len(), index.heap_bytes()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn candidate_counts(&self, url: &str) -> Vec<(&'static str, usize)> {
        self.lists()
            .into_iter()
            .map(|(name, _, index)| (name, index.candidates(url).len()))
            .collect()
    }

    /// Builds every list's index now, so that the first request does not.
    pub(crate) fn index(&self) {
        let _ = self.compiled();
    }

    pub(crate) fn scan_request(&self, url: &str) -> RequestScan {
        let compiled = self.compiled();
        let mut scan = RequestScan::default();
        if compiled.req_index.is_empty() {
            return scan;
        }
        let mut hits = Vec::new();
        compiled.req_index.collect_candidates(url, &mut hits);
        for slot in hits {
            let Some(&item) = compiled.req_refs.get(slot) else {
                continue;
            };
            match item {
                ReqRuleRef::Header(idx) => scan.headers.push(idx),
                ReqRuleRef::UrlRewrite(idx) => scan.url_rewrites.push(idx),
                ReqRuleRef::MapLocal(idx) => scan.map_locals.push(idx),
                ReqRuleRef::RequestMock(idx) => scan.request_mocks.push(idx),
                ReqRuleRef::Body(idx) => scan.bodies.push(idx),
                ReqRuleRef::Script(idx) => scan.scripts.push(idx),
            }
        }
        scan
    }

    /// Scans all response-phase rules against the final sent `url` once and confirms each
    /// candidate's URL regex, preserving original rule order while deferring head conditions.
    pub(crate) fn prepare_response(&self, url: &str) -> ResponsePlan {
        let compiled = self.compiled();
        let mut plan = ResponsePlan::default();
        if compiled.resp_index.is_empty() {
            return plan;
        }
        let mut hits = Vec::new();
        compiled.resp_index.collect_candidates(url, &mut hits);
        for slot in hits {
            let Some(&item) = compiled.resp_refs.get(slot) else {
                continue;
            };
            match item {
                RespRuleRef::Header(idx) => {
                    if let Some(rule) = self.header_rewrites.get(idx as usize)
                        && rule.pattern.is_match(url)
                    {
                        plan.needs_sent_headers |= rule.conditions.request.is_some();
                        plan.headers.push(idx);
                    }
                }
                RespRuleRef::Body(idx) => {
                    if let Some(rule) = self.body_rewrites.get(idx as usize)
                        && rule.pattern.is_match(url)
                    {
                        plan.needs_sent_headers |= rule.conditions.request.is_some();
                        plan.bodies.push(idx);
                    }
                }
                RespRuleRef::Script(idx) => {
                    if let Some(script) = self.scripts.get(idx as usize)
                        && script.matches_http(url, true)
                    {
                        plan.needs_sent_headers = true;
                        plan.scripts.push(idx);
                    }
                }
            }
        }
        plan
    }

    pub(crate) fn script_by_name(
        &self,
        kind: ScriptKind,
        name: &str,
    ) -> Option<&std::sync::Arc<crate::script::Script>> {
        let compiled = self.compiled();
        let idx = match kind {
            ScriptKind::Rule => compiled.rule_scripts.get(name).copied(),
            ScriptKind::Dns => compiled.dns_scripts.get(name).copied(),
            _ => {
                return self
                    .scripts
                    .iter()
                    .find(|script| script.kind == kind && script.name == name);
            }
        }?;
        self.scripts.get(idx)
    }

    #[cfg(test)]
    pub(crate) fn url_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::UrlRewrite> {
        self.scan_request(url)
            .url_rewrites
            .into_iter()
            .filter_map(|idx| self.url_rewrites.get(idx as usize))
    }
}

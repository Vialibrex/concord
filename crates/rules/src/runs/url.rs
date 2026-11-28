//! `URL-REGEX` pre-matchers: contiguous `UrlRun` runs and program-wide `UrlSet`.

use std::sync::Arc;

use concord_common::HttpFacts;
use concord_config::mitm::delegatable_regex;
use regex::{RegexSet, RegexSetBuilder, SetMatches};

const URL_SET_HYBRID_CACHE: usize = 2 * 1024 * 1024;
const URL_SET_BUCKET_NFA_LIMIT: usize = 512 * 1024;
#[cfg(target_pointer_width = "64")]
const URL_SET_BUILDER_STATE_BYTES: usize = 32;
#[cfg(not(target_pointer_width = "64"))]
const URL_SET_BUILDER_STATE_BYTES: usize = 16;

enum BucketKind {
    Set(RegexSet),
    Fancy,
}

struct BuiltBucket {
    start: usize,
    end: usize,
    kind: BucketKind,
}

/// Upper bound on `thompson::Builder::memory_usage()` for a single unchunked `RegexSet` so that
/// `hybrid::dfa::minimum_cache_capacity(S, P) = 27*S + 36*P + C (C <= 12 KiB)` stays inside
/// `URL_SET_HYBRID_CACHE` even with zero `memory_states`. Capped at `URL_SET_HYBRID_CACHE` on
/// 64-bit so small sets stay within the single-set regime without stretching to the 2 MiB cliff.
fn single_set_nfa_limit(pattern_count: usize) -> usize {
    let fixed = pattern_count.saturating_mul(36).saturating_add(12 * 1024);
    let max_states = URL_SET_HYBRID_CACHE.saturating_sub(fixed) / 27;
    max_states
        .saturating_mul(URL_SET_BUILDER_STATE_BYTES)
        .min(URL_SET_HYBRID_CACHE)
}

/// Heuristic window pre-cap using `size_of::<thompson::builder::State>()` per source byte.
/// Not a strict lower bound (character classes and flags can compile to fewer states than
/// source bytes); avoids parsing an oversized whole set into HIR before chunking.
fn pre_capped_len(sources: &[String], size_limit: usize) -> usize {
    let mut est = 0usize;
    let mut count = 0usize;
    for src in sources {
        let pat_est = src
            .len()
            .max(1)
            .saturating_mul(URL_SET_BUILDER_STATE_BYTES)
            .saturating_add(URL_SET_BUILDER_STATE_BYTES + 8);
        if count > 0 && est.saturating_add(pat_est) > size_limit {
            break;
        }
        est = est.saturating_add(pat_est);
        count += 1;
    }
    count.max(1)
}

fn try_url_set(window: &[String], size_limit: usize) -> Option<RegexSet> {
    RegexSetBuilder::new(window)
        .size_limit(size_limit)
        .dfa_size_limit(URL_SET_HYBRID_CACHE)
        .build()
        .ok()
}

fn refine_bucket_len(
    remaining: &[String],
    mut len: usize,
    mut hi: usize,
    mut set: RegexSet,
    limit: usize,
) -> (usize, RegexSet) {
    while hi > len + 1 {
        let mid = len + (hi - len) / 2;
        if let Some(wider) = remaining.get(..mid)
            && let Some(wider_set) = try_url_set(wider, limit)
        {
            set = wider_set;
            len = mid;
        } else {
            hi = mid;
        }
    }
    (len, set)
}

fn grow_bucket_len(
    remaining: &[String],
    mut len: usize,
    cap: usize,
    mut set: RegexSet,
    limit: usize,
) -> (usize, RegexSet) {
    let max_len = cap.min(remaining.len());
    let mut grew = false;
    while len < max_len {
        let next = len.saturating_mul(2).min(max_len);
        if let Some(wider) = remaining.get(..next)
            && let Some(wider_set) = try_url_set(wider, limit)
        {
            set = wider_set;
            len = next;
            grew = true;
        } else {
            if grew {
                return refine_bucket_len(remaining, len, next, set, limit);
            }
            break;
        }
    }
    (len, set)
}

fn build_url_buckets(
    sources: &[String],
    single_limit: usize,
    bucket_limit: usize,
) -> Vec<BuiltBucket> {
    if sources.is_empty() {
        return Vec::new();
    }
    if single_limit > bucket_limit
        && pre_capped_len(sources, single_limit) == sources.len()
        && let Some(set) = try_url_set(sources, single_limit)
    {
        return vec![BuiltBucket {
            start: 0,
            end: sources.len(),
            kind: BucketKind::Set(set),
        }];
    }
    let mut buckets = Vec::new();
    let mut pos = 0usize;
    let mut step: Option<usize> = None;
    while pos < sources.len() {
        let Some(remaining) = sources.get(pos..) else {
            break;
        };
        let cap = pre_capped_len(remaining, bucket_limit);
        let mut len = step
            .map_or(cap, |prev| prev.min(cap))
            .min(remaining.len())
            .max(1);
        let mut failed_len: Option<usize> = None;
        let mut back = 1usize;
        while let Some(window) = remaining.get(..len) {
            if let Some(set) = try_url_set(window, bucket_limit) {
                let (len, set) = if let Some(hi) = failed_len {
                    refine_bucket_len(remaining, len, hi, set, bucket_limit)
                } else if len < remaining.len() && buckets.len().is_power_of_two() {
                    grow_bucket_len(remaining, len, cap, set, bucket_limit)
                } else {
                    (len, set)
                };
                buckets.push(BuiltBucket {
                    start: pos,
                    end: pos + len,
                    kind: BucketKind::Set(set),
                });
                if len < remaining.len() {
                    step = Some(len);
                }
                pos += len;
                break;
            } else if len > 1 {
                failed_len = Some(len);
                if step.is_some() {
                    len = len.saturating_sub(back).max(1);
                    back = back.saturating_mul(2);
                } else {
                    len /= 2;
                }
            } else {
                buckets.push(BuiltBucket {
                    start: pos,
                    end: pos + 1,
                    kind: BucketKind::Fancy,
                });
                pos += 1;
                break;
            }
        }
    }
    buckets
}

struct UrlRunBucket {
    set: RegexSet,
    owners: Box<[u32]>,
}

/// A run of `URL-REGEX` rules. Patterns fancy-regex hands whole to the `regex` engine are
/// matched in bounded `RegexSet` buckets; the rest are tried one at a time, in list order.
pub(crate) struct UrlRun {
    pub(crate) start: u32,
    pub(crate) end: u32,
    buckets: Box<[UrlRunBucket]>,
    fancy: Box<[(u32, fancy_regex::Regex)]>,
}

impl UrlRun {
    pub(crate) fn build(start: u32, end: u32, items: Vec<(u32, fancy_regex::Regex)>) -> UrlRun {
        Self::build_with_limits(start, end, items, None, URL_SET_BUCKET_NFA_LIMIT)
    }

    #[cfg(test)]
    pub(crate) fn build_with_limit(
        start: u32,
        end: u32,
        items: Vec<(u32, fancy_regex::Regex)>,
        size_limit: usize,
    ) -> UrlRun {
        Self::build_with_limits(start, end, items, Some(size_limit), size_limit)
    }

    pub(crate) fn build_with_limits(
        start: u32,
        end: u32,
        items: Vec<(u32, fancy_regex::Regex)>,
        single_limit: Option<usize>,
        bucket_limit: usize,
    ) -> UrlRun {
        let mut sources = Vec::new();
        let mut owners = Vec::new();
        let mut delegated = Vec::new();
        let mut fancy = Vec::new();
        for (idx, regex) in items {
            match delegatable_regex(regex.as_str()) {
                Some(cooked) => {
                    sources.push(cooked);
                    owners.push(idx);
                    delegated.push(Some((idx, regex)));
                }
                None => fancy.push((idx, regex)),
            }
        }
        let single_limit = single_limit.unwrap_or_else(|| single_set_nfa_limit(sources.len()));
        let mut buckets = Vec::new();
        let mut moved_to_fancy = false;
        for bucket in build_url_buckets(&sources, single_limit, bucket_limit) {
            match bucket.kind {
                BucketKind::Set(set) => {
                    if let Some(slice) = owners.get(bucket.start..bucket.end) {
                        buckets.push(UrlRunBucket {
                            set,
                            owners: slice.into(),
                        });
                    }
                }
                BucketKind::Fancy => {
                    if let Some(item) = delegated.get_mut(bucket.start).and_then(Option::take) {
                        fancy.push(item);
                        moved_to_fancy = true;
                    }
                }
            }
        }
        if moved_to_fancy {
            fancy.sort_unstable_by_key(|(idx, _)| *idx);
        }
        UrlRun {
            start,
            end,
            buckets: buckets.into_boxed_slice(),
            fancy: fancy.into_boxed_slice(),
        }
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.buckets
            .iter()
            .map(|bucket| bucket.owners.len() * 4)
            .sum::<usize>()
            + self.fancy.len() * std::mem::size_of::<(u32, fancy_regex::Regex)>()
    }

    /// The smallest rule index in `from..end` whose pattern matches `url`.
    pub(crate) fn next_from(&self, url: &str, from: u32) -> Option<u32> {
        let from = from.max(self.start);
        let mut best = None;
        for bucket in &self.buckets {
            if bucket.owners.last().is_none_or(|&last| last < from) {
                continue;
            }
            if let Some(hit) = bucket
                .set
                .matches(url)
                .iter()
                .filter_map(|at| bucket.owners.get(at).copied())
                .find(|idx| *idx >= from)
            {
                best = Some(hit);
                break;
            }
        }
        for (idx, regex) in self.fancy.iter() {
            if *idx < from {
                continue;
            }
            if best.is_some_and(|best| *idx >= best) {
                break;
            }
            if regex.is_match(url).unwrap_or(false) {
                return Some(*idx);
            }
        }
        best
    }

    #[cfg(test)]
    pub(crate) fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

pub(crate) enum UrlNode {
    Slot(u32),
    Fancy(Box<fancy_regex::Regex>),
}

pub(crate) struct UrlCache {
    http: Arc<HttpFacts>,
    start: u32,
    len: u32,
    bucket: usize,
    hits: SetMatches,
    parked: Option<Box<[Option<SetMatches>]>>,
}

/// Slot allocator for full `RouteProgram` compilation. Classical rule-sets evaluate
/// against the outer program's `Ev.url_set`, so slot ids from their own allocator would
/// index the wrong outer pattern.
#[derive(Default)]
pub(crate) struct UrlSlots {
    sources: Vec<String>,
    regexes: Vec<fancy_regex::Regex>,
}

impl UrlSlots {
    pub(crate) fn alloc(&mut self, regex: fancy_regex::Regex) -> UrlNode {
        if let Some(cooked) = delegatable_regex(regex.as_str()) {
            let slot = self.sources.len() as u32;
            self.sources.push(cooked);
            self.regexes.push(regex);
            return UrlNode::Slot(slot);
        }
        UrlNode::Fancy(Box::new(regex))
    }

    pub(crate) fn build(self) -> UrlSet {
        UrlSet::build(self.sources, self.regexes)
    }
}

enum UrlBucket {
    Set {
        start: u32,
        end: u32,
        set: RegexSet,
    },
    Fancy {
        start: u32,
        regex: fancy_regex::Regex,
    },
}

impl UrlBucket {
    fn end(&self) -> u32 {
        match self {
            UrlBucket::Set { end, .. } => *end,
            UrlBucket::Fancy { start, .. } => start + 1,
        }
    }
}

/// Program-wide pre-matcher for lone and nested `URL-REGEX` leaves across a
/// `RouteProgram`'s main list and sub-rule lists.
#[derive(Default)]
pub(crate) struct UrlSet {
    inner: UrlSetInner,
    #[cfg(test)]
    scans: std::sync::atomic::AtomicUsize,
}

#[derive(Default)]
enum UrlSetInner {
    #[default]
    Empty,
    Single(RegexSet),
    Chunked(Box<[UrlBucket]>),
    Fallback(Box<[fancy_regex::Regex]>),
}

impl UrlSet {
    pub(crate) const fn empty() -> UrlSet {
        UrlSet {
            inner: UrlSetInner::Empty,
            #[cfg(test)]
            scans: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn build(sources: Vec<String>, regexes: Vec<fancy_regex::Regex>) -> UrlSet {
        let single_limit = single_set_nfa_limit(sources.len());
        Self::build_with_limits(sources, regexes, single_limit, URL_SET_BUCKET_NFA_LIMIT)
    }

    #[cfg(test)]
    pub(crate) fn build_with_limit(
        sources: Vec<String>,
        regexes: Vec<fancy_regex::Regex>,
        size_limit: usize,
    ) -> UrlSet {
        Self::build_with_limits(sources, regexes, size_limit, size_limit)
    }

    pub(crate) fn build_with_limits(
        sources: Vec<String>,
        regexes: Vec<fancy_regex::Regex>,
        single_limit: usize,
        bucket_limit: usize,
    ) -> UrlSet {
        let inner = match regexes.len() {
            0 => UrlSetInner::Empty,
            1 => UrlSetInner::Fallback(regexes.into_boxed_slice()),
            _ => {
                match <[BuiltBucket; 1]>::try_from(build_url_buckets(
                    &sources,
                    single_limit,
                    bucket_limit,
                )) {
                    Ok(
                        [
                            BuiltBucket {
                                kind: BucketKind::Set(set),
                                ..
                            },
                        ],
                    ) => UrlSetInner::Single(set),
                    Ok(
                        [
                            BuiltBucket {
                                kind: BucketKind::Fancy,
                                ..
                            },
                        ],
                    ) => UrlSetInner::Fallback(regexes.into_boxed_slice()),
                    Err(built) if !built.iter().any(|b| matches!(b.kind, BucketKind::Set(_))) => {
                        UrlSetInner::Fallback(regexes.into_boxed_slice())
                    }
                    Err(built) => {
                        let mut owned: Vec<Option<fancy_regex::Regex>> =
                            regexes.into_iter().map(Some).collect();
                        let buckets = built
                            .into_iter()
                            .filter_map(|bucket| match bucket.kind {
                                BucketKind::Set(set) => Some(UrlBucket::Set {
                                    start: bucket.start as u32,
                                    end: bucket.end as u32,
                                    set,
                                }),
                                BucketKind::Fancy => owned
                                    .get_mut(bucket.start)
                                    .and_then(Option::take)
                                    .map(|regex| UrlBucket::Fancy {
                                        start: bucket.start as u32,
                                        regex,
                                    }),
                            })
                            .collect();
                        UrlSetInner::Chunked(buckets)
                    }
                }
            }
        };
        UrlSet {
            inner,
            #[cfg(test)]
            scans: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        match &self.inner {
            UrlSetInner::Fallback(list) => list.len() * std::mem::size_of::<fancy_regex::Regex>(),
            UrlSetInner::Chunked(buckets) => buckets.len() * std::mem::size_of::<UrlBucket>(),
            UrlSetInner::Empty | UrlSetInner::Single(_) => 0,
        }
    }

    #[inline]
    pub(crate) fn matches(
        &self,
        slot: u32,
        http: &Arc<HttpFacts>,
        cache: &mut Option<Box<UrlCache>>,
    ) -> bool {
        if let Some(cached) = cache
            && Arc::ptr_eq(&cached.http, http)
        {
            let offset = slot.wrapping_sub(cached.start);
            if offset < cached.len {
                return cached.hits.matched(offset as usize);
            }
        }
        self.matches_slow(slot, http, cache)
    }

    #[cold]
    fn matches_slow(
        &self,
        slot: u32,
        http: &Arc<HttpFacts>,
        cache: &mut Option<Box<UrlCache>>,
    ) -> bool {
        match &self.inner {
            UrlSetInner::Empty => false,
            UrlSetInner::Single(set) => {
                #[cfg(test)]
                self.scans
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let cached = cache.insert(Box::new(UrlCache {
                    http: Arc::clone(http),
                    start: 0,
                    len: u32::MAX,
                    bucket: 0,
                    hits: set.matches(&http.url),
                    parked: None,
                }));
                cached.hits.matched(slot as usize)
            }
            UrlSetInner::Chunked(buckets) => {
                let idx = buckets.partition_point(|bucket| bucket.end() <= slot);
                match buckets.get(idx) {
                    None => false,
                    Some(UrlBucket::Fancy { regex, .. }) => {
                        regex.is_match(&*http.url).unwrap_or(false)
                    }
                    Some(UrlBucket::Set { start, end, set }) => {
                        let len = *end - *start;
                        let same_http = cache
                            .as_ref()
                            .is_some_and(|cached| Arc::ptr_eq(&cached.http, http));
                        if same_http && let Some(cached) = cache.as_mut() {
                            let next_hits = cached
                                .parked
                                .as_mut()
                                .and_then(|parked| parked.get_mut(idx))
                                .and_then(Option::take)
                                .unwrap_or_else(|| {
                                    #[cfg(test)]
                                    self.scans
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    set.matches(&http.url)
                                });
                            let prev_hits = std::mem::replace(&mut cached.hits, next_hits);
                            if let Some(slot_entry) = cached
                                .parked
                                .as_mut()
                                .and_then(|parked| parked.get_mut(cached.bucket))
                            {
                                *slot_entry = Some(prev_hits);
                            }
                            cached.start = *start;
                            cached.len = len;
                            cached.bucket = idx;
                            return cached.hits.matched((slot - *start) as usize);
                        }
                        #[cfg(test)]
                        self.scans
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let cached = cache.insert(Box::new(UrlCache {
                            http: Arc::clone(http),
                            start: *start,
                            len,
                            bucket: idx,
                            hits: set.matches(&http.url),
                            parked: Some(
                                std::iter::repeat_with(|| None)
                                    .take(buckets.len())
                                    .collect(),
                            ),
                        }));
                        cached.hits.matched((slot - *start) as usize)
                    }
                }
            }
            UrlSetInner::Fallback(list) => list
                .get(slot as usize)
                .is_some_and(|regex| regex.is_match(&*http.url).unwrap_or(false)),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_set(&self) -> bool {
        matches!(self.inner, UrlSetInner::Single(_) | UrlSetInner::Chunked(_))
    }

    #[cfg(test)]
    pub(crate) fn bucket_count(&self) -> usize {
        match &self.inner {
            UrlSetInner::Single(_) => 1,
            UrlSetInner::Chunked(buckets) => buckets.len(),
            UrlSetInner::Empty | UrlSetInner::Fallback(_) => 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn fancy_bucket_count(&self) -> usize {
        match &self.inner {
            UrlSetInner::Chunked(buckets) => buckets
                .iter()
                .filter(|b| matches!(b, UrlBucket::Fancy { .. }))
                .count(),
            _ => 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn scans(&self) -> usize {
        self.scans.load(std::sync::atomic::Ordering::Relaxed)
    }
}

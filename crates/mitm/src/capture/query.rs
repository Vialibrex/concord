use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use concord_common::exchange_query::{ContentKind, ExchangeFilter, ExchangeQuery, StatusClass};
use concord_common::intercept::ConnTag;
use concord_common::sync::lock;
use serde::Serialize;
use time::OffsetDateTime;

use super::{Capture, CaptureStore, Exchange, ExchangeSummary, is_empty, millis, since_format};

/// One page of `mitm.query`, newest first, with what the page's view needs besides it.
#[derive(Debug, Serialize)]
pub struct QueryAnswer {
    pub capturing: bool,
    #[serde(skip_serializing_if = "Option::is_none", with = "since_format")]
    pub since: Option<OffsetDateTime>,
    /// The `since` that asks for what is added or changed after this answer.
    pub version: u64,
    /// The lowest id held; a client keeping earlier answers drops the ids below it.
    pub oldest: i64,
    pub held: usize,
    /// How many of the held exchanges match the filter.
    pub matched: usize,
    pub exchanges: Vec<ExchangeSummary>,
    /// The `before` of the next page; absent when this page holds the last match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<i64>,
    /// Changed since `since` and no longer matching, so a client drops them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unmatched: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facets: Option<Facets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<Vec<RateBucket>>,
    /// Of the finished matches, in milliseconds.
    #[serde(rename = "median-duration", skip_serializing_if = "Option::is_none")]
    pub median_duration: Option<i64>,
}

/// Each dimension counts the exchanges every other part of the filter lets through, so a
/// view can offer the other values of a dimension it already narrowed.
#[derive(Debug, Default, Serialize)]
pub struct Facets {
    pub status: BTreeMap<&'static str, usize>,
    /// Keyed in upper case.
    pub method: BTreeMap<String, usize>,
    pub kind: BTreeMap<&'static str, usize>,
    /// Keyed by process; `""` holds the exchanges of no known app.
    pub app: BTreeMap<String, usize>,
}

/// The process behind the connection an exchange went out on, kept after that connection is gone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct App {
    pub process: String,
    #[serde(rename = "process-path", skip_serializing_if = "is_empty")]
    pub process_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RateBucket {
    /// The second's start, in Unix milliseconds.
    pub t: i64,
    pub requests: usize,
    /// Failed, or answered 4xx or 5xx.
    pub errors: usize,
}

/// An exchange as the filter reads it, borrowed while its record is locked.
pub(super) struct View<'a> {
    pub(super) exchange: &'a Exchange,
    pub(super) conn: Option<&'a ConnTag>,
    pub(super) changed: u64,
    pub(super) duration: i64,
}

impl View<'_> {
    pub(super) fn id(&self) -> i64 {
        self.exchange.summary.id
    }

    pub(super) fn status(&self) -> StatusClass {
        let summary = &self.exchange.summary;
        StatusClass::of(summary.status, &summary.error, summary.pending)
    }

    pub(super) fn kind(&self) -> ContentKind {
        ContentKind::of(&self.exchange.summary.content_type)
    }

    fn app(&self) -> &str {
        self.conn.map_or("", |conn| conn.process.as_str())
    }

    fn start_ms(&self) -> i64 {
        unix_millis(self.exchange.summary.start)
    }
}

fn unix_millis(at: OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// Which parts of the filter one exchange passes: the four that have counts apart from the rest.
struct Passes {
    status: bool,
    method: bool,
    kind: bool,
    app: bool,
    rest: bool,
}

impl Passes {
    fn of(filter: &ExchangeFilter, needle: Option<&Needle>, view: &View<'_>) -> Self {
        let summary = &view.exchange.summary;
        let any = |list: &[String], value: &str| {
            list.is_empty() || list.iter().any(|item| item.eq_ignore_ascii_case(value))
        };
        let start = view.start_ms();
        let rest = any(&filter.hosts, &summary.host)
            && filter
                .rewritten
                .is_none_or(|wanted| wanted == view.exchange.rewritten())
            && filter.slow_ms.is_none_or(|slow| view.duration >= slow)
            && filter.from_ms.is_none_or(|from| start >= from)
            && filter.to_ms.is_none_or(|to| start < to)
            && needle.is_none_or(|needle| {
                [
                    summary.url.as_str(),
                    summary.method.as_str(),
                    summary.content_type.as_str(),
                    summary.error.as_str(),
                    view.app(),
                ]
                .iter()
                .any(|hay| needle.found_in(hay))
            });
        Passes {
            status: filter.statuses.is_empty() || filter.statuses.contains(&view.status()),
            method: any(&filter.methods, &summary.method),
            kind: filter.kinds.is_empty() || filter.kinds.contains(&view.kind()),
            app: any(&filter.apps, view.app()),
            rest,
        }
    }

    fn all(&self) -> bool {
        self.status && self.method && self.kind && self.app && self.rest
    }
}

struct Needle {
    lower: String,
}

impl Needle {
    fn new(text: &str) -> Option<Self> {
        (!text.is_empty()).then(|| Needle {
            lower: text.to_lowercase(),
        })
    }

    fn found_in(&self, hay: &str) -> bool {
        if self.lower.is_ascii() {
            let needle = self.lower.as_bytes();
            hay.as_bytes()
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
        } else {
            hay.to_lowercase().contains(&self.lower)
        }
    }
}

impl Facets {
    fn count(&mut self, view: &View<'_>, passes: &Passes) {
        if !passes.rest {
            return;
        }
        if passes.method && passes.kind && passes.app {
            *self.status.entry(view.status().name()).or_default() += 1;
        }
        if passes.status && passes.kind && passes.app {
            bump(
                &mut self.method,
                &view.exchange.summary.method.to_ascii_uppercase(),
            );
        }
        if passes.status && passes.method && passes.app {
            *self.kind.entry(view.kind().name()).or_default() += 1;
        }
        if passes.status && passes.method && passes.kind {
            bump(&mut self.app, view.app());
        }
    }
}

fn bump(counts: &mut BTreeMap<String, usize>, key: &str) {
    match counts.get_mut(key) {
        Some(count) => *count += 1,
        None => {
            counts.insert(key.to_string(), 1);
        }
    }
}

impl CaptureStore {
    pub fn query(&self, query: &ExchangeQuery) -> QueryAnswer {
        let inner = lock(&self.inner);
        let capturing = self.is_on();
        let needle = query.filter.text.as_deref().and_then(Needle::new);
        let mut answer = QueryAnswer {
            capturing,
            since: capturing.then_some(inner.since),
            version: inner.version,
            oldest: inner
                .records
                .front()
                .map_or(inner.last_id + 1, |capture| capture.id),
            held: inner.records.len(),
            matched: 0,
            exchanges: Vec::new(),
            next: None,
            unmatched: Vec::new(),
            facets: query.facets.then(Facets::default),
            rate: None,
            median_duration: None,
        };
        let mut rate = query
            .rate_from_ms
            .map(|_| BTreeMap::<i64, (usize, usize)>::new());
        let mut durations = Vec::new();
        for capture in inner.records.iter().rev() {
            capture.view(|view| {
                let passes = Passes::of(&query.filter, needle.as_ref(), view);
                if let Some(facets) = &mut answer.facets {
                    facets.count(view, &passes);
                }
                let changed = query.since.is_none_or(|since| view.changed > since);
                if !passes.all() {
                    if changed && query.since.is_some() {
                        answer.unmatched.push(view.id());
                    }
                    return;
                }
                // Sizes and the running duration move without a version, so a client following
                // with `since` gets every exchange in progress each time.
                let fresh = changed || view.exchange.summary.pending;
                answer.matched += 1;
                if !view.exchange.summary.pending {
                    durations.push(view.duration);
                }
                if let (Some(rate), Some(from)) = (&mut rate, query.rate_from_ms) {
                    let start = view.start_ms();
                    if start >= from {
                        let bucket = rate.entry(start - start.rem_euclid(1000)).or_default();
                        bucket.0 += 1;
                        bucket.1 += usize::from(view.status().is_error());
                    }
                }
                if !fresh || query.before.is_some_and(|before| view.id() >= before) {
                    return;
                }
                if query
                    .limit
                    .is_some_and(|limit| answer.exchanges.len() >= limit)
                {
                    if answer.next.is_none() {
                        answer.next = answer.exchanges.last().map(|last| last.id);
                    }
                    return;
                }
                answer.exchanges.push(capture.summary_of(view));
            });
        }
        answer.rate = rate.map(|buckets| {
            buckets
                .into_iter()
                .map(|(t, (requests, errors))| RateBucket {
                    t,
                    requests,
                    errors,
                })
                .collect()
        });
        if !durations.is_empty() {
            let middle = durations.len() / 2;
            answer.median_duration = Some(*durations.select_nth_unstable(middle).1);
        }
        answer
    }
}

impl Capture {
    pub(super) fn summary_of(&self, view: &View<'_>) -> ExchangeSummary {
        let mut summary = view.exchange.summary.clone();
        summary.request_size = self.request_size.load(Ordering::Relaxed);
        summary.response_size = self.response_size.load(Ordering::Relaxed);
        summary.duration = view.duration;
        summary.status_class = view.status().name();
        summary.kind = view.kind().name();
        summary.rewritten = view.exchange.rewritten();
        summary.connection_id = view.conn.map(|conn| conn.seq);
        summary.app = view
            .conn
            .filter(|conn| !conn.process.is_empty() || conn.uid.is_some())
            .map(|conn| App {
                process: conn.process.clone(),
                process_path: conn.process_path.clone(),
                uid: conn.uid,
            });
        summary
    }

    /// Under the store's lock, as every reader of `changed` is.
    pub(super) fn view<R>(&self, read: impl FnOnce(&View<'_>) -> R) -> R {
        let record = lock(&self.record);
        let conn = lock(&self.connection);
        let duration = if record.exchange.summary.pending {
            millis(self.started)
        } else {
            record.exchange.summary.duration
        };
        read(&View {
            exchange: &record.exchange,
            conn: conn.as_deref(),
            changed: self.changed.load(Ordering::Relaxed),
            duration,
        })
    }
}

/// The host and the path with its query of a URL the capture recorded.
pub(super) fn split_url(url: &str) -> (&str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host),
        None => host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host),
    };
    (host, if path.is_empty() { "/" } else { path })
}

/// A `Content-Type` without its parameters, in lower case.
pub(super) fn mime_of(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use concord_common::exchange_query::{ContentKind, ExchangeFilter, ExchangeQuery, StatusClass};
    use concord_common::intercept::ConnTag;
    use concord_common::sync::lock;

    use super::QueryAnswer;
    use crate::capture::{Cap, CaptureStore};
    use crate::limits::{DEFAULT_CAPTURE_BYTES, DEFAULT_MAX_BODY_SIZE, Pressure};
    use crate::script::HeaderList;

    fn store() -> Arc<CaptureStore> {
        let store = CaptureStore::new(Arc::new(Pressure::with_hold(Duration::from_secs(60))));
        store.set_capture(true);
        store
    }

    fn app(seq: u64, process: &str) -> Arc<ConnTag> {
        Arc::new(ConnTag {
            id: format!("c{seq}"),
            seq,
            uid: Some(10_000 + seq as u32),
            process: process.to_string(),
            ..ConnTag::default()
        })
    }

    fn header(content_type: &str) -> HeaderList {
        let mut header = HeaderList::new();
        header.insert("Content-Type".into(), vec![content_type.into()]);
        header
    }

    /// One finished exchange: `status` 0 fails it.
    fn exchange(
        store: &Arc<CaptureStore>,
        method: &str,
        url: &str,
        status: u16,
        mime: &str,
    ) -> Cap {
        let cap = store.begin(method, url, "HTTP/1.1", HeaderList::new());
        if status == 0 {
            cap.fail("connection reset");
        } else {
            cap.responded(status, header(mime));
        }
        cap.finish();
        cap
    }

    /// Sets how long a finished exchange took, which the store reads off the clock.
    fn took(cap: &Cap, millis: i64) {
        lock(&cap.0.as_ref().unwrap().record)
            .exchange
            .summary
            .duration = millis;
    }

    fn query(store: &CaptureStore, query: ExchangeQuery) -> QueryAnswer {
        store.query(&query)
    }

    fn urls(answer: &QueryAnswer) -> Vec<&str> {
        answer
            .exchanges
            .iter()
            .map(|summary| summary.path.as_str())
            .collect()
    }

    fn filtered(filter: ExchangeFilter) -> ExchangeQuery {
        ExchangeQuery {
            filter,
            ..ExchangeQuery::default()
        }
    }

    #[test]
    fn pages_go_newest_first_and_a_new_exchange_does_not_move_a_page_already_taken() {
        let store = store();
        for i in 0..5 {
            exchange(
                &store,
                "GET",
                &format!("https://a.test/{i}"),
                200,
                "text/html",
            );
        }
        let first = query(
            &store,
            ExchangeQuery {
                limit: Some(2),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(urls(&first), ["/4", "/3"]);
        exchange(&store, "GET", "https://a.test/5", 200, "text/html");
        let second = query(
            &store,
            ExchangeQuery {
                before: first.next,
                limit: Some(2),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(urls(&second), ["/2", "/1"]);
        let last = query(
            &store,
            ExchangeQuery {
                before: second.next,
                limit: Some(2),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(urls(&last), ["/0"]);
        assert_eq!(last.next, None, "the last page says so");
        assert_eq!((last.held, last.matched), (6, 6));
    }

    #[test]
    fn since_brings_what_was_added_or_finished_and_what_stopped_matching() {
        let store = store();
        let pending = store.begin("GET", "https://a.test/slow", "HTTP/1.1", HeaderList::new());
        exchange(
            &store,
            "GET",
            "https://a.test/done",
            200,
            "application/json",
        );
        let wanted = filtered(ExchangeFilter {
            statuses: vec![StatusClass::Pending, StatusClass::Success],
            ..ExchangeFilter::default()
        });
        let before = query(&store, wanted.clone());
        assert_eq!(urls(&before), ["/done", "/slow"]);
        let unchanged = query(
            &store,
            ExchangeQuery {
                since: Some(before.version),
                ..wanted.clone()
            },
        );
        assert_eq!(urls(&unchanged), ["/slow"], "only the one in progress");

        pending.responded(503, header("text/plain"));
        pending.finish();
        exchange(
            &store,
            "POST",
            "https://a.test/new",
            201,
            "application/json",
        );
        let after = query(
            &store,
            ExchangeQuery {
                since: Some(before.version),
                ..wanted
            },
        );
        assert_eq!(urls(&after), ["/new"]);
        assert_eq!(
            after.unmatched,
            [before.exchanges[1].id],
            "the slow one finished as a 503"
        );
        assert!(after.version > before.version);
    }

    #[test]
    fn each_part_of_the_filter_narrows_and_they_combine() {
        let store = store();
        exchange(
            &store,
            "GET",
            "https://api.test/users?id=1",
            200,
            "application/json; charset=utf-8",
        )
        .attach(Some(&app(1, "chrome")));
        exchange(
            &store,
            "POST",
            "https://api.test/graphql",
            502,
            "application/json",
        )
        .attach(Some(&app(1, "chrome")));
        exchange(&store, "GET", "https://img.test/a.png", 200, "image/png")
            .attach(Some(&app(2, "safari")));
        let failed = exchange(&store, "GET", "https://api.test/notifications", 0, "");
        failed.attach(Some(&app(2, "safari")));
        let rewritten = exchange(
            &store,
            "GET",
            "https://cdn.test/app.js",
            304,
            "text/javascript",
        );
        rewritten.note("url-rewrite", "", "", None);

        let paths = |filter: ExchangeFilter| {
            query(&store, filtered(filter))
                .exchanges
                .into_iter()
                .map(|summary| summary.path)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            paths(ExchangeFilter {
                statuses: vec![StatusClass::ServerError, StatusClass::Failed],
                ..Default::default()
            }),
            ["/notifications", "/graphql"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                methods: vec!["post".into()],
                ..Default::default()
            }),
            ["/graphql"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                kinds: vec![ContentKind::Image, ContentKind::Script],
                ..Default::default()
            }),
            ["/app.js", "/a.png"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                hosts: vec!["API.test".into()],
                ..Default::default()
            }),
            ["/notifications", "/graphql", "/users?id=1"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                apps: vec!["".into()],
                ..Default::default()
            }),
            ["/app.js"],
            "no connection, no app"
        );
        assert_eq!(
            paths(ExchangeFilter {
                rewritten: Some(true),
                ..Default::default()
            }),
            ["/app.js"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                text: Some("GRAPH".into()),
                ..Default::default()
            }),
            ["/graphql"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                text: Some("reset".into()),
                ..Default::default()
            }),
            ["/notifications"],
            "the error is searched too"
        );
        assert_eq!(
            paths(ExchangeFilter {
                hosts: vec!["api.test".into()],
                apps: vec!["chrome".into()],
                statuses: vec![StatusClass::Success],
                kinds: vec![ContentKind::Json],
                ..Default::default()
            }),
            ["/users?id=1"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                slow_ms: Some(60_000),
                ..Default::default()
            }),
            Vec::<String>::new()
        );
        assert_eq!(
            paths(ExchangeFilter {
                from_ms: Some(i64::MAX),
                ..Default::default()
            }),
            Vec::<String>::new()
        );
        assert_eq!(
            paths(ExchangeFilter {
                to_ms: Some(i64::MAX),
                ..Default::default()
            })
            .len(),
            5
        );
    }

    #[test]
    fn a_summary_carries_its_app_and_connection_and_the_facets_count_around_their_own_choice() {
        let store = store();
        let first = exchange(&store, "get", "https://a.test/1", 200, "application/json");
        first.attach(Some(&app(7, "chrome")));
        took(&first, 10);
        exchange(&store, "GET", "https://a.test/2", 404, "text/html")
            .attach(Some(&app(7, "chrome")));
        let third = exchange(&store, "POST", "https://a.test/3", 200, "application/json");
        third.attach(Some(&app(8, "curl")));
        took(&third, 30);
        exchange(&store, "PUT", "https://a.test/4", 201, "image/png");
        let fifth = exchange(&store, "GET", "https://a.test/5", 200, "application/json");
        fifth.attach(Some(&app(8, "curl")));
        took(&fifth, 50);

        let answer = query(
            &store,
            ExchangeQuery {
                filter: ExchangeFilter {
                    statuses: vec![StatusClass::Success],
                    kinds: vec![ContentKind::Json],
                    ..Default::default()
                },
                facets: true,
                rate_from_ms: Some(0),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(urls(&answer), ["/5", "/3", "/1"]);
        let third = &answer.exchanges[1];
        assert_eq!(
            (third.connection_id, third.status_class, third.kind),
            (Some(8), "2xx", "json")
        );
        let app = third.app.as_ref().unwrap();
        assert_eq!((app.process.as_str(), app.uid), ("curl", Some(10_008)));
        let facets = answer.facets.unwrap();
        let counts = |pairs: &[(&str, usize)]| {
            pairs
                .iter()
                .map(|(key, count)| (key.to_string(), *count))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            facets.status,
            BTreeMap::from([("2xx", 3)]),
            "the kinds chosen narrow the statuses: the 404 was html"
        );
        assert_eq!(facets.method, counts(&[("GET", 2), ("POST", 1)]));
        assert_eq!(
            facets.kind,
            BTreeMap::from([("image", 1), ("json", 3)]),
            "the statuses chosen narrow the kinds, not the kinds themselves"
        );
        assert_eq!(facets.app, counts(&[("chrome", 1), ("curl", 2)]));
        let rate = answer.rate.unwrap();
        assert_eq!(rate.iter().map(|bucket| bucket.requests).sum::<usize>(), 3);
        assert_eq!(rate.iter().map(|bucket| bucket.errors).sum::<usize>(), 0);
        assert!(rate.iter().all(|bucket| bucket.t % 1000 == 0));
        assert_eq!(answer.median_duration, Some(30));
    }

    #[test]
    fn past_the_limit_the_oldest_go_and_the_answer_says_where_the_capture_now_starts() {
        let store = store();
        store.limit(3, DEFAULT_CAPTURE_BYTES, DEFAULT_MAX_BODY_SIZE);
        let first = exchange(&store, "GET", "https://a.test/0", 200, "text/html");
        first.attach(Some(&app(1, "chrome")));
        let page = query(
            &store,
            ExchangeQuery {
                limit: Some(1),
                ..ExchangeQuery::default()
            },
        );
        for i in 1..5 {
            exchange(
                &store,
                "GET",
                &format!("https://a.test/{i}"),
                200,
                "text/html",
            );
        }
        let answer = query(
            &store,
            ExchangeQuery {
                since: Some(page.version),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(urls(&answer), ["/4", "/3", "/2"]);
        assert_eq!(answer.oldest, answer.exchanges[2].id);
        assert_eq!(answer.held, 3);
        let older = query(
            &store,
            ExchangeQuery {
                before: Some(answer.oldest),
                ..ExchangeQuery::default()
            },
        );
        assert!(older.exchanges.is_empty() && older.next.is_none());
    }

    fn paged(store: &CaptureStore, before: Option<i64>, since: Option<u64>) -> QueryAnswer {
        query(
            store,
            ExchangeQuery {
                before,
                since,
                limit: Some(2),
                ..ExchangeQuery::default()
            },
        )
    }

    fn fill(store: &Arc<CaptureStore>, paths: std::ops::Range<usize>) {
        for i in paths {
            exchange(
                store,
                "GET",
                &format!("https://a.test/{i}"),
                200,
                "text/html",
            );
        }
    }

    #[test]
    fn a_page_whose_exchanges_were_dropped_meanwhile_goes_on_from_what_is_left() {
        let store = store();
        store.limit(5, DEFAULT_CAPTURE_BYTES, DEFAULT_MAX_BODY_SIZE);
        fill(&store, 0..5);
        let first = paged(&store, None, None);
        assert_eq!(urls(&first), ["/4", "/3"]);
        fill(&store, 5..7);
        let second = paged(&store, first.next, None);
        assert_eq!(urls(&second), ["/2"], "/0 and /1 are gone");
        assert_eq!(second.next, None);
        fill(&store, 7..12);
        let after_all_went = paged(&store, second.exchanges[0].id.into(), None);
        assert!(after_all_went.exchanges.is_empty() && after_all_went.next.is_none());
        assert!(after_all_went.oldest > second.exchanges[0].id);
    }

    #[test]
    fn a_follow_cut_short_by_the_limit_goes_on_with_its_first_version_and_before() {
        let store = store();
        fill(&store, 0..2);
        let start = paged(&store, None, None);
        fill(&store, 2..7);
        let first = paged(&store, None, Some(start.version));
        assert_eq!(urls(&first), ["/6", "/5"]);
        fill(&store, 7..8);
        let second = paged(&store, first.next, Some(start.version));
        assert_eq!(urls(&second), ["/4", "/3"]);
        let third = paged(&store, second.next, Some(start.version));
        assert_eq!(urls(&third), ["/2"], "nothing older than the pass");
        assert_eq!(third.next, None);
        let next_pass = paged(&store, None, Some(first.version));
        assert_eq!(urls(&next_pass), ["/7"]);
        assert_eq!(
            (next_pass.matched, first.matched),
            (8, 7),
            "matched counts every held match"
        );
    }

    #[test]
    fn a_follow_brings_every_exchange_still_in_progress_with_its_sizes() {
        let store = store();
        let pending = store.begin("GET", "https://a.test/big", "HTTP/1.1", HeaderList::new());
        pending.responded(200, header("video/mp4"));
        exchange(&store, "GET", "https://a.test/done", 200, "text/html");
        let before = query(&store, ExchangeQuery::default());
        pending.add_response_size(4096);
        let follow = query(
            &store,
            ExchangeQuery {
                since: Some(before.version),
                ..ExchangeQuery::default()
            },
        );
        assert_eq!(follow.version, before.version, "a size moves no version");
        assert_eq!(
            urls(&follow),
            ["/big"],
            "the finished one is not sent again"
        );
        assert_eq!(follow.exchanges[0].response_size, 4096);
        assert!(follow.exchanges[0].pending);
    }

    #[test]
    fn text_is_found_without_case_in_any_script_and_slow_finds_what_took_long() {
        let store = store();
        exchange(
            &store,
            "GET",
            "https://xn--fsqu00a.test/搜索?q=Äpfel",
            200,
            "text/html",
        );
        let slow = exchange(&store, "GET", "https://a.test/slow", 200, "text/html");
        took(&slow, 1500);
        let waiting = store.begin(
            "GET",
            "https://a.test/waiting",
            "HTTP/1.1",
            HeaderList::new(),
        );
        std::thread::sleep(Duration::from_millis(30));
        let paths = |filter: ExchangeFilter| {
            urls(&query(&store, filtered(filter)))
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        for text in ["äPFEL", "搜索", "XN--FSQU00A"] {
            assert_eq!(
                paths(ExchangeFilter {
                    text: Some(text.into()),
                    ..Default::default()
                }),
                ["/搜索?q=Äpfel"],
                "{text}"
            );
        }
        assert_eq!(
            paths(ExchangeFilter {
                slow_ms: Some(1000),
                ..Default::default()
            }),
            ["/slow"]
        );
        assert_eq!(
            paths(ExchangeFilter {
                slow_ms: Some(20),
                statuses: vec![StatusClass::Pending],
                ..Default::default()
            }),
            ["/waiting"],
            "one in progress counts how long it has waited"
        );
        drop(waiting);
    }

    #[test]
    fn apps_are_compared_without_case() {
        let store = store();
        exchange(&store, "GET", "https://a.test/1", 200, "text/html")
            .attach(Some(&app(1, "Chrome")));
        let answer = query(
            &store,
            filtered(ExchangeFilter {
                apps: vec!["CHROME".into()],
                ..Default::default()
            }),
        );
        assert_eq!(urls(&answer), ["/1"]);
    }

    /// How long one query holds the store's lock over a full default capture:
    /// `cargo test --release -p concord-mitm --lib query_time -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement; run it in release"]
    fn query_time_over_a_full_capture() {
        let store = store();
        for i in 0..2000 {
            let cap = exchange(
                &store,
                if i % 3 == 0 { "POST" } else { "GET" },
                &format!("https://host{}.example.test/api/items/{i}?page=2", i % 50),
                [200, 404, 502, 0][i % 4],
                [
                    "application/json; charset=utf-8",
                    "text/html",
                    "image/png",
                    "",
                ][i % 4],
            );
            cap.attach(Some(&app(
                i as u64 % 20,
                ["chrome", "curl", "Telegram"][i % 3],
            )));
        }
        let page = |filter: ExchangeFilter, facets: bool| ExchangeQuery {
            filter,
            limit: Some(64),
            facets,
            rate_from_ms: facets.then_some(0),
            ..ExchangeQuery::default()
        };
        let text = |text: &str| ExchangeFilter {
            text: Some(text.into()),
            ..ExchangeFilter::default()
        };
        for (name, query) in [
            ("a page", page(ExchangeFilter::default(), false)),
            (
                "a page with facets and rate",
                page(ExchangeFilter::default(), true),
            ),
            ("text, facets and rate", page(text("items/19"), true)),
            ("non-ASCII text and facets", page(text("搜索"), true)),
        ] {
            let mut took: Vec<_> = (0..200)
                .map(|_| {
                    let start = std::time::Instant::now();
                    assert_eq!(store.query(&query).held, 2000);
                    start.elapsed()
                })
                .collect();
            took.sort_unstable();
            println!("{name}: p50 {:?}, p99 {:?}", took[100], took[198]);
        }
    }
}

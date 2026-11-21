use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use http::{HeaderMap, HeaderValue};

use crate::probe::ctx::{Ctx, ProbeError};
use crate::probe::fetch::{ProbeRequest, ProbeResult};
use crate::probe::hits::HitRecorder;
use crate::probe::rules::{
    self, Patterns, bilibili_status, chatgpt_ios_status, tiktok_region, tiktok_status,
    youtube_region,
};
use crate::probe::services::{
    AVAILABLE, BLOCKED, COMING_SOON, DISALLOWED_ISP, FAILED, ORIGINALS_ONLY, RESTRICTED, Requester,
    ServiceEnv, ServiceItem, TIMEOUT, UNAVAILABLE, UNSUPPORTED_REGION,
};

type Respond = dyn Fn(&ProbeRequest) -> Option<ProbeResult> + Send + Sync;

struct Script {
    respond: Box<Respond>,
    seen: Mutex<Vec<ProbeRequest>>,
}

#[async_trait]
impl Requester for Script {
    async fn request(&self, _ctx: &Ctx, request: ProbeRequest) -> Option<ProbeResult> {
        let answer = (self.respond)(&request);
        lock(&self.seen).push(request);
        answer
    }
}

fn scripted<F>(respond: F) -> Script
where
    F: Fn(&ProbeRequest) -> Option<ProbeResult> + Send + Sync + 'static,
{
    Script {
        respond: Box::new(respond),
        seen: Mutex::new(Vec::new()),
    }
}

fn answers(status: u16, body: &str) -> Option<ProbeResult> {
    Some(ProbeResult::answer(status, body))
}

fn fails(error: ProbeError) -> Option<ProbeResult> {
    Some(ProbeResult {
        error: Some(error),
        ..ProbeResult::default()
    })
}

async fn run<'s, F, Fut>(script: &'s Script, rule: F) -> ServiceItem
where
    F: FnOnce(&'s ServiceEnv<'s>) -> Fut,
    Fut: std::future::Future<Output = ServiceItem>,
{
    let patterns = Box::leak(Box::new(Patterns::new()));
    let ctx = Box::leak(Box::new(Ctx::new(Duration::from_secs(30))));
    let hits = Box::leak(Box::new(Arc::new(HitRecorder::default())));
    let env = Box::leak(Box::new(ServiceEnv {
        requester: script,
        ctx,
        proxy: "node-a",
        timeout: Duration::from_secs(5),
        hits,
        patterns,
    }));
    rule(env).await
}

fn url_is(request: &ProbeRequest, part: &str) -> bool {
    request.url.contains(part)
}

#[test]
fn chatgpt_ios_refusal_is_the_success_signal() {
    let cases = [
        ("Request is not allowed. Please try again later.", AVAILABLE),
        ("You may be connected to a disallowed ISP", DISALLOWED_ISP),
        ("Sorry, you have been blocked", BLOCKED),
        ("<html>something else entirely</html>", FAILED),
        ("", FAILED),
    ];
    for (body, want) in cases {
        assert_eq!(
            chatgpt_ios_status(&ProbeResult::answer(200, body)),
            want,
            "{body:?}"
        );
    }
}

#[test]
fn tiktok_status_reads_the_code_and_the_page() {
    let cases = [
        (200, r#"{"region":"JP"}"#, AVAILABLE),
        (403, "", UNSUPPORTED_REGION),
        (451, "", UNSUPPORTED_REGION),
        (200, "Access Denied", UNSUPPORTED_REGION),
        (
            200,
            "TikTok is not available in your region",
            UNSUPPORTED_REGION,
        ),
        (500, "", FAILED),
    ];
    for (code, body, want) in cases {
        assert_eq!(
            tiktok_status(&ProbeResult::answer(code, body)),
            want,
            "{code} {body:?}"
        );
    }
}

#[test]
fn tiktok_region_reads_the_app_context() {
    let patterns = Patterns::new();
    let cluster = r#"{"idc":"no1a","vdc":"no1a","region":"EU-TTP2","vregion":"EU-TTP2"}"#;
    let page = format!(
        r#"{cluster}{{"__DEFAULT_SCOPE__":{{"webapp.app-context":{{"language":"en","region":"GB","appId":1233}}}}}}"#
    );
    assert_eq!(tiktok_region(&patterns, &page), "GB");
    assert_eq!(tiktok_region(&patterns, cluster), "");
    assert_eq!(
        tiktok_region(
            &patterns,
            r#"{"webapp.app-context":{"region":"zh-Hant-TW"}}"#
        ),
        ""
    );
}

#[test]
fn bilibili_reads_the_leading_code() {
    let patterns = Patterns::new();
    let cases = [
        (
            r#"{"code":0,"message":"success","result":{"code":0,"accept_format":"hdf"#,
            AVAILABLE,
        ),
        (
            r#"{"code":-10403,"message":"region locked"}"#,
            UNSUPPORTED_REGION,
        ),
        (r#"{"code":-412,"message":"request blocked"}"#, FAILED),
        (r#"{"message":"success","result":{"code":0}}"#, FAILED),
        ("", FAILED),
    ];
    for (body, want) in cases {
        assert_eq!(bilibili_status(&patterns, body), want, "{body:?}");
    }
}

#[test]
fn spotify_prefers_the_redirected_path() {
    let patterns = Patterns::new();
    let redirected = ProbeResult {
        url: "https://www.spotify.com/de-de/".into(),
        body: r#"{"countryCode":"US"}"#.into(),
        ..ProbeResult::default()
    };
    assert_eq!(rules::spotify_region(&patterns, &redirected), "de");
    let direct = ProbeResult {
        url: "https://www.spotify.com/api/content/v1/country-selector".into(),
        body: r#"{"countryCode":"SE"}"#.into(),
        ..ProbeResult::default()
    };
    assert_eq!(rules::spotify_region(&patterns, &direct), "SE");
}

#[test]
fn youtube_region_patterns() {
    let patterns = Patterns::new();
    let bodies = [
        (r#"<span id="country-code"> GB </span>"#, "GB"),
        (r#"{"GL":"JP","other":1}"#, "JP"),
        (r#"{"countryCode":"KR"}"#, "KR"),
        (r#"{"country_code":"BR"}"#, "BR"),
        ("nothing", ""),
    ];
    for (body, want) in bodies {
        assert_eq!(youtube_region(&patterns, body), want, "{body:?}");
    }
}

#[tokio::test]
async fn reachable_follows_the_status_code() {
    for (code, want) in [(204, AVAILABLE), (403, RESTRICTED), (404, UNAVAILABLE)] {
        let script = scripted(move |_| answers(code, ""));
        let item = run(&script, |env| {
            rules::reachable(env, "https://example.test/")
        })
        .await;
        assert_eq!(item.status, want, "{code}");
    }
    let script = scripted(|_| fails(ProbeError::Timeout));
    let item = run(&script, |env| {
        rules::reachable(env, "https://example.test/")
    })
    .await;
    assert_eq!(item.status, TIMEOUT);
}

#[tokio::test]
async fn claude_reads_the_trace_location_and_address() {
    for (body, status, region, ip) in [
        (
            "fl=1\nip=198.51.100.9\nloc=JP\n",
            AVAILABLE,
            "JP",
            "198.51.100.9",
        ),
        ("loc=cn\n", UNSUPPORTED_REGION, "CN", ""),
        ("loc=HK", UNSUPPORTED_REGION, "HK", ""),
        ("fl=1\nip=2001:db8::7\n", FAILED, "", "2001:db8::7"),
        ("loc=T1\n", FAILED, "", ""),
    ] {
        let script = scripted(move |_| answers(200, body));
        let item = run(&script, |env| rules::claude(env)).await;
        assert_eq!(
            (item.status, item.region.as_str(), item.ip.as_str()),
            (status, region, ip),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn gemini_reads_the_marker_and_stops_scanning_at_it() {
    for (body, status, region) in [
        (r#"junk,2,1,200,"JPNrest"#, AVAILABLE, "JP"),
        (r#"junk,2,1,200,"CHNrest"#, UNSUPPORTED_REGION, "CN"),
        (r#"junk,2,1,200,"HKGrest"#, UNSUPPORTED_REGION, "HK"),
        (r#"junk,2,1,200,"jpnrest"#, FAILED, ""),
        (r#"junk,2,1,200,"JP"#, FAILED, ""),
        ("no marker", FAILED, ""),
    ] {
        let script = scripted(move |_| answers(200, body));
        let item = run(&script, |env| rules::gemini(env)).await;
        assert_eq!(
            (item.status, item.region.as_str()),
            (status, region),
            "{body:?}"
        );

        let seen = lock(&script.seen);
        let until = seen[0].until.as_ref().expect("the page is scanned");
        assert!(until(r#"x,2,1,200,"JPN"#));
        assert!(!until(r#"x,2,1,200,"JP"#));
    }
}

#[tokio::test]
async fn chatgpt_folds_ios_trace_and_web_into_one_entry() {
    let script = scripted(|request| match request.url.as_str() {
        url if url.contains("ios.chat") => {
            answers(403, "Request is not allowed. Please try again later.")
        }
        url if url.contains("cdn-cgi/trace") => answers(200, "ip=2001:db8::7\nloc=jp\n"),
        _ => answers(200, "{}"),
    });
    let item = run(&script, |env| rules::chatgpt(env)).await;
    assert_eq!(
        (item.status, item.region.as_str(), item.ip.as_str()),
        (AVAILABLE, "JP", "2001:db8::7")
    );

    let silent_trace = scripted(|request| match request.url.as_str() {
        url if url.contains("ios.chat") => {
            answers(403, "Request is not allowed. Please try again later.")
        }
        url if url.contains("cdn-cgi/trace") => fails(ProbeError::Timeout),
        _ => answers(200, "{}"),
    });
    let item = run(&silent_trace, |env| rules::chatgpt(env)).await;
    assert_eq!(
        (item.status, item.region.as_str(), item.ip.as_str()),
        (AVAILABLE, "", "")
    );

    let blocked = scripted(|request| match request.url.as_str() {
        url if url.contains("ios.chat") => {
            answers(403, "Request is not allowed. Please try again later.")
        }
        url if url.contains("cookie_requirements") => {
            answers(400, r#"{"error":"unsupported_country"}"#)
        }
        _ => answers(200, "loc=CN"),
    });
    let item = run(&blocked, |env| rules::chatgpt(env)).await;
    assert_eq!(
        (item.status, item.region.as_str()),
        (UNSUPPORTED_REGION, "CN")
    );

    let down = scripted(|request| {
        if request.url.contains("ios.chat") {
            fails(ProbeError::Timeout)
        } else {
            answers(200, "")
        }
    });
    assert_eq!(run(&down, |env| rules::chatgpt(env)).await.status, TIMEOUT);
}

#[tokio::test]
async fn youtube_premium_judges_the_page() {
    for (code, body, status) in [
        (200, "<title>YouTube Premium</title>", AVAILABLE),
        (
            200,
            "Premium is not available in your country",
            UNSUPPORTED_REGION,
        ),
        (200, "plain", AVAILABLE),
        (404, "plain", UNAVAILABLE),
        (403, "forbidden", RESTRICTED),
    ] {
        let script = scripted(move |_| answers(code, body));
        let item = run(&script, |env| rules::youtube_premium(env)).await;
        assert_eq!(item.status, status, "{code} {body:?}");
    }
}

#[tokio::test]
async fn spotify_judges_code_and_payload() {
    for (code, body, status, region) in [
        (200, r#"{"countryCode":"SE"}"#, AVAILABLE, "SE"),
        (403, "", UNSUPPORTED_REGION, ""),
        (200, "Not available in your country", UNSUPPORTED_REGION, ""),
        (500, "", UNAVAILABLE, ""),
    ] {
        let script = scripted(move |_| {
            Some(ProbeResult {
                url: "https://www.spotify.com/api/content/v1/country-selector".into(),
                ..ProbeResult::answer(code, body)
            })
        });
        let item = run(&script, |env| rules::spotify(env)).await;
        assert_eq!(
            (item.status, item.region.as_str()),
            (status, region),
            "{code} {body:?}"
        );
    }
}

#[tokio::test]
async fn discord_reads_the_region_only_when_available() {
    let script = scripted(|_| answers(200, r#"{"country_code":"us"}"#));
    let item = run(&script, |env| rules::discord(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, "US"));

    let script = scripted(|_| answers(403, r#"{"country_code":"us"}"#));
    let item = run(&script, |env| rules::discord(env)).await;
    assert_eq!((item.status, item.region.as_str()), (RESTRICTED, ""));
}

#[tokio::test]
async fn prime_video_reads_the_territory() {
    for (body, status, region) in [
        (r#"x"currentTerritory":"NL"y"#, AVAILABLE, "NL"),
        ("isServiceRestricted", UNSUPPORTED_REGION, ""),
        ("nothing", FAILED, ""),
    ] {
        let script = scripted(move |_| answers(200, body));
        let item = run(&script, |env| rules::prime_video(env)).await;
        assert_eq!(
            (item.status, item.region.as_str()),
            (status, region),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn tiktok_reads_status_and_region() {
    let page = r#"{"webapp.app-context":{"region":"GB"}}"#;
    let script = scripted(move |_| answers(200, page));
    let item = run(&script, |env| rules::tiktok(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, "GB"));
}

#[tokio::test]
async fn bilibili_falls_back_to_the_other_catalogue() {
    let mainland = scripted(|_| answers(200, r#"{"code":0}"#));
    let item = run(&mainland, |env| rules::bilibili(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, "CN"));

    let elsewhere = scripted(|request| {
        if url_is(request, "avid=82846771") {
            answers(200, r#"{"code":-10403}"#)
        } else {
            answers(200, r#"{"code":0}"#)
        }
    });
    let item = run(&elsewhere, |env| rules::bilibili(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, ""));
    assert_eq!(lock(&elsewhere.seen).len(), 2);

    let neither = scripted(|_| answers(200, r#"{"code":-412}"#));
    assert_eq!(
        run(&neither, |env| rules::bilibili(env)).await.status,
        FAILED
    );
    assert_eq!(lock(&neither.seen).len(), 1);
}

fn netflix_script(
    cdn: Option<ProbeResult>,
    first: u16,
    second: u16,
    location: &'static str,
) -> Script {
    let cdn = Mutex::new(cdn);
    scripted(move |request| {
        if url_is(request, "api.fast.com") {
            return lock(&cdn).take();
        }
        if url_is(request, "80018499") {
            assert!(request.no_redirect);
            let mut headers = HeaderMap::new();
            headers.insert("location", HeaderValue::from_static(location));
            return Some(ProbeResult {
                headers,
                ..ProbeResult::answer(302, "")
            });
        }
        answers(
            if url_is(request, "81280792") {
                first
            } else {
                second
            },
            "",
        )
    })
}

#[tokio::test]
async fn netflix_prefers_the_cdn_answer() {
    let cdn = answers(
        200,
        r#"{"targets":[{"location":{"city":"Tokyo","country":"JP"}}]}"#,
    );
    let script = netflix_script(cdn, 404, 404, "");
    let item = run(&script, |env| rules::netflix(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, "JP"));
    assert_eq!(lock(&script.seen).len(), 1);

    let script = netflix_script(answers(403, ""), 200, 200, "");
    assert_eq!(
        run(&script, |env| rules::netflix(env)).await.status,
        BLOCKED
    );
}

#[tokio::test]
async fn netflix_falls_back_to_the_title_pages() {
    let cases = [
        (404, 404, "", ORIGINALS_ONLY, ""),
        (403, 200, "", UNSUPPORTED_REGION, ""),
        (
            200,
            404,
            "https://www.netflix.com/jp-en/title/80018499",
            AVAILABLE,
            "JP",
        ),
        (
            404,
            301,
            "https://www.netflix.com/us/title/80018499",
            AVAILABLE,
            "US",
        ),
        (200, 404, "https://www.netflix.com/", AVAILABLE, ""),
        (500, 500, "", UNAVAILABLE, ""),
    ];
    for (first, second, location, status, region) in cases {
        let script = netflix_script(answers(200, "not json"), first, second, location);
        let item = run(&script, |env| rules::netflix(env)).await;
        assert_eq!(
            (item.status, item.region.as_str()),
            (status, region),
            "{first} {second}"
        );
    }

    let script = scripted(|request| {
        if url_is(request, "81280792") {
            None
        } else {
            answers(200, "")
        }
    });
    let item = run(&script, |env| rules::netflix(env)).await;
    assert_eq!(item.status, FAILED, "the first title page did not answer");
}

fn disney_script(device: u16, token: &'static str, session: &'static str) -> Script {
    scripted(move |request| {
        if url_is(request, "/devices") {
            answers(device, r#"{"assertion":"a b/c+d"}"#)
        } else if url_is(request, "/token") {
            answers(200, token)
        } else {
            answers(200, session)
        }
    })
}

#[tokio::test]
async fn disney_walks_the_handshake() {
    let script = disney_script(
        200,
        r#"{"refresh_token":"refresh-1"}"#,
        r#"{"countryCode":"JP","inSupportedLocation":true}"#,
    );
    let item = run(&script, |env| rules::disney_plus(env)).await;
    assert_eq!((item.status, item.region.as_str()), (AVAILABLE, "JP"));

    let seen = lock(&script.seen);
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|request| request.method == http::Method::POST)
    );
    assert!(
        seen[0]
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "))
    );
    let form = String::from_utf8(seen[1].body.clone()).unwrap();
    assert!(
        form.contains("subject_token=a+b%2Fc%2Bd&subject_token_type="),
        "{form}"
    );
    assert!(String::from_utf8_lossy(&seen[2].body).contains(r#""refreshToken":"refresh-1""#));
}

#[tokio::test]
async fn disney_stops_where_the_address_is_turned_away() {
    let ok_token = r#"{"refresh_token":"r"}"#;
    let ok_session = r#"{"countryCode":"JP","inSupportedLocation":true}"#;
    let cases: [(Script, &str, &str); 8] = [
        (
            disney_script(403, ok_token, ok_session),
            BLOCKED,
            "device 403",
        ),
        (
            disney_script(200, "forbidden-location", ok_session),
            BLOCKED,
            "forbidden",
        ),
        (
            disney_script(200, "403 ERROR", ok_session),
            BLOCKED,
            "403 error",
        ),
        (
            disney_script(200, "{}", ok_session),
            FAILED,
            "no refresh token",
        ),
        (
            disney_script(200, ok_token, r#"{"inSupportedLocation":true}"#),
            UNAVAILABLE,
            "no country",
        ),
        (
            disney_script(
                200,
                ok_token,
                r#"{"countryCode":"JP","inSupportedLocation":false}"#,
            ),
            COMING_SOON,
            "not yet",
        ),
        (
            disney_script(200, ok_token, r#"{"countryCode":"JP"}"#),
            FAILED,
            "no verdict",
        ),
        (disney_script(200, ok_token, ""), FAILED, "empty session"),
    ];
    for (script, status, label) in cases {
        let item = run(&script, |env| rules::disney_plus(env)).await;
        assert_eq!(item.status, status, "{label}");
    }

    let no_assertion = scripted(|_| answers(200, "{}"));
    assert_eq!(
        run(&no_assertion, |env| rules::disney_plus(env))
            .await
            .status,
        FAILED
    );
}

#[tokio::test]
async fn the_service_env_sends_the_browser_agent_unless_overridden() {
    let script = scripted(|_| answers(200, ""));
    run(&script, |env| {
        rules::reachable(env, "https://example.test/")
    })
    .await;
    run(&script, |env| rules::disney_plus(env)).await;

    let seen = lock(&script.seen);
    assert!(
        seen[0]
            .headers
            .iter()
            .any(|(name, value)| name == "User-Agent" && value.starts_with("Mozilla/5.0"))
    );
    assert_eq!(seen[0].proxy, "node-a");
    assert_eq!(seen[0].timeout, Duration::from_secs(5));
    assert!(seen[0].recorder.is_some());
    assert!(seen[1].headers.iter().any(|(name, _)| name == "User-Agent"));
}

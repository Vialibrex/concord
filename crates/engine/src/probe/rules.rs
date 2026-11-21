use std::sync::Arc;

use http::Method;
use regex::Regex;
use serde::Deserialize;
use url::Url;

use super::fetch::{ProbeRequest, ProbeResult};
use super::region::{is_ascii_upper, normalize_region};
use super::services::{
    AVAILABLE, BLOCKED, COMING_SOON, DISALLOWED_ISP, FAILED, HTML_MAX_BODY, ORIGINALS_ONLY,
    SMALL_MAX_BODY, ServiceEnv, ServiceItem, UNAVAILABLE, UNSUPPORTED_REGION, answered, item_from,
    status_from_code, trace_ip, trace_value,
};

/// The public browser client token Disney+ hands to any web visitor; the device
/// and token calls are rejected without it.
const DISNEY_AUTH: &str =
    "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84";
const GEMINI_REGION_MARKER: &str = ",2,1,200,\"";
const CLAUDE_BLOCKED_REGIONS: [&str; 10] =
    ["AF", "BY", "CN", "CU", "HK", "IR", "KP", "MO", "RU", "SY"];
const GEMINI_BLOCKED_REGIONS: [&str; 9] = [
    "CHN", "RUS", "BLR", "CUB", "IRN", "PRK", "SYR", "HKG", "MAC",
];

pub struct Patterns {
    youtube_region: Vec<Regex>,
    tiktok_region: Regex,
    prime_region: Regex,
    disney_assertion: Regex,
    disney_refresh: Regex,
    disney_country: Regex,
    disney_supported: Regex,
    spotify_country: Regex,
    discord_country: Regex,
    bilibili_code: Regex,
}

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("probe pattern")
}

impl Patterns {
    pub fn new() -> Self {
        Self {
            youtube_region: [
                r#"(?i)id=["']country-code["'][^>]*>\s*([A-Za-z]{2,3})\s*<"#,
                r#""GL"\s*:\s*"([A-Za-z]{2})""#,
                r#""countryCode"\s*:\s*"([A-Za-z]{2})""#,
                r#""country_code"\s*:\s*"([A-Za-z]{2})""#,
            ]
            .map(pattern)
            .to_vec(),
            tiktok_region: pattern(
                r#""webapp\.app-context"\s*:\s*\{[^{}]*?"region"\s*:\s*"([^"]*)""#,
            ),
            prime_region: pattern(r#""currentTerritory":"([^"]+)""#),
            disney_assertion: pattern(r#""assertion"\s*:\s*"([^"]+)""#),
            disney_refresh: pattern(r#""refresh_token"\s*:\s*"([^"]+)""#),
            disney_country: pattern(r#""countryCode"\s*:\s*"([^"]+)""#),
            disney_supported: pattern(r#""inSupportedLocation"\s*:\s*(false|true)"#),
            spotify_country: pattern(r#""countryCode"\s*:\s*"([^"]+)""#),
            discord_country: pattern(r#""country_code"\s*:\s*"([^"]+)""#),
            bilibili_code: pattern(r#"^\s*\{\s*"code"\s*:\s*(-?\d+)"#),
        }
    }
}

fn first_submatch(pattern: &Regex, body: &str) -> String {
    pattern
        .captures(body)
        .and_then(|captures| captures.get(1))
        .map(|group| group.as_str().to_string())
        .unwrap_or_default()
}

pub async fn reachable(env: &ServiceEnv<'_>, url: &str) -> ServiceItem {
    let result = env.get(url, 0).await;
    let mut item = item_from(result.as_ref());
    if let Some(result) = answered(&item, &result) {
        item.status = status_from_code(result.status);
    }
    item
}

pub async fn claude(env: &ServiceEnv<'_>) -> ServiceItem {
    let result = env
        .get("https://claude.ai/cdn-cgi/trace", SMALL_MAX_BODY)
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    item.ip = trace_ip(&result.body);
    let region = normalize_region(&trace_value(&result.body, "loc"));
    if region.is_empty() {
        item.status = FAILED;
        return item;
    }
    item.status = if CLAUDE_BLOCKED_REGIONS.contains(&region.as_str()) {
        UNSUPPORTED_REGION
    } else {
        AVAILABLE
    };
    item.region = region;
    item
}

pub async fn gemini(env: &ServiceEnv<'_>) -> ServiceItem {
    let result = env
        .scan(
            "https://gemini.google.com",
            Arc::new(|tail: &str| gemini_code(tail).is_some()),
        )
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    let Some(code) = gemini_code(&result.body).filter(|code| is_ascii_upper(code)) else {
        item.status = FAILED;
        return item;
    };
    item.region = normalize_region(code);
    item.status = if GEMINI_BLOCKED_REGIONS.contains(&code) {
        UNSUPPORTED_REGION
    } else {
        AVAILABLE
    };
    item
}

fn gemini_code(text: &str) -> Option<&str> {
    let start = text.find(GEMINI_REGION_MARKER)? + GEMINI_REGION_MARKER.len();
    text.get(start..start + 3)
}

/// Folds Verge's separate iOS and Web results into one entry: the card shows a
/// single row per service, and a split would put two identical OpenAI icons next
/// to each other.
pub async fn chatgpt(env: &ServiceEnv<'_>) -> ServiceItem {
    let ios = env
        .get("https://ios.chat.openai.com/", SMALL_MAX_BODY)
        .await;
    let mut item = item_from(ios.as_ref());
    if let Some(ios) = answered(&item, &ios) {
        item.status = chatgpt_ios_status(ios);
    }

    let trace = env
        .get("https://chat.openai.com/cdn-cgi/trace", SMALL_MAX_BODY)
        .await;
    if let Some(trace) = answered(&item_from(trace.as_ref()), &trace) {
        item.region = normalize_region(&trace_value(&trace.body, "loc"));
        item.ip = trace_ip(&trace.body);
    }

    let web = env
        .get(
            "https://api.openai.com/compliance/cookie_requirements",
            SMALL_MAX_BODY,
        )
        .await;
    if let Some(web) = answered(&item_from(web.as_ref()), &web)
        && web.body_contains(&["unsupported_country"])
    {
        item.status = UNSUPPORTED_REGION;
    }
    item
}

pub fn chatgpt_ios_status(result: &ProbeResult) -> &'static str {
    if result.body_contains(&["you may be connected to a disallowed isp"]) {
        DISALLOWED_ISP
    } else if result.body_contains(&["sorry, you have been blocked"]) {
        BLOCKED
    } else if result.body_contains(&["request is not allowed. please try again later."]) {
        AVAILABLE
    } else {
        FAILED
    }
}

pub async fn youtube_premium(env: &ServiceEnv<'_>) -> ServiceItem {
    let result = env
        .get("https://www.youtube.com/premium?hl=en", HTML_MAX_BODY)
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    item.region = youtube_region(env.patterns, &result.body);
    item.status = if result.body_contains(&[
        "youtube premium is not available in your country",
        "premium is not available in your country",
        "premium is not available in your region",
    ]) {
        UNSUPPORTED_REGION
    } else if (200..300).contains(&result.status)
        && result.body_contains(&["youtube premium", "ad-free", r#""browseid":"spunlimited""#])
    {
        AVAILABLE
    } else {
        status_from_code(result.status)
    };
    item
}

pub fn youtube_region(patterns: &Patterns, body: &str) -> String {
    patterns
        .youtube_region
        .iter()
        .map(|pattern| first_submatch(pattern, body))
        .find(|code| !code.is_empty())
        .map(|code| normalize_region(&code))
        .unwrap_or_default()
}

pub async fn spotify(env: &ServiceEnv<'_>) -> ServiceItem {
    let result = env
        .get(
            "https://www.spotify.com/api/content/v1/country-selector?platform=web&format=json",
            SMALL_MAX_BODY,
        )
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    item.region = normalize_region(&spotify_region(env.patterns, result));
    item.status = if matches!(result.status, 403 | 451) {
        UNSUPPORTED_REGION
    } else if !(200..300).contains(&result.status) {
        status_from_code(result.status)
    } else if result.body_contains(&["not available in your country"]) {
        UNSUPPORTED_REGION
    } else {
        AVAILABLE
    };
    item
}

/// Prefers the country Spotify redirected the request into, and falls back to the
/// one named in the payload.
pub fn spotify_region(patterns: &Patterns, result: &ProbeResult) -> String {
    if let Ok(final_url) = Url::parse(&result.url) {
        let first = final_url.path().trim_matches('/').split('/').next();
        if let Some(first) = first.filter(|first| !first.is_empty() && *first != "api") {
            return first.split('-').next().unwrap_or_default().to_string();
        }
    }
    first_submatch(&patterns.spotify_country, &result.body)
}

/// TikTok is not behind Cloudflare: `/cdn-cgi/trace` redirects to a 404 page.
pub async fn tiktok(env: &ServiceEnv<'_>) -> ServiceItem {
    let region = env.patterns.tiktok_region.clone();
    let result = env
        .scan(
            "https://www.tiktok.com/",
            Arc::new(move |tail: &str| region.is_match(tail)),
        )
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    item.status = tiktok_status(result);
    item.region = tiktok_region(env.patterns, &result.body);
    item
}

pub fn tiktok_status(result: &ProbeResult) -> &'static str {
    if matches!(result.status, 403 | 451) {
        UNSUPPORTED_REGION
    } else if !(200..300).contains(&result.status) {
        FAILED
    } else if result.body_contains(&[
        "access denied",
        "not available in your region",
        "tiktok is not available",
    ]) {
        UNSUPPORTED_REGION
    } else {
        AVAILABLE
    }
}

/// The page names its serving cluster "region" too ("EU-TTP2"); the visitor's
/// country is the one in the web app's context.
pub fn tiktok_region(patterns: &Patterns, body: &str) -> String {
    normalize_region(&first_submatch(&patterns.tiktok_region, body))
}

pub async fn bilibili(env: &ServiceEnv<'_>) -> ServiceItem {
    const MAINLAND: &str = "https://api.bilibili.com/pgc/player/web/playurl?avid=82846771&qn=0&type=&otype=json&ep_id=307247&fourk=1&fnver=0&fnval=16&module=bangumi";
    const HONG_KONG_MACAU_TAIWAN: &str = "https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1&fnver=0&fnval=16&module=bangumi";
    let mut item = bilibili_episode(env, MAINLAND).await;
    match item.status {
        AVAILABLE => {
            item.region = "CN".to_string();
            item
        }
        UNSUPPORTED_REGION => bilibili_episode(env, HONG_KONG_MACAU_TAIWAN).await,
        _ => item,
    }
}

async fn bilibili_episode(env: &ServiceEnv<'_>, url: &str) -> ServiceItem {
    let result = env.get(url, SMALL_MAX_BODY).await;
    let mut item = item_from(result.as_ref());
    if let Some(result) = answered(&item, &result) {
        item.status = bilibili_status(env.patterns, &result.body);
    }
    item
}

/// A playable episode runs past the small body cap; only its leading code is read.
pub fn bilibili_status(patterns: &Patterns, body: &str) -> &'static str {
    match first_submatch(&patterns.bilibili_code, body).as_str() {
        "0" => AVAILABLE,
        "-10403" => UNSUPPORTED_REGION,
        _ => FAILED,
    }
}

pub async fn discord(env: &ServiceEnv<'_>) -> ServiceItem {
    let result = env
        .get(
            "https://discord.com/api/v9/auth/location-metadata",
            SMALL_MAX_BODY,
        )
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    item.status = status_from_code(result.status);
    if item.status == AVAILABLE {
        item.region =
            normalize_region(&first_submatch(&env.patterns.discord_country, &result.body));
    }
    item
}

pub async fn prime_video(env: &ServiceEnv<'_>) -> ServiceItem {
    let region = env.patterns.prime_region.clone();
    let result = env
        .scan(
            "https://www.primevideo.com",
            Arc::new(move |tail: &str| {
                tail.contains("isServiceRestricted") || region.is_match(tail)
            }),
        )
        .await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    if result.body.contains("isServiceRestricted") {
        item.status = UNSUPPORTED_REGION;
        return item;
    }
    let region = first_submatch(&env.patterns.prime_region, &result.body);
    if region.is_empty() {
        item.status = FAILED;
        return item;
    }
    item.region = normalize_region(&region);
    item.status = AVAILABLE;
    item
}

pub async fn netflix(env: &ServiceEnv<'_>) -> ServiceItem {
    let from_cdn = netflix_from_cdn(env).await;
    if matches!(from_cdn.status, AVAILABLE | BLOCKED) {
        return from_cdn;
    }

    let first = env.get("https://www.netflix.com/title/81280792", 0).await;
    let first_item = item_from(first.as_ref());
    let Some(first) = answered(&first_item, &first) else {
        return first_item;
    };
    let second = env.get("https://www.netflix.com/title/70143836", 0).await;
    let second_item = item_from(second.as_ref());
    let Some(second) = answered(&second_item, &second) else {
        return second_item;
    };

    let mut item = first_item.clone();
    if first.status == 404 && second.status == 404 {
        item.status = ORIGINALS_ONLY;
    } else if first.status == 403 || second.status == 403 {
        item.status = UNSUPPORTED_REGION;
    } else if netflix_served(first.status) || netflix_served(second.status) {
        item.status = AVAILABLE;
        item.region = netflix_region(env).await;
    } else {
        item.status = status_from_code(first.status);
    }
    item
}

fn netflix_served(code: u16) -> bool {
    matches!(code, 200 | 301)
}

/// Reads the country out of the redirect Netflix would send a visitor to, so the
/// redirect must not be followed.
async fn netflix_region(env: &ServiceEnv<'_>) -> String {
    let mut request = ProbeRequest::get("https://www.netflix.com/title/80018499");
    request.no_redirect = true;
    let Some(result) = env
        .send(request)
        .await
        .filter(|result| result.error.is_none())
    else {
        return String::new();
    };
    let location = result
        .headers
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let segments: Vec<&str> = location.split('/').collect();
    segments
        .get(3)
        .and_then(|segment| segment.split('-').next())
        .map(normalize_region)
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct FastPayload {
    targets: Vec<FastTarget>,
}

#[derive(Deserialize)]
struct FastTarget {
    location: FastLocation,
}

#[derive(Deserialize)]
struct FastLocation {
    country: String,
}

async fn netflix_from_cdn(env: &ServiceEnv<'_>) -> ServiceItem {
    const URL: &str = "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=5";
    let result = env.get(URL, SMALL_MAX_BODY).await;
    let mut item = item_from(result.as_ref());
    let Some(result) = answered(&item, &result) else {
        return item;
    };
    if result.status == 403 {
        item.status = BLOCKED;
        return item;
    }
    match serde_json::from_str::<FastPayload>(&result.body)
        .ok()
        .and_then(|payload| payload.targets.into_iter().next())
    {
        Some(target) => {
            item.region = normalize_region(&target.location.country);
            item.status = AVAILABLE;
        }
        None => item.status = FAILED,
    }
    item
}

fn disney_request(url: &str, content_type: &str, body: String) -> ProbeRequest {
    let mut request = ProbeRequest::get(url);
    request.method = Method::POST;
    request.headers = vec![
        ("authorization".to_string(), DISNEY_AUTH.to_string()),
        ("content-type".to_string(), content_type.to_string()),
    ];
    request.body = body.into_bytes();
    request.max_body = SMALL_MAX_BODY;
    request
}

/// Walks the browser hand-shake: register a device, exchange the assertion for a
/// refresh token, then ask the session which region it landed in. Any step can
/// answer on its own that the address is not welcome.
pub async fn disney_plus(env: &ServiceEnv<'_>) -> ServiceItem {
    let patterns = env.patterns;
    let device = env
        .send(disney_request(
            "https://disney.api.edge.bamgrid.com/devices",
            "application/json; charset=UTF-8",
            r#"{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}"#
                .to_string(),
        ))
        .await;
    let mut item = item_from(device.as_ref());
    let Some(device) = answered(&item, &device) else {
        return item;
    };
    if device.status == 403 {
        item.status = BLOCKED;
        return item;
    }
    let assertion = first_submatch(&patterns.disney_assertion, &device.body);
    if assertion.is_empty() {
        item.status = FAILED;
        return item;
    }

    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&latitude=0&longitude=0&platform=browser&subject_token={}&subject_token_type=urn:bamtech:params:oauth:token-type:device",
        query_escape(&assertion),
    );
    let token = env
        .send(disney_request(
            "https://disney.api.edge.bamgrid.com/token",
            "application/x-www-form-urlencoded",
            form,
        ))
        .await;
    let Some(token) = answered(&item_from(token.as_ref()), &token) else {
        return item_from(token.as_ref());
    };
    if token.body.contains("forbidden-location") || token.body.contains("403 ERROR") {
        item.status = BLOCKED;
        return item;
    }
    let refresh = first_submatch(&patterns.disney_refresh, &token.body);
    if refresh.is_empty() {
        item.status = FAILED;
        return item;
    }

    let query = format!(
        r#"{{"query":"mutation refreshToken($input: RefreshTokenInput!) {{ refreshToken(refreshToken: $input) {{ activeSession {{ sessionId }} }} }}","variables":{{"input":{{"refreshToken":"{refresh}"}}}}}}"#
    );
    let session = env
        .send(disney_request(
            "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
            "application/json",
            query,
        ))
        .await;
    let session_item = item_from(session.as_ref());
    let Some(session) = answered(&session_item, &session)
        .filter(|session| !session.body.is_empty() && session.status < 400)
    else {
        item.status = FAILED;
        return item;
    };
    let region = normalize_region(&first_submatch(&patterns.disney_country, &session.body));
    if region.is_empty() {
        item.status = UNAVAILABLE;
        return item;
    }
    item.region = region;
    item.status = match first_submatch(&patterns.disney_supported, &session.body).as_str() {
        "true" => AVAILABLE,
        "false" => COMING_SOON,
        _ => FAILED,
    };
    item
}

/// Go's `url.QueryEscape`: everything but the unreserved set, a space as `+`.
fn query_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(char::from(byte));
            }
            b' ' => escaped.push('+'),
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

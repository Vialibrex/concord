use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;

use crate::http1::HeaderMap;

const GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const GREASE_VERSION: [&str; 3] = ["8", "99", "24"];
const SHUFFLE3: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];
const SHUFFLE4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];
const SAFARI_MINOR: [usize; 25] = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
];

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn year_of_days(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let year = yoe + era * 400;
    if mp >= 10 { year + 1 } else { year }
}

/// The user agent and client hints one client presents, picked once so every
/// request of a node agrees with the others.
#[derive(Clone, Debug)]
pub(crate) struct Browser {
    chrome_major: i64,
    chrome_ua: String,
    edge_ua: String,
    firefox_ua: String,
    safari_ua: String,
    curl_ua: String,
}

fn squared(rng: &mut impl RngExt) -> f64 {
    let x: f64 = rng.random();
    x * x
}

impl Browser {
    pub fn new() -> Browser {
        Browser::at(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
        )
    }

    fn at(now_secs: i64) -> Browser {
        let mut rng = rand::rng();
        let today = now_secs.div_euclid(86_400);

        let chrome_start = days_from_civil(2026, 1, 13);
        let diff = today - chrome_start - 35 - (squared(&mut rng) * 105.0).floor() as i64;
        let chrome_major = 144 + diff / 35;
        let chrome_ua = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
        );

        let curl_start = days_from_civil(2023, 3, 20);
        let diff = today - curl_start - 60 - (squared(&mut rng) * 165.0).floor() as i64;
        let curl_ua = format!("curl/8.{}.0", diff / 57);

        let firefox_start = days_from_civil(2024, 7, 29);
        let diff = today - firefox_start - 25 - (squared(&mut rng) * 50.0).floor() as i64;
        let firefox = diff / 30 + 128;
        let firefox_ua = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox}.0) Gecko/20100101 Firefox/{firefox}.0"
        );

        let mut release_year = year_of_days(today);
        let x: f64 = rng.random();
        let delay_days = (x * x * x * 75.0).floor() as i64;
        let mut split = days_from_civil(release_year, 9, 23) * 86_400 + delay_days * 86_400;
        if now_secs < split {
            release_year -= 1;
            split = days_from_civil(release_year, 9, 23) * 86_400 + delay_days * 86_400;
        }
        let index = usize::try_from((now_secs - split) / 1_296_000).unwrap_or(0);
        let minor = SAFARI_MINOR.get(index).copied().unwrap_or(6);
        let safari_ua = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{}.{minor} Safari/605.1.15",
            release_year - 1999
        );

        Browser {
            chrome_major,
            edge_ua: format!("{chrome_ua}Edg/{chrome_major}.0.0.0"),
            chrome_ua,
            firefox_ua,
            safari_ua,
            curl_ua,
        }
    }

    fn client_hints(&self, fork: &str) -> String {
        let seed = usize::try_from(self.chrome_major).unwrap_or(0);
        let na = |offset: usize| {
            GREASE_NA
                .get((seed + offset) % GREASE_NA.len())
                .copied()
                .unwrap_or(" ")
        };
        let version = GREASE_VERSION
            .get(seed % GREASE_VERSION.len())
            .copied()
            .unwrap_or("8");
        let mut brands = vec![
            format!("\"Not{}A{}Brand\";v=\"{version}\"", na(0), na(1)),
            format!("\"Chromium\";v=\"{}\"", self.chrome_major),
        ];
        match fork {
            "chrome" => brands.push(format!("\"Google Chrome\";v=\"{}\"", self.chrome_major)),
            "edge" => brands.push(format!("\"Microsoft Edge\";v=\"{}\"", self.chrome_major)),
            _ => {}
        }
        let order: Vec<usize> = match brands.len() {
            1 => vec![0],
            2 => vec![seed % 2, (seed + 1) % 2],
            3 => SHUFFLE3
                .get(seed % 6)
                .map(|o| o.to_vec())
                .unwrap_or_default(),
            _ => SHUFFLE4
                .get(seed % 24)
                .map(|o| o.to_vec())
                .unwrap_or_default(),
        };
        let mut shuffled = vec![String::new(); brands.len()];
        for (brand, target) in brands.into_iter().zip(order) {
            if let Some(slot) = shuffled.get_mut(target) {
                *slot = brand;
            }
        }
        shuffled.join(", ")
    }

    fn mask(&self, headers: &mut HeaderMap, browser: &str) {
        let hints = |headers: &mut HeaderMap, fork: &str, ua: &str| {
            headers.set_exact("Sec-CH-UA", &self.client_hints(fork));
            headers.set_exact("Sec-CH-UA-Mobile", "?0");
            headers.set_exact("Sec-CH-UA-Platform", "\"Windows\"");
            headers.set_exact("DNT", "1");
            headers.set("User-Agent", ua);
            headers.set("Accept-Language", "en-US,en;q=0.9");
        };
        match browser {
            "chrome" => hints(headers, "chrome", &self.chrome_ua),
            "edge" => hints(headers, "edge", &self.edge_ua),
            "firefox" => {
                headers.set("User-Agent", &self.firefox_ua);
                headers.set_exact("DNT", "1");
                headers.set("Accept-Language", "en-US,en;q=0.5");
            }
            "safari" => {
                headers.set("User-Agent", &self.safari_ua);
                headers.set("Accept-Language", "en-US,en;q=0.9");
            }
            "golang" => {
                headers.remove("User-Agent");
                return;
            }
            "curl" => {
                headers.set("User-Agent", &self.curl_ua);
                return;
            }
            _ => {}
        }
        headers.set("Sec-Fetch-Mode", "cors");
        headers.set("Sec-Fetch-Dest", "empty");
        headers.set("Sec-Fetch-Site", "same-origin");
        if headers.get("Priority").is_none() {
            match browser {
                "chrome" | "edge" => headers.set("Priority", "u=1, i"),
                "firefox" => headers.set("Priority", "u=4"),
                _ => headers.set("Priority", "u=3, i"),
            }
        }
        if headers.get("Cache-Control").is_none() {
            headers.set("Cache-Control", "no-cache");
        }
        if headers.get("Pragma").is_none() {
            headers.set("Pragma", "no-cache");
        }
        if headers.get("Accept").is_none() {
            headers.set("Accept", "*/*");
        }
    }

    /// `TryDefaultHeadersWith(header, "fetch")`.
    pub fn apply_fetch_defaults(&self, headers: &mut HeaderMap) {
        match headers.get("User-Agent") {
            None => self.mask(headers, "chrome"),
            Some(ua) => {
                let keyword = ua.to_string();
                if matches!(
                    keyword.as_str(),
                    "chrome" | "firefox" | "safari" | "edge" | "curl" | "golang"
                ) {
                    self.mask(headers, &keyword);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 1, 13), 20_466);
        assert_eq!(year_of_days(20_466), 2026);
        assert_eq!(year_of_days(days_from_civil(2025, 12, 31)), 2025);
    }

    #[test]
    fn default_headers_are_a_chrome_fetch() {
        let browser = Browser::at(days_from_civil(2026, 10, 31) * 86_400);
        assert!(browser.chrome_major >= 144);
        let mut headers = HeaderMap::default();
        browser.apply_fetch_defaults(&mut headers);
        assert!(headers.get("User-Agent").unwrap().contains("Chrome/"));
        assert_eq!(headers.get("Sec-Fetch-Mode"), Some("cors"));
        assert_eq!(headers.get("Priority"), Some("u=1, i"));
        assert_eq!(headers.get("Accept"), Some("*/*"));
        let hints = headers.get("Sec-CH-UA").unwrap();
        assert_eq!(hints.matches("Brand").count(), 1);
        assert!(hints.contains("Chromium"));
        assert!(hints.contains("Google Chrome"));
    }

    #[test]
    fn keyword_user_agents_are_expanded_and_custom_ones_left_alone() {
        let browser = Browser::at(days_from_civil(2026, 10, 31) * 86_400);
        let mut headers = HeaderMap::default();
        headers.set("User-Agent", "curl");
        browser.apply_fetch_defaults(&mut headers);
        assert!(headers.get("User-Agent").unwrap().starts_with("curl/8."));
        assert!(headers.get("Sec-Fetch-Mode").is_none());

        let mut headers = HeaderMap::default();
        headers.set("User-Agent", "golang");
        browser.apply_fetch_defaults(&mut headers);
        assert!(headers.get("User-Agent").is_none());

        let mut headers = HeaderMap::default();
        headers.set("User-Agent", "MyAgent/1");
        browser.apply_fetch_defaults(&mut headers);
        assert_eq!(headers.get("User-Agent"), Some("MyAgent/1"));
        assert!(headers.get("Accept").is_none());

        let mut headers = HeaderMap::default();
        headers.set("User-Agent", "firefox");
        browser.apply_fetch_defaults(&mut headers);
        assert!(headers.get("User-Agent").unwrap().contains("Firefox/"));
        assert_eq!(headers.get("Priority"), Some("u=4"));
    }
}

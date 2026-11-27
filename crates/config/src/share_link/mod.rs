mod decode;
mod encode;
mod plain_url;
mod urlx;
mod xhttp;

use crate::Map;
use crate::error::{ConfigError, Result};

pub fn decode_subscription(text: &str) -> Result<Vec<Map>> {
    decode::decode_subscription_text(text)
}

pub fn decode_subscription_bytes(bytes: &[u8]) -> Result<Vec<Map>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ConfigError::new("convert v2ray subscribe error: format invalid"))?;
    decode::decode_subscription_text(text)
}

pub fn decode_link(line: &str) -> Vec<Map> {
    decode::decode_link_line(line).unwrap_or_default()
}

pub fn encode_link(proxy: &Map) -> String {
    encode::encode_share_link(proxy)
}

#[cfg(test)]
mod tests;

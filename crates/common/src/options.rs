use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreOptions {
    /// An empty one keeps the URL in force.
    #[serde(rename = "test-url")]
    pub test_url: String,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: bool,
    /// Milliseconds; zero keeps the timeout in force.
    #[serde(rename = "delay-test-timeout")]
    pub delay_test_timeout: i64,
    #[serde(rename = "mitm-capture")]
    pub mitm_capture: bool,
    #[serde(rename = "mitm-trusted-ca")]
    pub mitm_trusted_ca: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl TunnelMode {
    pub const ALL: [Self; 3] = [TunnelMode::Rule, TunnelMode::Global, TunnelMode::Direct];

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.as_str().eq_ignore_ascii_case(text))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TunnelMode::Rule => "rule",
            TunnelMode::Global => "global",
            TunnelMode::Direct => "direct",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Silent,
}

impl LogLevel {
    pub const ALL: [Self; 5] = [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warning,
        LogLevel::Error,
        LogLevel::Silent,
    ];

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.as_str().eq_ignore_ascii_case(text))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Silent => "silent",
        }
    }
}

/// `strict` looks a process up only when a rule asks for it; `always` looks it up for every flow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindProcessMode {
    Always,
    #[default]
    Strict,
    Off,
}

impl FindProcessMode {
    pub const ALL: [Self; 3] = [
        FindProcessMode::Always,
        FindProcessMode::Strict,
        FindProcessMode::Off,
    ];

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.as_str().eq_ignore_ascii_case(text))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FindProcessMode::Always => "always",
            FindProcessMode::Strict => "strict",
            FindProcessMode::Off => "off",
        }
    }
}

pub const CONGESTION_CONTROLLERS: [&str; 3] = ["cubic", "reno", "bbr"];

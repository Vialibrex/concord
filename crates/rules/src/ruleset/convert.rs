//! `rule_set.compile` and `rule_set.dump`: text or YAML to `.mrs`, and `.mrs` back to text.

use std::fmt;

use serde_json::Value;

use super::{Behavior, Format, lines};
use crate::cidr_set::{IpCidrSet, parse_prefix};
use crate::domain_set::{DomainSet, DomainSetBuilder};
use crate::mrs::{self, MrsBehavior, MrsPayload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetInfo {
    pub behavior: Behavior,
    pub format: Format,
}

#[derive(Debug)]
pub struct CompiledRuleSet {
    pub info: SetInfo,
    /// The `.mrs` bytes to write beside the source; `None` when the set stays as it is.
    pub mrs: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileSetError {
    Empty,
    Mixed,
    Invalid,
}

impl CompileSetError {
    pub fn code(self) -> &'static str {
        match self {
            CompileSetError::Empty => "rule_set_empty",
            CompileSetError::Mixed => "rule_set_mixed",
            CompileSetError::Invalid => "rule_set_invalid",
        }
    }
}

impl fmt::Display for CompileSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CompileSetError::Empty => "rule set has no usable entries",
            CompileSetError::Mixed => "rule set mixes domains and IP ranges",
            CompileSetError::Invalid => "rule set is not a readable mrs file",
        })
    }
}

impl std::error::Error for CompileSetError {}

fn yaml_string_list(value: &Value) -> Option<Option<Vec<String>>> {
    match value {
        Value::Null => Some(None),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Some(text.clone()),
                Value::Number(num) => Some(num.to_string()),
                Value::Bool(flag) => Some(flag.to_string()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Some),
        _ => None,
    }
}

fn rule_set_entries(buf: &[u8]) -> (Format, Vec<String>) {
    if let Ok(text) = std::str::from_utf8(buf)
        && let Ok(parsed) = concord_config::yaml::parse_document_slow(text)
    {
        let payload = match parsed.root.get("payload") {
            Some(value) => yaml_string_list(value),
            None => Some(None),
        };
        let rules = match parsed.root.get("rules") {
            Some(value) => yaml_string_list(value),
            None => Some(None),
        };
        if let (Some(payload), Some(rules)) = (payload, rules)
            && (payload.is_some() || rules.is_some())
        {
            let entries = [payload, rules]
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect();
            return (Format::Yaml, entries);
        }
    }
    (Format::Text, lines::text_items(buf))
}

fn parse_cidr(entry: &str) -> Option<String> {
    if parse_prefix(entry).is_some() {
        return Some(entry.to_string());
    }
    let ip: std::net::IpAddr = entry.parse().ok()?;
    Some(format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
}

fn plain_domain(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('.') && !value.contains(['+', '*', '/'])
}

fn classify_classical(entries: &[String]) -> (Behavior, Vec<String>) {
    let mut domains = Vec::new();
    let mut cidrs = Vec::new();
    for entry in entries {
        let Some((rule_type, value)) = entry.split_once(',') else {
            return (Behavior::Classical, Vec::new());
        };
        if value.contains(',') {
            return (Behavior::Classical, Vec::new());
        }
        let value = value.trim();
        match rule_type.trim().to_uppercase().as_str() {
            "DOMAIN" if plain_domain(value) => domains.push(value.to_string()),
            "DOMAIN-SUFFIX" if plain_domain(value) => domains.push(format!("+.{value}")),
            "IP-CIDR" | "IP-CIDR6" if parse_prefix(value).is_some() => {
                cidrs.push(value.to_string())
            }
            _ => return (Behavior::Classical, Vec::new()),
        }
    }
    if cidrs.is_empty() {
        (Behavior::Domain, domains)
    } else if domains.is_empty() {
        (Behavior::IpCidr, cidrs)
    } else {
        (Behavior::Classical, Vec::new())
    }
}

pub(super) fn classify(entries: &[String]) -> Result<(Behavior, Vec<String>), CompileSetError> {
    if entries.is_empty() {
        return Err(CompileSetError::Empty);
    }
    if entries.iter().any(|entry| entry.contains(',')) {
        return Ok(classify_classical(entries));
    }
    let cidrs: Vec<String> = entries
        .iter()
        .filter_map(|entry| parse_cidr(entry))
        .collect();
    if cidrs.is_empty() {
        Ok((Behavior::Domain, entries.to_vec()))
    } else if cidrs.len() == entries.len() {
        Ok((Behavior::IpCidr, cidrs))
    } else {
        Err(CompileSetError::Mixed)
    }
}

fn encode_keys(behavior: Behavior, keys: &[String]) -> Result<Vec<u8>, CompileSetError> {
    let lines = lines::text_items(keys.join("\n").as_bytes());
    match behavior {
        Behavior::Domain => {
            let mut builder = DomainSetBuilder::new();
            let mut count = 0u64;
            for line in lines.iter().filter(|l| !l.contains('/')) {
                if builder.insert(line).is_ok() {
                    count += 1;
                }
            }
            let set = builder.build().ok_or(CompileSetError::Empty)?;
            Ok(mrs::encode(count, &MrsPayload::Domain(set)))
        }
        Behavior::IpCidr => {
            let mut set = IpCidrSet::new();
            let mut count = 0u64;
            for line in &lines {
                if set.add_str(line) {
                    count += 1;
                }
            }
            if count == 0 {
                return Err(CompileSetError::Empty);
            }
            set.merge();
            Ok(mrs::encode(count, &MrsPayload::IpCidr(set)))
        }
        Behavior::Classical => Err(CompileSetError::Empty),
    }
}

pub fn compile_rule_set(buf: &[u8], allow_empty: bool) -> Result<CompiledRuleSet, CompileSetError> {
    if mrs::is_zstd(buf) {
        for (behavior, mrs_behavior) in [
            (Behavior::Domain, MrsBehavior::Domain),
            (Behavior::IpCidr, MrsBehavior::IpCidr),
        ] {
            if mrs_to_text(buf, mrs_behavior).is_ok() {
                return Ok(CompiledRuleSet {
                    info: SetInfo {
                        behavior,
                        format: Format::Mrs,
                    },
                    mrs: None,
                });
            }
        }
        return Err(CompileSetError::Invalid);
    }
    let (format, entries) = rule_set_entries(buf);
    if entries.is_empty() && allow_empty {
        return Ok(CompiledRuleSet {
            info: SetInfo {
                behavior: Behavior::Classical,
                format,
            },
            mrs: None,
        });
    }
    let (behavior, keys) = classify(&entries)?;
    let info = SetInfo { behavior, format };
    if behavior == Behavior::Classical {
        return Ok(CompiledRuleSet { info, mrs: None });
    }
    Ok(CompiledRuleSet {
        info,
        mrs: Some(encode_keys(behavior, &keys)?),
    })
}

fn dump_domains(set: &DomainSet) -> Vec<String> {
    let mut keys = Vec::new();
    set.foreach(|key| {
        keys.push(key.to_string());
        true
    });
    let bare = |key: &str| key.strip_prefix('.').unwrap_or(key).to_string();
    keys.sort_by_key(|key| bare(key));
    let mut index = 0;
    while index + 1 < keys.len() {
        let domain = bare(keys.get(index).map_or("", String::as_str));
        if domain == bare(keys.get(index + 1).map_or("", String::as_str)) {
            if let Some(slot) = keys.get_mut(index) {
                *slot = format!("+.{domain}");
            }
            if let Some(slot) = keys.get_mut(index + 1) {
                slot.clear();
            }
            index += 1;
        }
        index += 1;
    }
    keys.retain(|key| !key.is_empty());
    keys.sort();
    keys
}

fn mrs_to_text(buf: &[u8], behavior: MrsBehavior) -> Result<String, String> {
    let file = mrs::decode(buf, behavior).map_err(|err| err.to_string())?;
    if file.count == 0 {
        return Err("empty rule".to_string());
    }
    let lines = match &file.payload {
        MrsPayload::Domain(set) => dump_domains(set),
        MrsPayload::IpCidr(set) => set
            .prefixes()
            .into_iter()
            .map(|(ip, bits)| format!("{ip}/{bits}"))
            .collect(),
    };
    Ok(lines.iter().map(|line| format!("{line}\n")).collect())
}

/// The text of an `.mrs` file. On failure, the error of each behavior tried.
pub fn dump_mrs(buf: &[u8]) -> Result<String, Vec<String>> {
    let mut errors = Vec::new();
    for behavior in [MrsBehavior::Domain, MrsBehavior::IpCidr] {
        match mrs_to_text(buf, behavior) {
            Ok(text) => return Ok(text),
            Err(err) => errors.push(err),
        }
    }
    Err(errors)
}

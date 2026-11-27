use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

pub use concord_config::mitm::MitmSection as RawConfig;
use concord_config::mitm::text::quote;
use concord_config::mitm::{
    BodyActionDef, BodyRewriteDef, HostEntryDef, IssueKind, Items, LineError, MapLocalBody,
    MapLocalDef, MitmDef, MitmLine, Read,
};
use serde::Serialize;

use crate::hostlist::{HostList, hosts_view};
use crate::limits::{Limits, Resolve};
use crate::rules::{
    ResourceSeen, Rules, compile_body_rewrite, compile_header_rewrite, compile_map_local,
    compile_url_rewrite, local_file_seen, resource_digest,
};
use crate::script::{ScriptHost, compile_script};
use crate::sources::SourceList;
use crate::view::{LineView, SourcesView};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub index: usize,
    pub kind: IssueKind,
    pub message: String,
}

pub struct ParseEnv {
    pub resources: PathBuf,
    pub scripts: Arc<ScriptHost>,
}

pub struct Config {
    pub enable: bool,
    pub decrypt_tls: bool,
    pub ca_fingerprint: String,
    pub hosts: HostList,
    pub skip_server_cert_verify: bool,
    pub skip_verify_hosts: HostList,
    pub(crate) sources: SourceList,
    pub auto_quic_block: bool,
    pub h2: bool,
    pub limits: Limits,
    pub(crate) rules: Rules,
    /// Plain HTTP on port 80 is read whatever its host while a rule can act on a request, as
    /// Surge's HTTP engine reads it without a hostname entry.
    pub(crate) plain_http: bool,
    def: MitmDef,
    resources: Resources,
    errors: Vec<LineIssue>,
}

struct LineIssue {
    text: String,
    unread: bool,
}

/// What the files a section names in the resources directory held as compiling read them,
/// in the order its lines name them, and the script runtime that compiled its scripts.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Resources {
    dir: PathBuf,
    runtime: u64,
    files: Vec<Result<ResourceSeen, LineError>>,
}

/// The spelling, resources and errors of the last apply that kept an engine.
pub(crate) struct Applied {
    def: MitmDef,
    resources: Resources,
    errors: Vec<LineIssue>,
}

impl Applied {
    pub(crate) fn compiles_from(&self, def: &MitmDef, env: &ParseEnv) -> bool {
        self.def.written_the_same(def) && self.resources.still_matches(def, env)
    }

    pub(crate) fn errors(&self, unread: bool) -> Vec<String> {
        filter_errors(&self.errors, unread)
    }
}

fn filter_errors(issues: &[LineIssue], unread: bool) -> Vec<String> {
    issues
        .iter()
        .filter(|issue| unread || !issue.unread)
        .map(|issue| issue.text.clone())
        .collect()
}

/// The files of `lines`, each with whether it is base64, which the compile reads whole.
fn local_files(lines: &[MitmLine<Read<MapLocalDef>>]) -> impl Iterator<Item = (&str, bool)> {
    lines.iter().filter_map(|line| match &line.read {
        Ok(local) => match local.body {
            MapLocalBody::File { base64 } => Some((local.data.as_str(), base64)),
            _ => None,
        },
        _ => None,
    })
}

impl Resources {
    pub(crate) fn still_matches(&self, def: &MitmDef, env: &ParseEnv) -> bool {
        if self.dir != env.resources || self.runtime != env.scripts.generation() {
            return false;
        }
        let mut recorded = self.files.iter();
        let mut next = |live: &dyn Fn() -> Result<ResourceSeen, LineError>| -> bool {
            let Some(seen) = recorded.next() else {
                return false;
            };
            matches!(seen, Ok(ResourceSeen::NotRead)) || seen == &live()
        };
        for line in &def.body_rewrite {
            if let Ok(BodyRewriteDef {
                action: BodyActionDef::JqFile(name),
                ..
            }) = &line.read
                && !next(&|| resource_digest(&env.resources, "jq file", name))
            {
                return false;
            }
        }
        for (name, base64) in local_files(&def.map_local).chain(local_files(&def.request_body_mock))
        {
            let matched = if base64 {
                next(&|| resource_digest(&env.resources, "data", name))
            } else {
                next(&|| local_file_seen(&env.resources, name))
            };
            if !matched {
                return false;
            }
        }
        for line in &def.script {
            if let Ok(script) = &line.read
                && !next(&|| resource_digest(&env.resources, "script-path", &script.path))
            {
                return false;
            }
        }
        recorded.next().is_none()
    }
}

/// What a line put in force and what of it could not be read or compiled: a hostname or
/// source line has both when some of its items apply. `unread` marks an error the section's
/// reading found, before any compiling.
struct LineRead {
    view: Option<LineView>,
    error: Option<LineError>,
    unread: bool,
}

/// The list, then the line's index, text and module.
type Visit<'a> = dyn FnMut(&'static str, usize, &str, Option<&str>, LineRead) + 'a;

fn items<T>(read: &Items<T>, view: Option<LineView>) -> LineRead {
    LineRead {
        view,
        error: read.error.clone(),
        unread: true,
    }
}

fn compiled<D, R>(
    read: &Read<D>,
    compile: impl FnOnce(&D) -> Result<R, LineError>,
    add: impl FnOnce(R) -> LineView,
) -> LineRead {
    let (view, error, unread) = match read.as_ref().map(compile) {
        Err(err) => (None, Some(err.clone()), true),
        Ok(Err(err)) => (None, Some(err), false),
        Ok(Ok(rule)) => (Some(add(rule)), None, false),
    };
    LineRead {
        view,
        error,
        unread,
    }
}

fn each<T>(
    key: &'static str,
    lines: &[MitmLine<T>],
    visit: &mut Visit<'_>,
    mut read: impl FnMut(&T, Option<&Arc<str>>) -> LineRead,
) {
    for line in lines {
        visit(
            key,
            line.index,
            &line.text,
            line.origin.as_deref(),
            read(&line.read, line.origin.as_ref()),
        );
    }
}

fn read_hosts(list: &mut HostList, read: &Items<HostEntryDef>) -> LineRead {
    list.extend_entries(&read.items);
    items(read, hosts_view(read))
}

impl Config {
    fn empty(def: &MitmDef) -> Config {
        Config {
            enable: def.enable,
            decrypt_tls: def.decrypt_tls.unwrap_or(true),
            ca_fingerprint: normalize_fingerprint(&def.ca_fingerprint),
            hosts: HostList::default(),
            skip_server_cert_verify: def.skip_server_cert_verify,
            skip_verify_hosts: HostList::default(),
            sources: SourceList::default(),
            auto_quic_block: def.auto_quic_block.unwrap_or(true),
            h2: def.h2,
            limits: def.limits.resolve(),
            rules: Rules::default(),
            plain_http: false,
            def: MitmDef::default(),
            resources: Resources::default(),
            errors: Vec::new(),
        }
    }

    /// Puts each line of `def` in force, list by list, and hands it with how it read to `visit`.
    fn add_lines(&mut self, def: &MitmDef, env: &ParseEnv, visit: &mut Visit<'_>) -> Resources {
        let runtime = env.scripts.generation();
        each("hostname", &def.hostname, visit, |read, _| {
            read_hosts(&mut self.hosts, read)
        });
        each(
            "hostname-disabled",
            &def.hostname_disabled,
            visit,
            |read, _| {
                self.hosts.remove_entries(&read.items);
                items(read, hosts_view(read))
            },
        );
        each(
            "skip-server-cert-verify-hostname",
            &def.skip_server_cert_verify_hostname,
            visit,
            |read, _| read_hosts(&mut self.skip_verify_hosts, read),
        );
        each(
            "client-source-address",
            &def.client_source_address,
            visit,
            |read, _| {
                let entries = self.sources.add(&read.items);
                let view =
                    (!entries.is_empty()).then_some(LineView::Sources(SourcesView { entries }));
                items(read, view)
            },
        );
        let files = self.add_rules(def, env, visit);
        Resources {
            dir: env.resources.clone(),
            runtime,
            files,
        }
    }

    fn add_rules(
        &mut self,
        def: &MitmDef,
        env: &ParseEnv,
        visit: &mut Visit<'_>,
    ) -> Vec<Result<ResourceSeen, LineError>> {
        let rules = &mut self.rules;
        let mut files = Vec::new();
        each("url-rewrite", &def.url_rewrite, visit, |read, module| {
            compiled(read, compile_url_rewrite, |mut rule| {
                rule.module = module.cloned();
                let view = rule.view();
                rules.url_rewrites.push(rule);
                view
            })
        });
        each(
            "header-rewrite",
            &def.header_rewrite,
            visit,
            |read, module| {
                compiled(read, compile_header_rewrite, |mut rule| {
                    rule.module = module.cloned();
                    let view = rule.view();
                    rules.header_rewrites.push(rule);
                    view
                })
            },
        );
        each("body-rewrite", &def.body_rewrite, visit, |read, module| {
            let mut seen = None;
            let out = compiled(
                read,
                |def| compile_body_rewrite(def, &env.resources, &mut seen),
                |mut rule| {
                    rule.module = module.cloned();
                    let view = rule.view();
                    rules.body_rewrites.push(Arc::new(rule));
                    view
                },
            );
            files.extend(seen);
            out
        });
        each("map-local", &def.map_local, visit, |read, module| {
            let mut seen = None;
            let out = compiled(
                read,
                |def| compile_map_local(def, &env.resources, &mut seen),
                |(mut rule, view)| {
                    rule.module = module.cloned();
                    rules.map_locals.push(rule);
                    view
                },
            );
            files.extend(seen);
            out
        });
        each(
            "request-body-mock",
            &def.request_body_mock,
            visit,
            |read, module| {
                let mut seen = None;
                let out = compiled(
                    read,
                    |def| compile_map_local(def, &env.resources, &mut seen),
                    |(mut rule, view)| {
                        rule.module = module.cloned();
                        rules.request_mocks.push(rule);
                        view
                    },
                );
                files.extend(seen);
                out
            },
        );
        each("script", &def.script, visit, |read, module| {
            let mut seen = None;
            let out = compiled(
                read,
                |def| compile_script(def, &env.resources, &env.scripts, &mut seen),
                |mut script| {
                    script.module = module.cloned();
                    let view = script.view();
                    rules.scripts.push(Arc::new(script));
                    view
                },
            );
            if read.is_ok() {
                files.push(seen.unwrap_or(Ok(ResourceSeen::NotRead)));
            }
            out
        });
        files
    }

    /// Lines that cannot be read are skipped and named in the errors.
    pub fn parse(raw: RawConfig, env: &ParseEnv) -> (Config, Vec<String>) {
        Config::compile(MitmDef::read(&raw), env, true)
    }

    /// The section in force, and the lines that could not be compiled, with those that
    /// could not be read when `unread`.
    pub(crate) fn compile(def: MitmDef, env: &ParseEnv, unread: bool) -> (Config, Vec<String>) {
        let mut config = Config::empty(&def);
        let mut errors = Vec::new();
        let resources = config.add_lines(&def, env, &mut |key, _, text, origin, read| {
            if let Some(err) = read.error {
                let line = format!("{key} {}: {err}", quote(text));
                errors.push(LineIssue {
                    text: match origin {
                        Some(module) => format!("module {module}: {line}"),
                        None => line,
                    },
                    unread: read.unread,
                });
            }
        });
        config.errors = errors;
        config.resources = resources;
        env.scripts.keep(&config.rules.scripts);
        config.hosts.index();
        config.skip_verify_hosts.index();
        config.rules.index();
        config.plain_http = config.rules.acts_on_requests();
        config.def = def;
        let errors = config.errors(unread);
        (config, errors)
    }

    /// The lines that could not be compiled, with those that could not be read when `unread`.
    pub(crate) fn errors(&self, unread: bool) -> Vec<String> {
        filter_errors(&self.errors, unread)
    }

    /// Whether `other` puts the same section in force from the same resource contents.
    pub fn same(&self, other: &Config) -> bool {
        self.def.reads_the_same(&other.def) && self.resources == other.resources
    }

    /// Whether compiling `def` against `env` would give this section and these errors.
    pub(crate) fn compiles_from(&self, def: &MitmDef, env: &ParseEnv) -> bool {
        self.def.written_the_same(def) && self.resources.still_matches(def, env)
    }

    pub(crate) fn into_applied(self) -> Applied {
        Applied {
            def: self.def,
            resources: self.resources,
            errors: self.errors,
        }
    }

    pub fn script_names(&self) -> Vec<&str> {
        self.rules
            .scripts
            .iter()
            .map(|script| script.name.as_str())
            .collect()
    }
}

/// By list, the lines that cannot be read, and how each line in force reads; a line some of
/// whose items apply is in both.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Validation {
    pub issues: BTreeMap<String, Vec<Issue>>,
    pub views: BTreeMap<String, Vec<LineEntry>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LineEntry {
    pub index: usize,
    pub view: LineView,
}

pub fn check(raw: &RawConfig, env: &ParseEnv) -> Validation {
    check_def(&MitmDef::read(raw), env)
}

pub(crate) fn check_def(def: &MitmDef, env: &ParseEnv) -> Validation {
    let mut validation = Validation::default();
    let mut scratch = Config::empty(&MitmDef::default());
    scratch.add_lines(def, env, &mut |key, index, _, _, read| {
        if let Some(err) = read.error {
            let issue = Issue {
                index,
                kind: err.kind,
                message: err.message,
            };
            validation
                .issues
                .entry(key.to_string())
                .or_default()
                .push(issue);
        }
        if let Some(view) = read.view {
            let entry = LineEntry { index, view };
            validation
                .views
                .entry(key.to_string())
                .or_default()
                .push(entry);
        }
    });
    validation
}

/// Upper-case hex pairs joined by colons.
pub fn normalize_fingerprint(text: &str) -> String {
    let hex: String = text
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != ' ')
        .collect::<String>()
        .to_uppercase();
    let mut pairs = Vec::with_capacity(hex.len() / 2 + 1);
    let mut rest = hex.as_str();
    while rest.len() > 2 {
        let (pair, tail) = rest.split_at(2);
        pairs.push(pair);
        rest = tail;
    }
    if !rest.is_empty() {
        pairs.push(rest);
    }
    pairs.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> (tempfile::TempDir, ParseEnv) {
        let home = tempfile::tempdir().unwrap();
        let env = ParseEnv {
            resources: home.path().join("resources"),
            scripts: Arc::new(ScriptHost::default()),
        };
        (home, env)
    }

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn check_names_the_item_of_a_hostname_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["b.test", "a.test, bad host"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        let want = vec![Issue {
            index: 1,
            kind: IssueKind::Invalid,
            message: "\"bad host\": unsupported character U+0020".to_string(),
        }];
        assert_eq!(issues, BTreeMap::from([("hostname".to_string(), want)]));
    }

    #[test]
    fn validate_names_the_lines_of_each_list() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["a.test"]),
            url_rewrite: lines(&["^ok _ reject", "(broken _ reject", "# note"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues["url-rewrite"].len(), 1);
        assert_eq!(issues["url-rewrite"][0].index, 1);
    }

    #[test]
    fn parse_names_the_bad_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            url_rewrite: lines(&["# comment", "", "^ok _ reject", "broken"]),
            map_local: lines(&["^x data-type=nope"]),
            ..RawConfig::default()
        };
        let (_, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(
            errors[0].contains("url-rewrite \"broken\""),
            "{}",
            errors[0]
        );
        assert!(errors[1].contains("map-local"), "{}", errors[1]);
    }

    #[test]
    fn a_profile_section_leaves_the_lines_it_cannot_read_to_its_load() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            url_rewrite: lines(&["broken"]),
            map_local: lines(&["^x data=missing.json"]),
            ..RawConfig::default()
        };
        let (_, errors) = Config::compile(MitmDef::read(&raw), &env, false);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].starts_with("map-local"), "{}", errors[0]);
        let (_, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 2, "{errors:?}");
    }

    #[test]
    fn a_line_a_module_wrote_names_the_module() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            map_local: lines(&["^x data=missing.json"]),
            ..RawConfig::default()
        };
        let mut def = MitmDef::read(&raw);
        def.mark_origin(&"Sample (7)".into());
        let (_, errors) = Config::compile(def, &env, false);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("module Sample (7): map-local"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn defaults_follow_the_go_core() {
        let (_home, env) = env();
        let (config, errors) = Config::parse(
            RawConfig {
                enable: true,
                ..RawConfig::default()
            },
            &env,
        );
        assert!(errors.is_empty());
        assert!(config.decrypt_tls && config.auto_quic_block && !config.h2);
    }

    #[test]
    fn same_compares_the_section_not_the_compiled_rules() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            hostname: lines(&["a.test"]),
            ..RawConfig::default()
        };
        let (a, _) = Config::parse(raw.clone(), &env);
        let (b, _) = Config::parse(raw.clone(), &env);
        let (c, _) = Config::parse(
            RawConfig {
                enable: false,
                ..raw
            },
            &env,
        );
        assert!(a.same(&b) && !a.same(&c));
    }

    #[test]
    fn same_ignores_where_comments_and_blank_lines_put_a_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            hostname: lines(&["a.test, b.test"]),
            url_rewrite: lines(&["^ok _ reject", "^next _ reject"]),
            ..RawConfig::default()
        };
        let (a, _) = Config::parse(raw.clone(), &env);
        let (moved, _) = Config::parse(
            RawConfig {
                hostname: lines(&["# hosts", "", "a.test,b.test"]),
                url_rewrite: lines(&["", "# ads", "  ^ok   _ reject", "^next _ reject"]),
                ..raw.clone()
            },
            &env,
        );
        let (swapped, _) = Config::parse(
            RawConfig {
                url_rewrite: lines(&["^next _ reject", "^ok _ reject"]),
                ..raw.clone()
            },
            &env,
        );
        let (changed, _) = Config::parse(
            RawConfig {
                url_rewrite: lines(&["^ok _ reject", "^other _ reject"]),
                ..raw
            },
            &env,
        );
        assert!(a.same(&moved));
        assert!(!a.same(&swapped) && !a.same(&changed));
    }

    #[test]
    fn raw_config_reads_the_wire_names_and_nulls() {
        let raw: RawConfig = serde_json::from_str(
            r#"{"enable":true,"hostname":null,"skip-server-cert-verify":true,"decrypt-tls":false,
            "ca-fingerprint":"ab","h2":true,"limits":{"max-body-size":10}}"#,
        )
        .unwrap();
        assert!(raw.enable && raw.skip_server_cert_verify && raw.h2);
        assert_eq!(raw.decrypt_tls, Some(false));
        assert_eq!(raw.limits.max_body_size, 10);
        assert!(raw.hostname.is_empty());
    }

    #[test]
    fn the_section_reads_its_hosts_and_switches() {
        let (_home, env) = env();
        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "hostname": ["-skip.a.test", "*.a.test"],
            "url-rewrite": [r"^https://x\.a\.test/ad _ reject", "broken"],
        }))
        .unwrap();
        let (config, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(config.enable && config.auto_quic_block);
        assert!(config.hosts.matches("x.a.test", 443) && !config.hosts.matches("skip.a.test", 443));

        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "decrypt-tls": false,
            "ca-fingerprint": "aa:bb",
            "h2": true,
        }))
        .unwrap();
        let (config, _) = Config::parse(raw, &env);
        assert!(!config.decrypt_tls && config.h2);
        assert_eq!(config.ca_fingerprint, "AA:BB");
    }

    #[test]
    fn fingerprints_normalize() {
        assert_eq!(normalize_fingerprint(" ab:cd ef "), "AB:CD:EF");
        assert_eq!(normalize_fingerprint("aabbcc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint(" AA:bb:CC "), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("aa bb cc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("AA:BB:CC:DD"), "AA:BB:CC:DD");
        assert_eq!(normalize_fingerprint("abc"), "AB:C");
        assert_eq!(normalize_fingerprint(""), "");
    }

    #[test]
    fn compile_records_resource_digests_from_read_bytes_and_not_read_scripts() {
        use sha2::{Digest, Sha256};

        let (_home, env) = env();
        std::fs::create_dir_all(&env.resources).unwrap();
        let small = b"small-local";
        let large = vec![b'x'; crate::rules::LOCAL_PIECE + 5];
        let b64_file = b"aGVsbG8=";
        let jq_file = b".a";
        std::fs::write(env.resources.join("small.txt"), small).unwrap();
        std::fs::write(env.resources.join("large.bin"), &large).unwrap();
        std::fs::write(env.resources.join("enc.b64"), b64_file).unwrap();
        std::fs::write(env.resources.join("f.jq"), jq_file).unwrap();
        std::fs::write(env.resources.join("bad_cron.js"), b"AA").unwrap();

        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "body-rewrite": [r"http-request-jq ^https://a\.test/ '.'"],
            "map-local": [
                r#"^https://a\.test/s data-type=file data="small.txt""#,
                r#"^https://a\.test/l data-type=file data="large.bin""#,
                r#"^https://a\.test/b data-type=base64 data="aGVsbG8=""#,
                r#"^https://a\.test/m data-type=file data="missing.txt""#,
            ],
            "script": [
                r#"BadCron = type=cron,cronexp="0 9 * *",script-path=bad_cron.js"#,
            ],
        }))
        .unwrap();
        let mut def = MitmDef::read(&raw);
        def.body_rewrite[0].read.as_mut().unwrap().action = BodyActionDef::JqFile("f.jq".into());
        def.map_local[2].read.as_mut().unwrap().body = MapLocalBody::File { base64: true };
        def.map_local[2].read.as_mut().unwrap().data = "enc.b64".into();

        let (config, errors) = Config::compile(def.clone(), &env, true);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert_eq!(config.resources.files.len(), 6);
        assert_eq!(
            config.resources.files[0],
            Ok(ResourceSeen::Content(Sha256::digest(jq_file).into()))
        );
        assert_eq!(
            config.resources.files[1],
            Ok(ResourceSeen::Content(Sha256::digest(small).into()))
        );
        assert_eq!(config.resources.files[2], Ok(ResourceSeen::ReadAtAnswer));
        assert_eq!(
            config.resources.files[3],
            Ok(ResourceSeen::Content(Sha256::digest(b64_file).into()))
        );
        assert!(config.resources.files[4].is_err());
        assert_eq!(config.resources.files[5], Ok(ResourceSeen::NotRead));
        assert!(config.compiles_from(&def, &env));

        std::fs::write(env.resources.join("bad_cron.js"), b"CHANGED").unwrap();
        assert!(
            config.compiles_from(&def, &env),
            "a script that failed before reading its file stays matched"
        );
        std::fs::write(env.resources.join("enc.b64"), b"d29ybGQ=").unwrap();
        assert!(!config.compiles_from(&def, &env));
    }
}

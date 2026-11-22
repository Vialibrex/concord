use std::collections::BTreeMap;

use concord_engine::mitm_types::{
    ArgumentDef, ArgumentKind, BodyReplacementView, BodyRewriteView, DataType, DomainEntry,
    FailureReason, FetchFailure, HeaderAction, HeaderRewriteView, HeaderView, HostEntryView,
    HostsView, IgnoreReason, IgnoredView, InlineRule, Issue, IssueKind, LineEntry, LineView,
    ListEdit, MapLocalView, ModuleFormat, ModuleMeta, ModuleOff, ModuleProblem, ModuleRule,
    ModuleStatus, ModuleView, NetworkDef, Phase, Policy, ProviderKind, RefusedRule, ResourceDef,
    ResourceKind, ResourceState, ResourceStatus, RuleSetDef, RuleSetSource, RuleView, ScriptView,
    ScriptViewKind, SourceEntryView, SourcesView, UrlAction, UrlRewriteView, Validation,
};
use concord_proto::types::{
    MitmArgumentKind, MitmBodyReplacement, MitmBodyRewrite, MitmDataType, MitmDomainEntry,
    MitmFetchFailure, MitmFetchFailureReason, MitmHeader, MitmHeaderAction, MitmHeaderRewrite,
    MitmHostEntry, MitmHosts, MitmIgnoreReason, MitmIssue, MitmIssueKind, MitmLineEntry,
    MitmLineView, MitmListEdit, MitmMapLocal, MitmModuleArgument, MitmModuleFormat,
    MitmModuleIgnored, MitmModuleInlineRule, MitmModuleMeta, MitmModuleNetwork, MitmModuleOff,
    MitmModulePolicy, MitmModuleProblem, MitmModuleResource, MitmModuleResourceStatus,
    MitmModuleRule, MitmModuleRuleSet, MitmModuleStatus, MitmModuleStatusList, MitmModuleView,
    MitmPhase, MitmRefusedRule, MitmResourceKind, MitmResourceState, MitmRuleProviderKind,
    MitmRuleSetSource, MitmScript, MitmScriptKind, MitmSourceEntry, MitmSources, MitmUrlAction,
    MitmUrlRewrite, MitmValidateResult,
};

fn index(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn by_list<T, U>(lists: BTreeMap<String, Vec<T>>, each: fn(T) -> U) -> BTreeMap<String, Vec<U>> {
    lists
        .into_iter()
        .map(|(list, items)| (list, items.into_iter().map(each).collect()))
        .collect()
}

pub fn validation(validation: Validation) -> MitmValidateResult {
    let Validation { issues, views } = validation;
    MitmValidateResult {
        issues: by_list(issues, issue),
        views: by_list(views, line_entry),
    }
}

fn issue(issue: Issue) -> MitmIssue {
    let Issue {
        index: at,
        kind,
        message,
    } = issue;
    MitmIssue {
        index: index(at),
        kind: issue_kind(kind),
        message,
    }
}

fn issue_kind(kind: IssueKind) -> MitmIssueKind {
    match kind {
        IssueKind::Syntax => MitmIssueKind::Syntax,
        IssueKind::Missing => MitmIssueKind::Missing,
        IssueKind::Unknown => MitmIssueKind::Unknown,
        IssueKind::Unsupported => MitmIssueKind::Unsupported,
        IssueKind::Invalid => MitmIssueKind::Invalid,
        IssueKind::Pattern => MitmIssueKind::Pattern,
        IssueKind::Jq => MitmIssueKind::Jq,
        IssueKind::Resource => MitmIssueKind::Resource,
        IssueKind::Script => MitmIssueKind::Script,
    }
}

fn line_entry(entry: LineEntry) -> MitmLineEntry {
    let LineEntry { index: at, view } = entry;
    MitmLineEntry {
        index: index(at),
        view: line_view(view),
    }
}

fn line_view(view: LineView) -> MitmLineView {
    match view {
        LineView::UrlRewrite(view) => MitmLineView::UrlRewrite(url_rewrite(view)),
        LineView::HeaderRewrite(view) => MitmLineView::HeaderRewrite(header_rewrite(view)),
        LineView::BodyRewrite(view) => MitmLineView::BodyRewrite(body_rewrite(view)),
        LineView::MapLocal(view) => MitmLineView::MapLocal(map_local(view)),
        LineView::Script(view) => MitmLineView::Script(script(view)),
        LineView::Hosts(view) => MitmLineView::Hosts(hosts(view)),
        LineView::Sources(view) => MitmLineView::Sources(sources(view)),
    }
}

fn phase(phase: Phase) -> MitmPhase {
    match phase {
        Phase::Request => MitmPhase::Request,
        Phase::Response => MitmPhase::Response,
    }
}

fn url_action(action: UrlAction) -> MitmUrlAction {
    match action {
        UrlAction::Header => MitmUrlAction::Header,
        UrlAction::Redirect302 => MitmUrlAction::Redirect302,
        UrlAction::Redirect307 => MitmUrlAction::Redirect307,
        UrlAction::Reject => MitmUrlAction::Reject,
        UrlAction::Reject200 => MitmUrlAction::Reject200,
        UrlAction::RejectImg => MitmUrlAction::RejectImg,
        UrlAction::RejectDict => MitmUrlAction::RejectDict,
        UrlAction::RejectArray => MitmUrlAction::RejectArray,
    }
}

fn url_rewrite(view: UrlRewriteView) -> MitmUrlRewrite {
    let UrlRewriteView {
        pattern,
        action,
        replacement,
        request_head,
    } = view;
    MitmUrlRewrite {
        pattern,
        action: url_action(action),
        replacement,
        request_head,
    }
}

fn header_action(action: HeaderAction) -> MitmHeaderAction {
    match action {
        HeaderAction::Add => MitmHeaderAction::HeaderAdd,
        HeaderAction::Del => MitmHeaderAction::HeaderDel,
        HeaderAction::Replace => MitmHeaderAction::HeaderReplace,
        HeaderAction::ReplaceRegex => MitmHeaderAction::HeaderReplaceRegex,
        HeaderAction::TextReplace => MitmHeaderAction::HeaderTextReplace,
    }
}

fn header_rewrite(view: HeaderRewriteView) -> MitmHeaderRewrite {
    let HeaderRewriteView {
        phase: at,
        pattern,
        request_head,
        response_head,
        action,
        name,
        value,
        regex,
        replacement,
    } = view;
    MitmHeaderRewrite {
        phase: phase(at),
        pattern,
        request_head,
        response_head,
        action: header_action(action),
        name,
        value,
        regex,
        replacement,
    }
}

fn body_rewrite(view: BodyRewriteView) -> MitmBodyRewrite {
    let BodyRewriteView {
        phase: at,
        pattern,
        request_head,
        response_head,
        replacements,
        jq,
    } = view;
    MitmBodyRewrite {
        phase: phase(at),
        pattern,
        request_head,
        response_head,
        replacements: replacements
            .into_iter()
            .map(|pair| {
                let BodyReplacementView { regex, replacement } = pair;
                MitmBodyReplacement { regex, replacement }
            })
            .collect(),
        jq,
    }
}

fn data_type(data_type: DataType) -> MitmDataType {
    match data_type {
        DataType::Text => MitmDataType::Text,
        DataType::TinyGif => MitmDataType::TinyGif,
        DataType::Base64 => MitmDataType::Base64,
        DataType::File => MitmDataType::File,
    }
}

fn map_local(view: MapLocalView) -> MitmMapLocal {
    let MapLocalView {
        pattern,
        request_head,
        data_type: kind,
        data,
        status,
        headers,
        content_type,
    } = view;
    MitmMapLocal {
        pattern,
        request_head,
        data_type: data_type(kind),
        data,
        status,
        headers: headers
            .into_iter()
            .map(|header| {
                let HeaderView { name, value } = header;
                MitmHeader { name, value }
            })
            .collect(),
        content_type,
    }
}

fn script_kind(kind: ScriptViewKind) -> MitmScriptKind {
    match kind {
        ScriptViewKind::HttpRequest => MitmScriptKind::HttpRequest,
        ScriptViewKind::HttpResponse => MitmScriptKind::HttpResponse,
        ScriptViewKind::Cron => MitmScriptKind::Cron,
        ScriptViewKind::Event => MitmScriptKind::Event,
        ScriptViewKind::Generic => MitmScriptKind::Generic,
        ScriptViewKind::Rule => MitmScriptKind::Rule,
        ScriptViewKind::Dns => MitmScriptKind::Dns,
    }
}

fn script(view: ScriptView) -> MitmScript {
    let ScriptView {
        name,
        kind,
        path,
        pattern,
        request_head,
        response_head,
        cronexp,
        event,
        requires_body,
        binary_body,
        max_size,
        timeout_ms,
    } = view;
    MitmScript {
        name,
        kind: script_kind(kind),
        path,
        pattern,
        request_head,
        response_head,
        cronexp,
        event,
        requires_body,
        binary_body,
        max_size,
        timeout_ms,
    }
}

fn hosts(view: HostsView) -> MitmHosts {
    let HostsView { entries } = view;
    MitmHosts {
        entries: entries
            .into_iter()
            .map(|entry| {
                let HostEntryView {
                    host,
                    port,
                    exclude,
                } = entry;
                MitmHostEntry {
                    host,
                    port,
                    exclude,
                }
            })
            .collect(),
    }
}

fn sources(view: SourcesView) -> MitmSources {
    let SourcesView { entries } = view;
    MitmSources {
        entries: entries
            .into_iter()
            .map(|entry| {
                let SourceEntryView { network, exclude } = entry;
                MitmSourceEntry { network, exclude }
            })
            .collect(),
    }
}

pub fn module_view(view: ModuleView) -> MitmModuleView {
    let ModuleView {
        format,
        meta,
        off,
        arguments,
        resources,
        declared_scripts,
        asks_consent,
        issues,
        views,
        rules,
        rule_sets,
        network: asked,
        ignored,
    } = view;
    MitmModuleView {
        format: module_format(format),
        meta: module_meta(meta),
        off: off.map(module_off),
        arguments: arguments.into_iter().map(argument).collect(),
        resources: resources.into_iter().map(resource).collect(),
        declared_scripts,
        asks_consent,
        issues: by_list(issues, issue),
        views: by_list(views, line_entry),
        rules: rules.into_iter().map(rule).collect(),
        rule_sets: rule_sets.into_iter().map(rule_set).collect(),
        network: network(asked),
        ignored: ignored.into_iter().map(ignored_line).collect(),
    }
}

fn module_format(format: ModuleFormat) -> MitmModuleFormat {
    match format {
        ModuleFormat::Surge => MitmModuleFormat::Surge,
        ModuleFormat::Loon => MitmModuleFormat::Loon,
        ModuleFormat::QuantumultX => MitmModuleFormat::QuantumultX,
        ModuleFormat::Stash => MitmModuleFormat::Stash,
    }
}

fn module_meta(meta: ModuleMeta) -> MitmModuleMeta {
    let ModuleMeta {
        name,
        desc,
        author,
        icon,
        homepage,
        category,
        system,
        requirement,
        arguments_desc,
    } = meta;
    MitmModuleMeta {
        name,
        desc,
        author,
        icon,
        homepage,
        category,
        system,
        requirement,
        arguments_desc,
    }
}

fn module_off(off: ModuleOff) -> MitmModuleOff {
    match off {
        ModuleOff::Requirement => MitmModuleOff::Requirement,
        ModuleOff::RequirementUnreadable => MitmModuleOff::RequirementUnreadable,
    }
}

fn argument(argument: ArgumentDef) -> MitmModuleArgument {
    let ArgumentDef {
        name,
        kind,
        number,
        default,
        label,
        desc,
        line,
    } = argument;
    MitmModuleArgument {
        name,
        kind: match kind {
            ArgumentKind::Text => MitmArgumentKind::Text,
            ArgumentKind::Switch => MitmArgumentKind::Switch,
            ArgumentKind::Select { options } => MitmArgumentKind::Select { options },
        },
        number,
        default,
        label,
        desc,
        line,
    }
}

fn resource_kind(kind: ResourceKind) -> MitmResourceKind {
    match kind {
        ResourceKind::Script => MitmResourceKind::Script,
        ResourceKind::MapLocal => MitmResourceKind::MapLocal,
        ResourceKind::Jq => MitmResourceKind::Jq,
    }
}

fn resource(resource: ResourceDef) -> MitmModuleResource {
    let ResourceDef { url, kind, lines } = resource;
    MitmModuleResource {
        url,
        kind: resource_kind(kind),
        lines,
    }
}

fn rule(view: RuleView) -> MitmModuleRule {
    let RuleView {
        line,
        rule:
            ModuleRule {
                rule,
                policy,
                no_resolve,
                extended_matching,
                requires_resolve,
            },
    } = view;
    MitmModuleRule {
        line,
        rule,
        policy: match policy {
            Policy::Builtin(name) => MitmModulePolicy::Builtin(name.to_owned()),
            Policy::Named(name) => MitmModulePolicy::Named(name),
        },
        no_resolve,
        extended_matching,
        requires_resolve,
    }
}

fn rule_set(set: RuleSetDef) -> MitmModuleRuleSet {
    let RuleSetDef {
        name,
        domain,
        source,
        provider,
    } = set;
    MitmModuleRuleSet {
        name,
        domain,
        source: match source {
            RuleSetSource::Url { url, interval } => MitmRuleSetSource::Url { url, interval },
            RuleSetSource::Inline { rules } => MitmRuleSetSource::Inline {
                rules: rules
                    .into_iter()
                    .map(|inline| {
                        let InlineRule { line, rule } = inline;
                        MitmModuleInlineRule { line, rule }
                    })
                    .collect(),
            },
            RuleSetSource::Builtin { rules } => MitmRuleSetSource::Builtin {
                rules: rules.iter().map(|rule| (*rule).to_owned()).collect(),
            },
            RuleSetSource::File { file } => MitmRuleSetSource::File { file },
        },
        provider: provider.map(|kind| {
            let ProviderKind { behavior, format } = kind;
            MitmRuleProviderKind { behavior, format }
        }),
    }
}

fn list_edit(edit: ListEdit) -> MitmListEdit {
    let ListEdit {
        replace,
        before,
        after,
    } = edit;
    MitmListEdit {
        replace,
        before,
        after,
    }
}

fn domain_entries(entries: Vec<DomainEntry>) -> Vec<MitmDomainEntry> {
    entries
        .into_iter()
        .map(|entry| {
            let DomainEntry {
                domain,
                values,
                line: _,
            } = entry;
            MitmDomainEntry { domain, values }
        })
        .collect()
}

fn network(network: NetworkDef) -> MitmModuleNetwork {
    let NetworkDef {
        nameserver,
        default_nameserver,
        fake_ip_filter,
        nameserver_policy,
        hosts: entries,
        route_address,
        route_exclude_address,
        bypass_domain,
        lines,
    } = network;
    MitmModuleNetwork {
        nameserver: nameserver.map(list_edit),
        default_nameserver: default_nameserver.map(list_edit),
        fake_ip_filter: fake_ip_filter.map(list_edit),
        nameserver_policy: domain_entries(nameserver_policy),
        hosts: domain_entries(entries),
        route_address,
        route_exclude_address: route_exclude_address.map(list_edit),
        bypass_domain: bypass_domain.map(list_edit),
        lines,
    }
}

fn ignore_reason(reason: IgnoreReason) -> MitmIgnoreReason {
    match reason {
        IgnoreReason::Section => MitmIgnoreReason::Section,
        IgnoreReason::AppOnly => MitmIgnoreReason::AppOnly,
        IgnoreReason::Proxies => MitmIgnoreReason::Proxies,
        IgnoreReason::Setting => MitmIgnoreReason::Setting,
        IgnoreReason::ManagedCa => MitmIgnoreReason::ManagedCa,
        IgnoreReason::Requirement => MitmIgnoreReason::Requirement,
        IgnoreReason::RequirementUnreadable => MitmIgnoreReason::RequirementUnreadable,
        IgnoreReason::ScriptType => MitmIgnoreReason::ScriptType,
        IgnoreReason::Event => MitmIgnoreReason::Event,
        IgnoreReason::Disabled => MitmIgnoreReason::Disabled,
        IgnoreReason::FinalRule => MitmIgnoreReason::FinalRule,
        IgnoreReason::DeviceRule => MitmIgnoreReason::DeviceRule,
        IgnoreReason::RuleType => MitmIgnoreReason::RuleType,
        IgnoreReason::Policy => MitmIgnoreReason::Policy,
        IgnoreReason::NestedRuleSet => MitmIgnoreReason::NestedRuleSet,
        IgnoreReason::Reflect => MitmIgnoreReason::Reflect,
        IgnoreReason::SkipVerifyAll => MitmIgnoreReason::SkipVerifyAll,
        IgnoreReason::NoAttachment => MitmIgnoreReason::NoAttachment,
        IgnoreReason::Unreadable => MitmIgnoreReason::Unreadable,
        IgnoreReason::Condition => MitmIgnoreReason::Condition,
        IgnoreReason::RuntimeValue => MitmIgnoreReason::RuntimeValue,
    }
}

fn ignored_line(ignored: IgnoredView) -> MitmModuleIgnored {
    let IgnoredView {
        line,
        text,
        reason,
        detail,
    } = ignored;
    MitmModuleIgnored {
        line,
        text,
        reason: ignore_reason(reason),
        detail,
    }
}

pub fn module_status(modules: Vec<ModuleStatus>) -> MitmModuleStatusList {
    MitmModuleStatusList {
        modules: modules.into_iter().map(one_status).collect(),
    }
}

fn one_status(status: ModuleStatus) -> MitmModuleStatus {
    let ModuleStatus {
        name,
        enabled,
        in_force,
        problem,
        off,
        resources,
        refused_rules,
        host_network,
    } = status;
    MitmModuleStatus {
        name,
        enabled,
        in_force,
        problem: problem.map(|problem| match problem {
            ModuleProblem::Unreadable { detail } => MitmModuleProblem::Unreadable { detail },
            ModuleProblem::Duplicate => MitmModuleProblem::Duplicate,
        }),
        off: off.map(module_off),
        resources: resources.into_iter().map(resource_status).collect(),
        refused_rules: refused_rules
            .into_iter()
            .map(|refused| {
                let RefusedRule { line, detail } = refused;
                MitmRefusedRule { line, detail }
            })
            .collect(),
        host_network: network(host_network),
    }
}

fn resource_status(status: ResourceStatus) -> MitmModuleResourceStatus {
    let ResourceStatus {
        url,
        kind,
        lines,
        file,
        state,
        error,
    } = status;
    MitmModuleResourceStatus {
        url,
        kind: resource_kind(kind),
        lines,
        file,
        state: match state {
            ResourceState::Ok => MitmResourceState::Ok,
            ResourceState::Failed => MitmResourceState::Failed,
            ResourceState::Missing => MitmResourceState::Missing,
            ResourceState::Fetching => MitmResourceState::Fetching,
        },
        error: error.map(fetch_failure),
    }
}

fn fetch_failure(failure: FetchFailure) -> MitmFetchFailure {
    let FetchFailure {
        reason,
        status,
        detail,
    } = failure;
    MitmFetchFailure {
        reason: match reason {
            FailureReason::Http => MitmFetchFailureReason::Http,
            FailureReason::Dns => MitmFetchFailureReason::Dns,
            FailureReason::Tls => MitmFetchFailureReason::Tls,
            FailureReason::Timeout => MitmFetchFailureReason::Timeout,
            FailureReason::Connection => MitmFetchFailureReason::Connection,
            FailureReason::Other => MitmFetchFailureReason::Other,
        },
        status,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::Value;

    use super::*;

    /// The config crate writes an absent option as `null` where the wire type leaves it out,
    /// which a client reads the same.
    fn wire(value: impl Serialize) -> Value {
        fn drop_nulls(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    map.retain(|_, item| !item.is_null());
                    map.values_mut().for_each(drop_nulls);
                }
                Value::Array(items) => items.iter_mut().for_each(drop_nulls),
                _ => {}
            }
        }
        let mut value = serde_json::to_value(value).unwrap();
        drop_nulls(&mut value);
        value
    }

    fn some(text: &str) -> Option<String> {
        Some(text.to_string())
    }

    fn entries() -> BTreeMap<String, Vec<LineEntry>> {
        let views = vec![
            LineView::UrlRewrite(UrlRewriteView {
                pattern: "^http://a".into(),
                action: UrlAction::Redirect302,
                replacement: some("https://a"),
                request_head: some("X: 1"),
            }),
            LineView::UrlRewrite(UrlRewriteView {
                pattern: "^http://b".into(),
                action: UrlAction::RejectImg,
                replacement: None,
                request_head: None,
            }),
            LineView::HeaderRewrite(HeaderRewriteView {
                phase: Phase::Response,
                pattern: "p".into(),
                request_head: some("a"),
                response_head: some("b"),
                action: HeaderAction::ReplaceRegex,
                name: some("X-A"),
                value: None,
                regex: some("r"),
                replacement: some("s"),
            }),
            LineView::BodyRewrite(BodyRewriteView {
                phase: Phase::Request,
                pattern: "p".into(),
                request_head: None,
                response_head: None,
                replacements: vec![BodyReplacementView {
                    regex: "a".into(),
                    replacement: "b".into(),
                }],
                jq: some(".a"),
            }),
            LineView::MapLocal(MapLocalView {
                pattern: "p".into(),
                request_head: None,
                data_type: DataType::TinyGif,
                data: String::new(),
                status: Some(200),
                headers: vec![HeaderView {
                    name: "X-A".into(),
                    value: "1".into(),
                }],
                content_type: "image/gif".into(),
            }),
            LineView::Script(ScriptView {
                name: "s".into(),
                kind: ScriptViewKind::Cron,
                path: "s.js".into(),
                pattern: None,
                request_head: None,
                response_head: None,
                cronexp: some("* * * * *"),
                event: None,
                requires_body: true,
                binary_body: false,
                max_size: Some(1024),
                timeout_ms: 5000,
            }),
            LineView::Hosts(HostsView {
                entries: vec![HostEntryView {
                    host: "*.a.test".into(),
                    port: Some(443),
                    exclude: true,
                }],
            }),
            LineView::Sources(SourcesView {
                entries: vec![SourceEntryView {
                    network: "10.0.0.0/8".into(),
                    exclude: false,
                }],
            }),
        ];
        [(
            "url-rewrite".to_string(),
            views
                .into_iter()
                .enumerate()
                .map(|(index, view)| LineEntry { index, view })
                .collect(),
        )]
        .into()
    }

    fn issues() -> BTreeMap<String, Vec<Issue>> {
        [(
            "script".to_string(),
            vec![Issue {
                index: 3,
                kind: IssueKind::Resource,
                message: "missing".into(),
            }],
        )]
        .into()
    }

    fn network_def() -> NetworkDef {
        let edit = ListEdit {
            replace: true,
            before: vec!["1.1.1.1".into()],
            after: vec!["8.8.8.8".into()],
        };
        NetworkDef {
            nameserver: Some(edit.clone()),
            default_nameserver: None,
            fake_ip_filter: Some(edit.clone()),
            nameserver_policy: vec![DomainEntry {
                domain: "a.test".into(),
                values: vec!["1.1.1.1".into()],
                line: 4,
            }],
            hosts: Vec::new(),
            route_address: vec!["10.0.0.0/8".into()],
            route_exclude_address: None,
            bypass_domain: Some(edit),
            lines: vec![4],
        }
    }

    #[test]
    fn a_validation_reaches_the_wire_as_the_mitm_crate_writes_it() {
        let read = || Validation {
            issues: issues(),
            views: entries(),
        };
        assert_eq!(wire(validation(read())), wire(read()));
    }

    #[test]
    fn a_module_view_reaches_the_wire_as_the_mitm_crate_writes_it() {
        let read = || ModuleView {
            format: ModuleFormat::QuantumultX,
            meta: ModuleMeta {
                name: some("m"),
                desc: None,
                arguments_desc: some("a"),
                ..ModuleMeta::default()
            },
            off: Some(ModuleOff::RequirementUnreadable),
            arguments: vec![
                ArgumentDef {
                    name: "a".into(),
                    kind: ArgumentKind::Select {
                        options: vec!["x".into(), "y".into()],
                    },
                    number: false,
                    default: "x".into(),
                    label: some("A"),
                    desc: None,
                    line: 2,
                },
                ArgumentDef {
                    name: "b".into(),
                    kind: ArgumentKind::Switch,
                    number: true,
                    default: "true".into(),
                    label: None,
                    desc: some("B"),
                    line: 3,
                },
            ],
            resources: vec![ResourceDef {
                url: "https://a.test/s.js".into(),
                kind: ResourceKind::MapLocal,
                lines: vec![5, 6],
            }],
            declared_scripts: vec![7],
            asks_consent: true,
            issues: issues(),
            views: entries(),
            rules: vec![
                RuleView {
                    line: 8,
                    rule: ModuleRule {
                        rule: "DOMAIN,a.test".into(),
                        policy: Policy::Builtin("REJECT"),
                        no_resolve: true,
                        extended_matching: false,
                        requires_resolve: false,
                    },
                },
                RuleView {
                    line: 9,
                    rule: ModuleRule {
                        rule: "SCRIPT,s".into(),
                        policy: Policy::Named("Proxy".into()),
                        no_resolve: false,
                        extended_matching: true,
                        requires_resolve: true,
                    },
                },
            ],
            rule_sets: vec![
                RuleSetDef {
                    name: "mitm-1".into(),
                    domain: true,
                    source: RuleSetSource::Url {
                        url: "https://a.test/set".into(),
                        interval: Some(86400),
                    },
                    provider: Some(ProviderKind {
                        behavior: "domain".into(),
                        format: "text".into(),
                    }),
                },
                RuleSetDef {
                    name: "mitm-2".into(),
                    domain: false,
                    source: RuleSetSource::Url {
                        url: "https://a.test/other".into(),
                        interval: None,
                    },
                    provider: None,
                },
                RuleSetDef {
                    name: "mitm-3".into(),
                    domain: false,
                    source: RuleSetSource::Inline {
                        rules: vec![InlineRule {
                            line: 10,
                            rule: "DOMAIN,b.test".into(),
                        }],
                    },
                    provider: None,
                },
                RuleSetDef {
                    name: "mitm-4".into(),
                    domain: false,
                    source: RuleSetSource::Builtin {
                        rules: &["IP-CIDR,10.0.0.0/8"],
                    },
                    provider: None,
                },
                RuleSetDef {
                    name: "mitm-5".into(),
                    domain: false,
                    source: RuleSetSource::File {
                        file: "set.list".into(),
                    },
                    provider: None,
                },
            ],
            network: network_def(),
            ignored: vec![IgnoredView {
                line: 11,
                text: "[Panel]".into(),
                reason: IgnoreReason::AppOnly,
                detail: some("panel"),
            }],
        };
        assert_eq!(wire(module_view(read())), wire(read()));
    }

    #[test]
    fn a_module_status_reaches_the_wire_as_the_engine_writes_it() {
        let read = || {
            vec![
                ModuleStatus {
                    name: "a".into(),
                    enabled: true,
                    in_force: false,
                    problem: Some(ModuleProblem::Unreadable {
                        detail: "gone".into(),
                    }),
                    off: Some(ModuleOff::Requirement),
                    resources: vec![
                        ResourceStatus {
                            url: "https://a.test/s.js".into(),
                            kind: ResourceKind::Script,
                            lines: vec![2],
                            file: some("ab12.js"),
                            state: ResourceState::Failed,
                            error: Some(FetchFailure {
                                reason: FailureReason::Http,
                                status: Some(404),
                                detail: "not found".into(),
                            }),
                        },
                        ResourceStatus {
                            url: "https://a.test/j".into(),
                            kind: ResourceKind::Jq,
                            lines: vec![3],
                            file: None,
                            state: ResourceState::Fetching,
                            error: None,
                        },
                    ],
                    refused_rules: vec![RefusedRule {
                        line: 4,
                        detail: "no outbound".into(),
                    }],
                    host_network: network_def(),
                },
                ModuleStatus {
                    name: "b".into(),
                    enabled: false,
                    in_force: false,
                    problem: Some(ModuleProblem::Duplicate),
                    off: None,
                    resources: Vec::new(),
                    refused_rules: Vec::new(),
                    host_network: NetworkDef::default(),
                },
            ]
        };
        let expected = serde_json::json!({ "modules": wire(read()) });
        assert_eq!(wire(module_status(read())), expected);
    }
}

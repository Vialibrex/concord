//! A profile's template keys, such as `rule-anchor:` holding `domain: &domain {...}`, warn of
//! nothing on each way a host hands the profile to the core.

use std::path::Path;
use std::sync::Arc;

use concord_common::{CoreEvent, EventSink};
use concord_engine::{Engine, EngineConfig, SetupRequest, ops};
use concord_platform::NativePlatform;
use serde_json::Value;

const PROFILE: &str = "\
rule-anchor:
  domain: &domain {type: inline, behavior: domain}
proxy-provider-anchor:
  inline: &inline {type: inline, health-check: {enable: false}}
dns:
  enable: false
  cn-dns: &cn [223.5.5.5]
  nameserver: *cn
proxy-providers:
  p1:
    <<: *inline
    payload:
      - {name: a, type: socks5, server: 127.0.0.1, port: 1}
rule-providers:
  cn:
    <<: *domain
    payload: [example.com]
proxy-groups:
  - {name: G, type: select, use: [p1], proxies: [DIRECT]}
rules:
  - RULE-SET,cn,G
  - MATCH,DIRECT
";

const TEMPLATES: [&str; 3] = ["rule-anchor", "proxy-provider-anchor", "cn-dns"];

struct NoEvents;

impl EventSink for NoEvents {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: CoreEvent) {}
}

fn names_a_template(text: &str) -> bool {
    TEMPLATES.iter().any(|template| text.contains(template))
}

async fn applied(engine: &Arc<Engine>, base: Option<(String, String)>) -> Vec<String> {
    engine
        .setup(SetupRequest {
            base,
            selected: Default::default(),
            options: Default::default(),
        })
        .await
        .unwrap();
    engine.warnings().into_iter().map(|w| w.path).collect()
}

/// What `config.read` gives a host, which the host writes back whole after a script.
async fn read_whole(profile: &Path) -> Value {
    let mut config = ops::read_config(profile.display().to_string())
        .await
        .unwrap();
    let map = config.as_object_mut().unwrap();
    let rules = map.remove("rule").unwrap();
    map.insert("rules".into(), rules);
    map.insert("mixed-port".into(), 0.into());
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_keys_warn_of_nothing_on_any_way_in() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("profile.yaml");
    std::fs::write(&profile, PROFILE).unwrap();
    let path = profile.display().to_string();

    let checked = ops::check_config(path.clone(), false).await.unwrap();
    assert!(checked.is_empty(), "-t warns: {checked:?}");

    let whole = read_whole(&profile).await;
    assert!(!names_a_template(&whole.to_string()), "{whole}");

    let base = concord_config::profile_base(PROFILE.as_bytes(), None).unwrap();
    let mut overlay = base.config.as_object().cloned().unwrap();
    overlay.remove("rule");
    overlay.insert("rules".into(), Value::Array(Vec::new()));
    overlay.insert("mixed-port".into(), 0.into());
    let overlay = Value::Object(overlay).to_string();
    assert!(!names_a_template(&overlay), "{overlay}");

    let home = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    let config = home.path().join("config.yaml");

    let warned = applied(&engine, Some((path, overlay))).await;
    assert!(
        warned.is_empty(),
        "an apply over the profile warns: {warned:?}"
    );
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(!names_a_template(&written), "{written}");
    let warned = applied(&engine, None).await;
    assert!(warned.is_empty(), "a resume warns: {warned:?}");

    std::fs::write(&config, whole.to_string()).unwrap();
    let warned = applied(&engine, None).await;
    assert!(
        warned.is_empty(),
        "the config a script returned warns: {warned:?}"
    );

    engine.shutdown().await;
}

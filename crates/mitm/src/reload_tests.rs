use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use concord_config::mitm::{BodyActionDef, MitmDef};
use serde_json::json;

use crate::config::RawConfig;
use crate::script::testkit::{FakeRuntime, sync_program};
use crate::script::{EVENT_PROFILE_RELOADED, ScriptProgram, ScriptResult, ScriptRuntime};
use crate::testing::{Client, Rig, TestServer, echo, rig_for, start_server};
use concord_test_support::eventually;

/// A rig whose runtime knows each source in `programs`; the files are written by the test.
async fn rig_knowing(programs: Vec<(&str, Arc<dyn ScriptProgram>)>) -> (TestServer, Rig) {
    let server = start_server(true, &["http/1.1"], echo()).await;
    let mut runtime = FakeRuntime::default();
    for (source, program) in programs {
        runtime.0.insert(source.to_string(), program);
    }
    let rig = rig_for(&server, Some(Arc::new(runtime) as Arc<dyn ScriptRuntime>));
    std::fs::create_dir_all(rig.resources()).unwrap();
    (server, rig)
}

fn adds(value: &'static str) -> Arc<dyn ScriptProgram> {
    sync_program(move |invocation| {
        let mut header = invocation.request.as_ref().unwrap().header.clone();
        header.insert("X-Added".into(), vec![value.into()]);
        Ok(ScriptResult {
            header: Some(header),
            ..ScriptResult::default()
        })
    })
}

/// Writes `content` over the file at `path`, of its length, and puts its modification time
/// back, so only its content tells the two apart.
fn replace_in_place(path: &Path, content: &str) {
    let before = std::fs::metadata(path).unwrap();
    assert_eq!(before.len(), content.len() as u64);
    std::fs::write(path, content).unwrap();
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(before.modified().unwrap())
        .unwrap();
    let after = std::fs::metadata(path).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
}

fn scripted(path: &str) -> serde_json::Value {
    json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "script": [format!(r"add = type=http-request,pattern=^https://example\.test/,script-path={path}")],
    })
}

async fn added(rig: &Rig) -> String {
    let mut client = Client::tls(rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let text = client.get("/x").await.text();
    text.split('|').nth(2).unwrap_or_default().to_string()
}

#[tokio::test]
async fn a_script_rewritten_in_place_runs_its_new_content() {
    let (_server, rig) = rig_knowing(vec![("AA", adds("a")), ("BB", adds("b"))]).await;
    let file = rig.resources().join("s.js");
    std::fs::write(&file, "AA").unwrap();
    assert!(rig.config(scripted("s.js")).is_empty());
    assert_eq!(added(&rig).await, "a");

    replace_in_place(&file, "BB");
    assert!(rig.config(scripted("s.js")).is_empty());
    assert_eq!(added(&rig).await, "b");
}

#[tokio::test]
async fn a_script_that_breaks_and_is_fixed_in_place_runs_again() {
    let (_server, rig) = rig_knowing(vec![("AA", adds("a")), ("BB", adds("b"))]).await;
    let file = rig.resources().join("s.js");
    std::fs::write(&file, "AA").unwrap();
    assert!(rig.config(scripted("s.js")).is_empty());

    replace_in_place(&file, "ZZ");
    let errors = rig.config(scripted("s.js"));
    assert!(
        errors.len() == 1 && errors[0].contains("SyntaxError: ZZ"),
        "{errors:?}"
    );
    assert_eq!(rig.config(scripted("s.js")), errors);
    assert_eq!(added(&rig).await, "");

    replace_in_place(&file, "BB");
    assert!(rig.config(scripted("s.js")).is_empty());
    assert_eq!(added(&rig).await, "b");
}

#[tokio::test]
async fn a_missing_script_that_appears_runs() {
    let (_server, rig) = rig_knowing(vec![("AA", adds("a"))]).await;
    let errors = rig.config(scripted("late.js"));
    assert!(
        errors.len() == 1 && errors[0].contains("no such file"),
        "{errors:?}"
    );
    assert_eq!(added(&rig).await, "");

    std::fs::write(rig.resources().join("late.js"), "AA").unwrap();
    assert!(rig.config(scripted("late.js")).is_empty());
    assert_eq!(added(&rig).await, "a");
}

#[tokio::test]
async fn a_map_local_file_rewritten_in_place_answers_its_new_content() {
    let (_server, rig) = rig_knowing(Vec::new()).await;
    let file = rig.resources().join("m.txt");
    std::fs::write(&file, "old-body").unwrap();
    let section = json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "map-local": [r#"^https://example\.test/m data-type=file data="m.txt""#],
    });
    let get = || async {
        let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
            .await
            .unwrap();
        client.get("/m").await.text()
    };
    assert!(rig.config(section.clone()).is_empty());
    assert_eq!(get().await, "old-body");

    replace_in_place(&file, "new-body");
    assert!(rig.config(section).is_empty());
    assert_eq!(get().await, "new-body");
}

#[tokio::test]
async fn a_jq_file_rewritten_in_place_runs_its_new_filter() {
    let (_server, rig) = rig_knowing(Vec::new()).await;
    let file = rig.resources().join("f.jq");
    std::fs::write(&file, ".a").unwrap();
    let def = || {
        let raw: RawConfig = serde_json::from_value(json!({
            "enable": true,
            "hostname": ["example.test"],
            "skip-server-cert-verify": true,
            "body-rewrite": [r"http-request-jq ^https://example\.test/ '.'"],
        }))
        .unwrap();
        let mut def = MitmDef::read(&raw);
        def.body_rewrite[0].read.as_mut().unwrap().action = BodyActionDef::JqFile("f.jq".into());
        Some(def)
    };
    let post = || async {
        let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
            .await
            .unwrap();
        let request = client.request(
            "POST",
            "/j",
            &[("content-type", "application/json")],
            r#"{"a":"one","b":"two"}"#,
        );
        let text = client.send(request).await.unwrap().text();
        text.rsplit('|').next().unwrap_or_default().to_string()
    };
    let tasks = || concord_common::Tasks::current(Default::default(), Default::default());
    assert!(rig.mitm.apply_section(def(), tasks()).is_empty());
    assert_eq!(post().await, r#""one""#);

    replace_in_place(&file, ".b");
    assert!(rig.mitm.apply_section(def(), tasks()).is_empty());
    assert_eq!(post().await, r#""two""#);
}

#[tokio::test]
async fn an_unchanged_apply_keeps_the_engine_and_reports_one_reload() {
    let reloads = Arc::new(std::sync::Mutex::new(0usize));
    let counter = {
        let reloads = reloads.clone();
        sync_program(move |_| {
            *lock(&reloads) += 1;
            Ok(ScriptResult::default())
        })
    };
    let (_server, rig) = rig_knowing(vec![("AA", adds("a")), ("EV", counter)]).await;
    std::fs::write(rig.resources().join("s.js"), "AA").unwrap();
    std::fs::write(rig.resources().join("ev.js"), "EV").unwrap();
    let section = || {
        let mut section = scripted("s.js");
        section["script"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!(
                "ev = type=event,event-name={EVENT_PROFILE_RELOADED},script-path=ev.js"
            )));
        section["url-rewrite"] = json!(["^https://example\\.test/bad( _ reject"]);
        section
    };
    let errors = rig.config(section());
    assert_eq!(errors.len(), 1, "{errors:?}");
    rig.mitm.set_running(true);
    let engine = Arc::downgrade(&rig.mitm.engine().unwrap().core);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/x").await.status, 200);

    assert_eq!(rig.config(section()), errors);
    assert!(eventually(|| *lock(&reloads) == 1).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*lock(&reloads), 1);
    assert!(Arc::ptr_eq(
        &engine.upgrade().unwrap(),
        &rig.mitm.engine().unwrap().core
    ));
    assert_eq!(client.get("/y").await.status, 200);
}

#[tokio::test]
async fn an_unchanged_apply_reports_its_own_lines_and_modules() {
    let (_server, rig) = rig_knowing(Vec::new()).await;
    let section = |local: &str| {
        json!({
            "enable": true,
            "hostname": ["example.test"],
            "url-rewrite": ["^https://a\\.test/( _ reject"],
            "map-local": [local],
        })
    };
    let missing = r#"^https://b\.test/ data-type=file data="gone.txt""#;
    let errors = rig.config(section(missing));
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(rig.config(section(missing)), errors);
    let spaced = r#"^https://b\.test/    data-type=file   data="gone.txt""#;
    let respaced = rig.config(section(spaced));
    assert_eq!(respaced.len(), 2, "{respaced:?}");
    assert!(
        respaced[1].contains("/    data-type=file   data="),
        "{respaced:?}"
    );

    let raw: RawConfig = serde_json::from_value(section(missing)).unwrap();
    let def = |origin: &str| {
        let mut def = MitmDef::read(&raw);
        def.mark_origin(&Arc::from(origin));
        Some(def)
    };
    let tasks = || concord_common::Tasks::current(Default::default(), Default::default());
    let first = rig.mitm.apply_section(def("One"), tasks());
    assert_eq!(
        first.len(),
        1,
        "a section's own reading reports what did not read: {first:?}"
    );
    assert_eq!(rig.mitm.apply_section(def("One"), tasks()), first);
    let renamed = rig.mitm.apply_section(def("Two"), tasks());
    assert_eq!(renamed.len(), 1, "{renamed:?}");
    assert!(renamed[0].starts_with("module Two:"), "{renamed:?}");
    assert_eq!(rig.mitm.apply(Some(raw.clone())).len(), 2);
}

#[tokio::test]
async fn a_new_trust_store_replaces_an_unchanged_engine() {
    let (_server, rig) = rig_knowing(Vec::new()).await;
    let section = json!({"enable": true, "hostname": ["example.test"]});
    rig.config(section.clone());
    let old = rig.mitm.engine().unwrap();
    rig.config(section.clone());
    assert!(Arc::ptr_eq(&old, &rig.mitm.engine().unwrap()));

    rig.mitm
        .set_trust(concord_tls::TrustStore::new(&[], Vec::new()));
    rig.config(section);
    assert!(!Arc::ptr_eq(&old, &rig.mitm.engine().unwrap()));
}

fn mapped(name: &str) -> serde_json::Value {
    json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "map-local": [format!(r#"^https://example\.test/m data-type=file data="{name}""#)],
    })
}

async fn mapped_body(rig: &Rig) -> String {
    let mut client = Client::tls(rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/m").await.text()
}

#[tokio::test]
async fn a_large_map_local_file_is_read_at_each_answer_without_compiling_again() {
    let (_server, rig) = rig_knowing(Vec::new()).await;
    let file = rig.resources().join("big.bin");
    let size = crate::rules::LOCAL_PIECE * 3 + 7;
    std::fs::write(&file, "a".repeat(size)).unwrap();
    assert!(rig.config(mapped("big.bin")).is_empty());
    let engine = rig.mitm.engine().unwrap();
    assert_eq!(mapped_body(&rig).await, "a".repeat(size));

    replace_in_place(&file, &"b".repeat(size));
    assert!(rig.config(mapped("big.bin")).is_empty());
    assert!(Arc::ptr_eq(&engine, &rig.mitm.engine().unwrap()));
    assert_eq!(mapped_body(&rig).await, "b".repeat(size));

    std::fs::write(&file, "small").unwrap();
    assert!(rig.config(mapped("big.bin")).is_empty());
    assert!(!Arc::ptr_eq(&engine, &rig.mitm.engine().unwrap()));
    assert_eq!(mapped_body(&rig).await, "small");

    std::fs::write(&file, "c".repeat(size)).unwrap();
    assert!(rig.config(mapped("big.bin")).is_empty());
    assert_eq!(mapped_body(&rig).await, "c".repeat(size));
}

#[tokio::test]
async fn a_script_larger_than_a_piece_rewritten_in_place_runs_its_new_content() {
    let size = crate::rules::LOCAL_PIECE * 2 + 3;
    let (old, new) = ("A".repeat(size), "B".repeat(size));
    let (_server, rig) = rig_knowing(vec![(&old, adds("a")), (&new, adds("b"))]).await;
    let file = rig.resources().join("s.js");
    std::fs::write(&file, &old).unwrap();
    assert!(rig.config(scripted("s.js")).is_empty());
    assert_eq!(added(&rig).await, "a");

    replace_in_place(&file, &new);
    assert!(rig.config(scripted("s.js")).is_empty());
    assert_eq!(added(&rig).await, "b");
}

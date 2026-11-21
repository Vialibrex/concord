//! Embeds a corpus of modules, so `mitm-modules` runs from a harness copied to another machine,
//! with the remote files each module reads as its `.expect.json` lists them: the private corpus
//! `CONCORD_MODULE_CORPUS` names at build time, or the config crate's samples without one.

use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed=CONCORD_MODULE_CORPUS");
    let dir = match std::env::var_os("CONCORD_MODULE_CORPUS") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
            .join("../../crates/config/tests/data/modules"),
    }
    .canonicalize()?;
    println!("cargo::rerun-if-changed={}", dir.display());
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !(name.ends_with(".json") || name.ends_with(".md") || name.starts_with("LICENSE")) {
            paths.push(path);
        }
    }
    paths.sort();
    let mut out = String::from("pub const CORPUS: &[Module] = &[\n");
    for path in paths {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let mut resources = String::new();
        let expect = dir.join(format!("{name}.expect.json"));
        if let Ok(text) = std::fs::read_to_string(&expect) {
            let parsed: serde_json::Value = serde_json::from_str(&text)?;
            for resource in parsed["resources"].as_array().into_iter().flatten() {
                let (Some(url), Some(kind)) = (resource["url"].as_str(), resource["kind"].as_str())
                else {
                    continue;
                };
                write!(resources, "({url:?}, {kind:?}), ")?;
            }
        }
        writeln!(
            out,
            "    Module {{ name: {name:?}, text: include_str!({:?}), resources: &[{resources}] }},",
            path.display().to_string()
        )?;
    }
    out.push_str("];\n");
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("corpus.rs"),
        out,
    )?;
    Ok(())
}

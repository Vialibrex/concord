//! Holds every `for crate in …; do` loop in the files below to the workspace members that declare default
//! features. A workspace build turns those features on, so only these loops build a crate without them.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const LOOPS: &[&str] = &[
    ".github/workflows/ci.yaml",
    ".github/workflows/toolchain-drift.yaml",
    ".agents/commands.md",
];

fn members_with_defaults(root: &Path) -> Result<BTreeSet<String>, String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(root)
        .output()
        .map_err(|err| format!("cargo metadata: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
    Ok(metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|package| {
            package
                .pointer("/features/default")
                .and_then(Value::as_array)
                .is_some_and(|default| !default.is_empty())
        })
        .filter_map(|package| Some(package.get("name")?.as_str()?.to_string()))
        .collect())
}

fn crate_loops(text: &str) -> Vec<BTreeSet<String>> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("for crate in "))
        .filter_map(|rest| rest.split_once("; do"))
        .map(|(names, _)| names.split_whitespace().map(str::to_string).collect())
        .collect()
}

fn problems(file: &str, text: &str, expected: &BTreeSet<String>) -> Vec<String> {
    let loops = crate_loops(text);
    if loops.is_empty() {
        return vec![format!("{file}: no `for crate in …; do` loop")];
    }
    loops
        .iter()
        .filter(|names| *names != expected)
        .map(|names| {
            format!(
                "{file}: a loop names {names:?}; the members with default features are {expected:?}"
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_loop_names_the_members_with_default_features() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let expected = members_with_defaults(&root).unwrap();
        let mut all = Vec::new();
        for file in LOOPS {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            all.extend(problems(file, &text, &expected));
        }
        assert!(all.is_empty(), "{}", all.join("\n"));
    }

    #[test]
    fn a_loop_that_misses_a_member_is_reported() {
        let expected: BTreeSet<String> = ["a".to_string(), "b".to_string()].into();
        let text = "  for crate in a; do\n  for crate in a b; do\n";
        assert_eq!(problems("f", text, &expected).len(), 1);
        assert_eq!(problems("f", "no loop", &expected).len(), 1);
    }
}

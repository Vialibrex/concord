//! Holds the background tasks below the engine to `concord_common::Tasks`, which registers each with
//! the engine's tracker so shutdown can stop it and wait for it, and the external controller's
//! sessions to the `Tasks` over its listener's tracker. A task started with `tokio::spawn`, on a
//! runtime `Handle`, in a `JoinSet` or by hyper's `TokioExecutor` outlives its owner. The check
//! reads names, not types: it sees these by the paths and imports that name them, so a handle that
//! arrives without its type being named stays out of its sight.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

use crate::ratchets::{is_test, is_test_file};
use crate::stream_policy::rust_files;

const OWNED: &[&str] = &[
    "crates/proxy/src",
    "crates/quic/src",
    "crates/transport/src",
    "crates/net/src",
    "crates/tls/src",
    "crates/dns/src",
    "crates/group/src",
    "crates/tunnel/src",
    "crates/inbound/src",
    "crates/tun/src",
    "crates/mitm/src",
    "crates/api/src",
    "crates/engine/src",
    "crates/controller/src",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    for dir in OWNED {
        rust_files(&root.join(dir), &mut files)?;
    }
    files.sort();
    let mut parsed = Vec::new();
    let mut test_only = BTreeSet::new();
    for file in files {
        let name = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let source =
            std::fs::read_to_string(&file).map_err(|err| format!("{}: {err}", file.display()))?;
        let syntax = syn::parse_file(&source).map_err(|err| format!("{name}: {err}"))?;
        test_only.extend(test_modules(&file, &syntax));
        parsed.push((file, name, syntax));
    }
    let mut problems = Vec::new();
    for (file, name, syntax) in parsed {
        if is_test_file(&name) || test_only.iter().any(|dir| file.starts_with(dir)) {
            continue;
        }
        problems.extend(unowned(&name, &syntax));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// The files of the modules `file` declares under `cfg(test)` without a body: `name.rs` and
/// `name/` beside it, or the `#[path]` it names.
fn test_modules(file: &Path, syntax: &syn::File) -> Vec<PathBuf> {
    let Some(dir) = file.parent() else {
        return Vec::new();
    };
    let own = match file.file_stem().and_then(|stem| stem.to_str()) {
        Some("mod" | "lib" | "main") | None => dir.to_path_buf(),
        Some(stem) => dir.join(stem),
    };
    let mut found = Vec::new();
    for item in &syntax.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_some() || !is_test(&module.attrs) {
            continue;
        }
        let named = module.attrs.iter().find_map(|attr| match &attr.meta {
            syn::Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(path),
                    ..
                }) => Some(dir.join(path.value())),
                _ => None,
            },
            _ => None,
        });
        match named {
            Some(path) => found.push(path),
            None => {
                let name = module.ident.to_string();
                found.push(own.join(format!("{name}.rs")));
                found.push(own.join(name));
            }
        }
    }
    found
}

fn unowned(name: &str, syntax: &syn::File) -> Vec<String> {
    let mut finder = Unowned::default();
    finder.visit_file(syntax);
    finder
        .found
        .into_iter()
        .map(|(line, call)| {
            format!("{name}:{line}: `{call}` starts a task nothing owns; spawn it through `Tasks`")
        })
        .collect()
}

#[derive(Default)]
struct Unowned {
    found: Vec<(usize, String)>,
}

fn unowned_call(path: &syn::Path) -> Option<String> {
    let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    unowned_names(&names).then(|| names.join("::"))
}

fn unowned_names(names: &[String]) -> bool {
    let tail: Vec<&str> = names.iter().rev().take(2).map(String::as_str).collect();
    let from_tokio = names.first().is_some_and(|first| first == "tokio");
    let spawns = matches!(tail.as_slice(), ["spawn" | "spawn_local", ..])
        && (names.len() == 1 || from_tokio || tail.get(1) == Some(&"task"));
    let takes_handle = matches!(tail.as_slice(), ["current" | "try_current", "Handle"])
        || (from_tokio && tail.first() == Some(&"Handle"));
    let runs_its_own = names
        .iter()
        .any(|name| name == "JoinSet" || name == "TokioExecutor");
    spawns || takes_handle || runs_its_own
}

/// Every path a `use` brings in, with `self` folded into its parent and renames under their
/// original name.
fn imported(tree: &syn::UseTree, prefix: &mut Vec<String>, found: &mut Vec<(usize, Vec<String>)>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            imported(&path.tree, prefix, found);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            found.push((name.ident.span().start().line, prefix.clone()));
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            found.push((name.ident.span().start().line, full));
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            found.push((rename.ident.span().start().line, full));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                imported(item, prefix, found);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

impl<'ast> Visit<'ast> for Unowned {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !is_test(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !is_test(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !is_test(&item.attrs) {
            visit::visit_item_impl(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if is_test(&item.attrs) {
            return;
        }
        let mut found = Vec::new();
        imported(&item.tree, &mut Vec::new(), &mut found);
        for (line, names) in found {
            if unowned_names(&names) {
                self.found.push((line, format!("use {}", names.join("::"))));
            }
        }
    }

    fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
        if let Some(name) = unowned_call(&ty.path) {
            let line = ty
                .path
                .segments
                .first()
                .map_or(0, |segment| segment.ident.span().start().line);
            self.found.push((line, name));
        }
        visit::visit_type_path(self, ty);
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if let Some(call) = unowned_call(&expr.path) {
            let line = expr
                .path
                .segments
                .first()
                .map_or(0, |segment| segment.ident.span().start().line);
            self.found.push((line, call));
        }
        visit::visit_expr_path(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owned_crates_spawn_only_through_tasks() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn a_spawn_or_a_handle_outside_tests_is_reported() {
        let source = "\
fn a() {
    tokio::spawn(async {});
    let _ = tokio::runtime::Handle::try_current();
    tasks.spawn(async {});
    tokio::task::spawn_blocking(|| ()).await;
}
#[cfg(test)]
mod tests {
    fn b() {
        tokio::spawn(async {});
    }
}
";
        let found = unowned("crates/proxy/src/a.rs", &syn::parse_file(source).unwrap());
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].starts_with("crates/proxy/src/a.rs:2: `tokio::spawn`"));
        assert!(
            found[1].starts_with("crates/proxy/src/a.rs:3: `tokio::runtime::Handle::try_current`")
        );
    }

    #[test]
    fn a_spawn_by_another_name_a_handle_a_join_set_or_hyper_s_executor_is_reported() {
        let source = "\
use tokio::task;
use tokio::task::{JoinHandle, spawn as go};
use tokio::runtime::Handle;
use hyper_util::rt::TokioExecutor;
fn a(handle: tokio::runtime::Handle) {
    task::spawn(async {});
    let mut set = tokio::task::JoinSet::new();
    let _ = TokioExecutor::new();
    task::spawn_blocking(|| ());
}
";
        let found = unowned("crates/proxy/src/a.rs", &syn::parse_file(source).unwrap());
        let lines: Vec<&str> = found
            .iter()
            .map(|problem| problem.split(" starts").next().unwrap())
            .collect();
        assert_eq!(
            lines,
            [
                "crates/proxy/src/a.rs:2: `use tokio::task::spawn`",
                "crates/proxy/src/a.rs:3: `use tokio::runtime::Handle`",
                "crates/proxy/src/a.rs:4: `use hyper_util::rt::TokioExecutor`",
                "crates/proxy/src/a.rs:5: `tokio::runtime::Handle`",
                "crates/proxy/src/a.rs:6: `task::spawn`",
                "crates/proxy/src/a.rs:7: `tokio::task::JoinSet::new`",
                "crates/proxy/src/a.rs:8: `TokioExecutor::new`",
            ]
        );
    }

    #[test]
    fn a_module_declared_for_tests_is_skipped_with_its_children() {
        let syntax = syn::parse_file(
            "#[cfg(test)]\nmod serve;\n#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x;\nmod live;\n",
        )
        .unwrap();
        assert_eq!(
            test_modules(Path::new("src/stack.rs"), &syntax),
            [
                PathBuf::from("src/stack/serve.rs"),
                PathBuf::from("src/stack/serve"),
                PathBuf::from("src/x_tests.rs"),
            ]
        );
        assert_eq!(
            test_modules(Path::new("src/lib.rs"), &syntax)[0],
            PathBuf::from("src/serve.rs")
        );
    }
}

//! Holds every numeric or `Duration` `const` and `static` in non-test code under `crates/` and
//! `bins/` to the tunables rule in `.agents/rules.md`. Each item is registered once: as a tunable
//! with its basis in the "Tunables" table of `.agents/reference-choices.md`, as a wire or format
//! constant under "Wire And Format Constants" there, or in `xtask/tunables.txt`, the ratchet of
//! tunables still without a basis, which only shrinks. A table row or ratchet line also records
//! the value, so a change of value fails until its row is updated. Whether a citation supports
//! the value is the reviewer's to open.

mod scan;
mod value;

use std::collections::BTreeMap;
use std::path::Path;

use scan::{Item, scan};
use value::{parse_values, render_values, values_match};

const DOC: &str = ".agents/reference-choices.md";
const RATCHET: &str = "xtask/tunables.txt";
const TUNABLES: &str = "## Tunables";
const WIRE: &str = "## Wire And Format Constants";
const TUNABLE_COLUMNS: &[&str] = &["Item", "Value", "Basis", "Citation or derivation"];
const WIRE_COLUMNS: &[&str] = &["Item or module", "Spec"];
/// Entries in `xtask/tunables.txt`. It only comes down: lower it with the file.
const RATCHET_CEILING: usize = 76;

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let items = scan(root)?;
    let doc = std::fs::read_to_string(root.join(DOC)).map_err(|err| format!("{DOC}: {err}"))?;
    let ratchet =
        std::fs::read_to_string(root.join(RATCHET)).map_err(|err| format!("{RATCHET}: {err}"))?;
    let problems = problems(&items, &doc, &ratchet, RATCHET_CEILING);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

struct Row {
    line: usize,
    items: Vec<String>,
    value: String,
    basis: String,
    citation: String,
}

struct Exemption {
    line: usize,
    pattern: String,
    spec: String,
}

struct Ratcheted {
    line: usize,
    path: String,
    value: String,
}

/// A `## ` section's table: its header, and each row's line number and cells.
type Table = (Vec<String>, Vec<(usize, Vec<String>)>);

fn table(doc: &str, heading: &str) -> Option<Table> {
    let mut lines = doc
        .lines()
        .enumerate()
        .skip_while(|(_, l)| l.trim_end() != heading);
    lines.next()?;
    let mut header = None;
    let mut rows = Vec::new();
    for (index, line) in lines {
        if line.starts_with("## ") {
            break;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells = crate::reference_choices::cells(line);
        if header.is_none() {
            header = Some(cells);
        } else if !cells
            .iter()
            .all(|c| c.chars().all(|c| c == '-' || c == ':'))
        {
            rows.push((index + 1, cells));
        }
    }
    Some((header.unwrap_or_default(), rows))
}

fn item_names(cell: &str) -> Vec<String> {
    cell.split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, name)| name.trim().to_string())
        .collect()
}

fn parse_doc(doc: &str, problems: &mut Vec<String>) -> (Vec<Row>, Vec<Exemption>) {
    let mut rows = Vec::new();
    match table(doc, TUNABLES) {
        None => problems.push(format!("{DOC}: section `{TUNABLES}` is missing")),
        Some((header, _)) if header != TUNABLE_COLUMNS => problems.push(format!(
            "{DOC}: `{TUNABLES}` columns are not {TUNABLE_COLUMNS:?}"
        )),
        Some((_, cells)) => {
            for (line, cells) in cells {
                let [items, value, basis, citation] = cells.as_slice() else {
                    problems.push(format!(
                        "{DOC}:{line}: expected {} cells",
                        TUNABLE_COLUMNS.len()
                    ));
                    continue;
                };
                rows.push(Row {
                    line,
                    items: item_names(items),
                    value: value.clone(),
                    basis: basis.clone(),
                    citation: citation.clone(),
                });
            }
        }
    }
    let mut exemptions = Vec::new();
    match table(doc, WIRE) {
        None => problems.push(format!("{DOC}: section `{WIRE}` is missing")),
        Some((header, _)) if header != WIRE_COLUMNS => {
            problems.push(format!("{DOC}: `{WIRE}` columns are not {WIRE_COLUMNS:?}"));
        }
        Some((_, cells)) => {
            for (line, cells) in cells {
                let [patterns, spec] = cells.as_slice() else {
                    problems.push(format!(
                        "{DOC}:{line}: expected {} cells",
                        WIRE_COLUMNS.len()
                    ));
                    continue;
                };
                for pattern in item_names(patterns) {
                    exemptions.push(Exemption {
                        line,
                        pattern,
                        spec: spec.clone(),
                    });
                }
            }
        }
    }
    (rows, exemptions)
}

fn parse_ratchet(text: &str, problems: &mut Vec<String>) -> Vec<Ratcheted> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let body = line.split_once('#').map_or(line, |(body, _)| body).trim();
        if body.is_empty() {
            continue;
        }
        match body.split_once(' ') {
            Some((path, value)) => entries.push(Ratcheted {
                line: line_no,
                path: path.to_string(),
                value: value.trim().to_string(),
            }),
            None => problems.push(format!("{RATCHET}:{line_no}: expected `<item> <value>`")),
        }
    }
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        problems.push(format!("{RATCHET}: keep the items sorted and unique"));
    }
    entries
}

/// A basis is `A` (a spec), `B` (the reference's value), `C` (a runtime mechanism) or `O` (a
/// requirement of a feature only Concord has), and its citation names where to open it.
fn basis_problem(row: &Row) -> Option<String> {
    let citation = &row.citation;
    let cited = crate::reference_choices::has_citation(citation);
    match row.basis.as_str() {
        "A" if cited || has_spec(citation) => None,
        "A" => Some(
            "basis A cites no spec (an RFC, a draft, a `file:line`, or a URL and its section)"
                .to_string(),
        ),
        "B" if cited && crate::reference_choices::names_reference(citation) => None,
        "B" => {
            Some("basis B cites no `file:line` in a reference named under References".to_string())
        }
        "C" if cited => None,
        "C" => Some("basis C cites no `file:line` or `file::symbol` for the mechanism".to_string()),
        "O" if cited => None,
        "O" => Some("basis O cites no `file:line` for the requirement".to_string()),
        other => Some(format!("basis `{other}` is not A, B, C or O")),
    }
}

fn has_spec(text: &str) -> bool {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair[0] == "RFC" && pair[1].starts_with(|c: char| c.is_ascii_digit()))
        || text.contains("draft-")
        || text.contains("https://")
}

fn exempts(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix("::*") {
        Some(module) => path.starts_with(&format!("{module}::")),
        None => pattern == path,
    }
}

fn problems(items: &[Item], doc: &str, ratchet: &str, ceiling: usize) -> Vec<String> {
    let mut problems = Vec::new();
    let (rows, exemptions) = parse_doc(doc, &mut problems);
    let ratcheted = parse_ratchet(ratchet, &mut problems);
    let by_path: BTreeMap<&str, &Item> = items.iter().map(|i| (i.path.as_str(), i)).collect();
    let mut claims = Claims::default();
    for row in &rows {
        row_problems(row, &by_path, &mut claims, &mut problems);
    }
    ratchet_problems(&ratcheted, ceiling, &by_path, &mut claims, &mut problems);
    for exemption in &exemptions {
        let at = format!("{DOC}:{}", exemption.line);
        if exemption.spec.trim().is_empty() || exemption.spec.trim() == "—" {
            problems.push(format!("{at}: `{}` names no spec", exemption.pattern));
        }
        let module = exemption.pattern.ends_with("::*");
        let mut matched = false;
        for item in items
            .iter()
            .filter(|item| exempts(&exemption.pattern, &item.path))
        {
            matched = true;
            if !(module && claims.0.contains_key(&item.path)) {
                claims.claim(&item.path, &at, &mut problems);
            }
        }
        if !matched {
            problems.push(format!(
                "{at}: `{}` matches no numeric const or static; fix it or delete it",
                exemption.pattern
            ));
        }
    }
    for item in items {
        if !claims.0.contains_key(&item.path) {
            problems.push(format!(
                "{}:{}: `{}` = {} has no basis. A tunable gets a row in {DOC} `{TUNABLES}` \
                 (value, basis A/B/C/O and its citation; `.agents/rules.md`, \"Tunables\"); a wire \
                 or format constant gets a line under `{WIRE}` with its spec",
                item.file,
                item.line,
                item.path,
                render_values(&item.values)
            ));
        }
    }
    problems
}

#[derive(Default)]
struct Claims(BTreeMap<String, String>);

impl Claims {
    fn claim(&mut self, path: &str, by: &str, problems: &mut Vec<String>) {
        match self.0.get(path) {
            Some(first) => {
                problems.push(format!(
                    "`{path}` is registered twice: {first} and {by}; keep one"
                ));
            }
            None => {
                self.0.insert(path.to_string(), by.to_string());
            }
        }
    }
}

fn row_problems(
    row: &Row,
    by_path: &BTreeMap<&str, &Item>,
    claims: &mut Claims,
    problems: &mut Vec<String>,
) {
    let at = format!("{DOC}:{}", row.line);
    if row.items.is_empty() {
        problems.push(format!(
            "{at}: name the item in backticks, `crate::module::NAME`"
        ));
    }
    if let Some(problem) = basis_problem(row) {
        problems.push(format!("{at}: {problem}"));
    }
    let Some(written) = parse_values(&row.value) else {
        problems.push(format!(
            "{at}: value `{}` is not a number, a number with a unit (B, KiB, MiB, GiB, ns, µs, \
             ms, s, min, h), `source text`, or `cfg` variants joined by ` / `",
            row.value
        ));
        return;
    };
    for path in &row.items {
        let Some(item) = by_path.get(path.as_str()) else {
            problems.push(format!(
                "{at}: `{path}` is not a numeric or `Duration` const or static in non-test code; \
                 fix the path or delete the row"
            ));
            continue;
        };
        claims.claim(path, &at, problems);
        if !values_match(&item.values, &written) {
            problems.push(format!(
                "{at}: `{path}` is {} in {}:{}, the row says {}; update the row and its basis",
                render_values(&item.values),
                item.file,
                item.line,
                row.value
            ));
        }
    }
}

fn ratchet_problems(
    ratcheted: &[Ratcheted],
    ceiling: usize,
    by_path: &BTreeMap<&str, &Item>,
    claims: &mut Claims,
    problems: &mut Vec<String>,
) {
    if ratcheted.len() > ceiling {
        problems.push(format!(
            "{RATCHET}: {} entries, above the ceiling of {ceiling}; the ratchet only shrinks: give \
             a new tunable its basis in {DOC} `{TUNABLES}`",
            ratcheted.len()
        ));
    } else if ratcheted.len() < ceiling {
        problems.push(format!(
            "{RATCHET}: {} entries; lower `RATCHET_CEILING` in xtask/src/tunables/mod.rs from \
             {ceiling} to {}",
            ratcheted.len(),
            ratcheted.len()
        ));
    }
    for entry in ratcheted {
        let at = format!("{RATCHET}:{}", entry.line);
        let Some(item) = by_path.get(entry.path.as_str()) else {
            problems.push(format!(
                "{at}: `{}` is no longer a numeric const or static; delete its line",
                entry.path
            ));
            continue;
        };
        claims.claim(&entry.path, &at, problems);
        if !parse_values(&entry.value).is_some_and(|written| values_match(&item.values, &written)) {
            problems.push(format!(
                "{at}: `{}` is {} in {}:{}, the ratchet says {}; a tunable without a basis keeps \
                 its value: give it a basis in {DOC} `{TUNABLES}` and delete this line",
                entry.path,
                render_values(&item.values),
                item.file,
                item.line,
                entry.value
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scan::*;
    use super::value::*;
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn every_tunable_has_a_basis() {
        if let Err(problems) = check(&root()) {
            panic!("{problems}");
        }
    }

    #[test]
    #[ignore = "prints every unregistered item as a ratchet line; for an author, not the gate"]
    fn list_unregistered() {
        let items = scan(&root()).unwrap();
        let doc = std::fs::read_to_string(root().join(DOC)).unwrap();
        let ratchet = std::fs::read_to_string(root().join(RATCHET)).unwrap_or_default();
        let problems = problems(&items, &doc, &ratchet, usize::MAX);
        for item in &items {
            if problems
                .iter()
                .any(|p| p.contains(&format!("`{}` = ", item.path)))
            {
                println!(
                    "{} {}  # {}:{}",
                    item.path,
                    render_values(&item.values),
                    item.file,
                    item.line
                );
            }
        }
    }

    fn items(file: &str, source: &str) -> Vec<Item> {
        scan_source(file, source).unwrap()
    }

    fn value(source: &str) -> Vec<Value> {
        items("crates/a/src/b.rs", source).remove(0).values
    }

    const DOC_HEAD: &str = "## Tunables\n\n| Item | Value | Basis | Citation or derivation |\n\
                            |---|---|---|---|\n";
    const WIRE_HEAD: &str =
        "\n## Wire And Format Constants\n\n| Item or module | Spec |\n|---|---|\n";

    fn doc(rows: &str, wire: &str) -> String {
        format!("{DOC_HEAD}{rows}{WIRE_HEAD}{wire}\n## Next\n")
    }

    const SOURCE: &str = "use std::time::Duration;\n\
        const BATCH: usize = 64;\n\
        pub(crate) const IDLE: Duration = Duration::from_secs(60);\n\
        const VERSION: u8 = 5;\n\
        const NAME: &str = \"x\";\n\
        #[cfg(test)]\nmod tests { const T: usize = 1; }\n\
        #[cfg(any(test, windows))]\nconst WINDOWS: u16 = 23;\n\
        #[cfg(all(test, unix))]\nconst UNIX_TEST: u16 = 1;\n\
        fn f() { const LOCAL: u32 = 2 * BATCH as u32; }\n";

    #[test]
    fn items_are_found_with_their_paths_and_values() {
        let found = items("crates/net/src/relay/mod.rs", SOURCE);
        let names: Vec<(&str, String)> = found
            .iter()
            .map(|i| (i.path.as_str(), render_values(&i.values)))
            .collect();
        assert_eq!(
            names,
            [
                ("net::relay::BATCH", "64".to_string()),
                ("net::relay::IDLE", "60 s".to_string()),
                ("net::relay::VERSION", "5".to_string()),
                ("net::relay::WINDOWS", "23".to_string()),
                ("net::relay::f::LOCAL", "128".to_string()),
            ]
        );
        assert_eq!(module_of("bins/android/src/core.rs"), "android::core");
        assert_eq!(module_of("crates/net/src/lib.rs"), "net");
        assert_eq!(module_of("bins/android/build.rs"), "android::build");
    }

    #[test]
    fn values_evaluate_or_keep_their_text() {
        assert_eq!(
            value("const A: usize = 64 * 1024;"),
            [Value::Known(Quantity::Plain(Num::Int(65_536)))]
        );
        assert_eq!(
            value("const A: Duration = Duration::from_millis(1500);"),
            [Value::Known(Quantity::Duration(Num::Int(1_500_000_000)))]
        );
        assert_eq!(
            value("const A: f64 = 1.25;"),
            [Value::Known(Quantity::Plain(Num::Float(1.25)))]
        );
        assert_eq!(
            value("const A: usize = u16::MAX as usize + 1;"),
            [Value::Known(Quantity::Plain(Num::Int(65_536)))]
        );
        assert_eq!(
            value("const A: NonZeroUsize = NonZeroUsize::new(8).unwrap();"),
            [Value::Known(Quantity::Plain(Num::Int(8)))]
        );
        assert_eq!(
            value("const A: usize = other::B * 2;"),
            [Value::Text("other::B * 2".to_string())]
        );
        assert_eq!(
            value("const A: Duration = Duration::from_secs(other::SECS);"),
            [Value::Text("Duration::from_secs(other::SECS)".to_string())]
        );
        assert_eq!(
            value("#[cfg(unix)]\nconst A: usize = 4;\n#[cfg(not(unix))]\nconst A: usize = 8;"),
            [
                Value::Known(Quantity::Plain(Num::Int(4))),
                Value::Known(Quantity::Plain(Num::Int(8)))
            ]
        );
    }

    #[test]
    fn cells_parse_with_units() {
        let parse = |cell: &str| parse_written(cell).unwrap();
        assert_eq!(
            parse("64 KiB"),
            Written::Quantity(Quantity::Plain(Num::Int(65_536)))
        );
        assert_eq!(
            parse("65,536"),
            Written::Quantity(Quantity::Plain(Num::Int(65_536)))
        );
        assert_eq!(
            parse("100 ms"),
            Written::Quantity(Quantity::Duration(Num::Int(100_000_000)))
        );
        assert!(Value::Known(Quantity::Duration(Num::Int(1_500_000_000))).matches(&parse("1.5 s")));
        assert_eq!(parse("`a::B * 2`"), Written::Text("a::B * 2".to_string()));
        assert!(parse_written("64 bytes per round").is_none());
        assert!(parse_values("4 / 8").is_some_and(|v| v.len() == 2));
    }

    fn found(source: &str, rows: &str, wire: &str, ratchet: &str, ceiling: usize) -> Vec<String> {
        problems(
            &items("crates/net/src/relay.rs", source),
            &doc(rows, wire),
            ratchet,
            ceiling,
        )
    }

    const ROWS: &str = "| `net::relay::BATCH` | 64 | C | Tokio budget (`coop/mod.rs:100`) |\n\
                        | `net::relay::IDLE` | 60 s | B | mihomo `tunnel/tunnel.go:63` |\n";
    const WIRE_ROWS: &str = "| `net::relay::VERSION`, `net::relay::WINDOWS` | RFC 1928 |\n";
    const RATCHET_LINES: &str = "# header\nnet::relay::f::LOCAL 128  # no basis yet\n";

    #[test]
    fn a_fully_registered_tree_passes() {
        assert_eq!(
            found(SOURCE, ROWS, WIRE_ROWS, RATCHET_LINES, 1),
            Vec::<String>::new()
        );
        let module = "| `net::relay::*` | RFC 1928 |\n";
        assert_eq!(
            found(SOURCE, ROWS, module, RATCHET_LINES, 1),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_new_item_without_a_basis_fails() {
        let source = format!("{SOURCE}const QUEUE: usize = 128;\n");
        let problems = found(&source, ROWS, WIRE_ROWS, RATCHET_LINES, 1);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("`net::relay::QUEUE` = 128 has no basis"));
    }

    #[test]
    fn a_changed_value_fails_in_the_table_and_the_ratchet() {
        let source = SOURCE
            .replace("= 64;", "= 32;")
            .replace("2 * BATCH", "3 * BATCH");
        let problems = found(&source, ROWS, WIRE_ROWS, RATCHET_LINES, 1);
        assert_eq!(problems.len(), 2, "{problems:#?}");
        assert!(problems[0].contains("`net::relay::BATCH` is 32"));
        assert!(problems[1].contains("the ratchet says 128"));
    }

    #[test]
    fn the_ratchet_only_shrinks() {
        let problems = found(SOURCE, ROWS, WIRE_ROWS, RATCHET_LINES, 0);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("above the ceiling of 0"))
        );
        let problems = found(SOURCE, ROWS, WIRE_ROWS, RATCHET_LINES, 2);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("lower `RATCHET_CEILING`"))
        );
    }

    #[test]
    fn a_basis_needs_its_class_and_citation() {
        let rows = ROWS.replace(
            "| C | Tokio budget (`coop/mod.rs:100`)",
            "| C | screened best",
        );
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(problems.iter().any(|p| p.contains("basis C cites no")));
        let rows = ROWS.replace("| B | mihomo", "| D | mihomo");
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("basis `D` is not A, B, C or O"))
        );
        let rows = ROWS.replace(
            "| C | Tokio budget (`coop/mod.rs:100`)",
            "| O | a round number",
        );
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(problems.iter().any(|p| p.contains("basis O cites no")));
        let rows = ROWS.replace(
            "| C | Tokio budget (`coop/mod.rs:100`)",
            "| A | the vendor manual",
        );
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(problems.iter().any(|p| p.contains("basis A cites no")));
        let rows = ROWS.replace(
            "| C | Tokio budget (`coop/mod.rs:100`)",
            "| A | the manual (`https://example.org/manual.html`, \"Limits\")",
        );
        assert!(found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1).is_empty());
        let rows = ROWS.replace(
            "mihomo `tunnel/tunnel.go:63`",
            "upstream `tunnel/tunnel.go:63`",
        );
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(problems.iter().any(|p| p.contains("basis B cites no")));
    }

    #[test]
    fn stale_and_double_registrations_fail() {
        let rows = format!("{ROWS}| `net::relay::GONE` | 1 | A | RFC 1 |\n");
        let problems = found(SOURCE, &rows, WIRE_ROWS, RATCHET_LINES, 1);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`net::relay::GONE` is not a numeric"))
        );
        let wire = format!("{WIRE_ROWS}| `net::relay::BATCH` | RFC 1 |\n");
        let problems = found(SOURCE, ROWS, &wire, RATCHET_LINES, 1);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`net::relay::BATCH` is registered twice"))
        );
        let wire = format!("{WIRE_ROWS}| `other::*` | RFC 1 |\n");
        let problems = found(SOURCE, ROWS, &wire, RATCHET_LINES, 1);
        assert!(problems.iter().any(|p| p.contains("`other::*` matches no")));
    }
}

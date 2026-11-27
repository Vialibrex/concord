//! Holds the entries of `.agents/reference-choices.md` under its three choice sections to the shape its
//! "Entry Shape" section sets: a kind, a citation in a pinned reference, an owner for a deviation and, for a
//! language-neutral deliberate difference, a measurement that names its platform and gives figures, or for a
//! behaviour difference the test that holds it. It checks form; whether a citation says what the entry claims is
//! the reviewer's to open.

use std::path::Path;

const FILE: &str = ".agents/reference-choices.md";
const REFERENCES: &str = "## References";
const DEVIATIONS: &str = "## Deviations To Resolve";
const MATCHING: &str = "## Matching The References";
const DELIBERATE: &str = "## Deliberate Differences";
const GATED: &[&str] = &[DEVIATIONS, MATCHING, DELIBERATE];
const KINDS: &[&str] = &["language-neutral", "runtime-bound"];
const DELIBERATE_COLUMNS: &[&str] = &["Area", "Kind", "Reference and reason", "Measurement"];
const BEHAVIOUR_ONLY: &str = "None (behaviour, no performance effect)";
const PLATFORMS: &[&str] = &["Linux", "macOS", "Windows", "Android"];
const NAMES: &[&str] = &[
    "mihomo",
    "sing-box",
    "sing",
    "sing-tun",
    "sing-mux",
    "sing-shadowsocks2",
    "sing-vmess",
    "sing-quic",
    "sing-anytls",
    "quic-go",
    "smux",
    "yamux",
    "wireguard-go",
    "mieru",
    "shadowsocks-rust",
    "naiveproxy",
    "cronet-go",
    "Go",
    "Rust",
    "Tokio",
    "Linux",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join(FILE)).map_err(|err| format!("{FILE}: {err}"))?;
    let problems = problems(&text);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

struct Entry {
    line: usize,
    text: String,
    cells: Option<Vec<String>>,
}

#[derive(Default)]
struct Section {
    header: Option<Vec<String>>,
    entries: Vec<Entry>,
}

fn problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut sections: Vec<(&'static str, Section)> = Vec::new();
    let mut references = String::new();
    let mut current: Option<&'static str> = None;
    let mut in_references = false;
    let mut open_bullet = false;
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        if line.starts_with("## ") {
            let heading = line.trim_end();
            in_references = heading == REFERENCES;
            current = GATED.iter().copied().find(|gated| *gated == heading);
            if let Some(name) = current {
                if sections.iter().any(|(seen, _)| *seen == name) {
                    problems.push(format!("{FILE}:{line_no}: `{name}` appears twice"));
                }
                sections.push((name, Section::default()));
            }
            open_bullet = false;
            continue;
        }
        if in_references {
            references.push_str(line);
            references.push('\n');
        }
        if current.is_none() {
            continue;
        }
        let Some((_, section)) = sections.last_mut() else {
            continue;
        };
        if let Some(problem) = take_line(section, line, line_no, &mut open_bullet) {
            problems.push(format!("{FILE}:{line_no}: {problem}"));
        }
    }
    for gated in GATED {
        if !sections.iter().any(|(name, _)| name == gated) {
            problems.push(format!("{FILE}: section `{gated}` is missing"));
        }
    }
    for name in NAMES {
        if !has_word(&references, name) {
            problems.push(format!(
                "{FILE}: `{name}` is not named under `{REFERENCES}`"
            ));
        }
    }
    for (name, section) in &sections {
        if *name == DELIBERATE
            && section
                .header
                .as_deref()
                .is_some_and(|h| h != DELIBERATE_COLUMNS)
        {
            problems.push(format!(
                "{FILE}: `{name}` columns are not {DELIBERATE_COLUMNS:?}"
            ));
        }
        for entry in &section.entries {
            problems.extend(
                entry_problems(name, section.header.as_deref(), entry)
                    .into_iter()
                    .map(|problem| format!("{FILE}:{} `{}`: {problem}", entry.line, title(entry))),
            );
        }
    }
    problems
}

fn take_line(
    section: &mut Section,
    line: &str,
    line_no: usize,
    open_bullet: &mut bool,
) -> Option<String> {
    if line.trim().is_empty() {
        *open_bullet = false;
        return None;
    }
    if line.starts_with('|') {
        *open_bullet = false;
        let cells = cells(line);
        let Some(header) = &section.header else {
            section.header = Some(cells);
            return None;
        };
        if cells
            .iter()
            .all(|cell| cell.chars().all(|c| c == '-' || c == ':'))
        {
            return None;
        }
        if cells.len() != header.len() {
            return Some(format!(
                "{} cells; the header has {}",
                cells.len(),
                header.len()
            ));
        }
        section.entries.push(Entry {
            line: line_no,
            text: line.to_string(),
            cells: Some(cells),
        });
        return None;
    }
    if line.starts_with("- ") {
        *open_bullet = true;
        section.entries.push(Entry {
            line: line_no,
            text: line.to_string(),
            cells: None,
        });
        return None;
    }
    if line.starts_with("  ") && *open_bullet {
        if let Some(entry) = section.entries.last_mut() {
            entry.text.push(' ');
            entry.text.push_str(line.trim());
        }
        return None;
    }
    if section.entries.is_empty() && section.header.is_none() {
        return None;
    }
    Some("text outside an entry; every entry is a table row or a `- ` bullet".to_string())
}

fn entry_problems(section: &str, header: Option<&[String]>, entry: &Entry) -> Vec<String> {
    let mut problems = Vec::new();
    let table = entry.cells.as_deref().zip(header);
    match (section, &table) {
        (MATCHING, Some(_)) => {
            problems.push("is a table row; this section takes bullets".to_string())
        }
        (DEVIATIONS | DELIBERATE, None) => {
            problems.push("is a bullet; this section takes table rows".to_string());
        }
        _ => {}
    }
    let kind = match table {
        Some((cells, header)) => column(header, cells, "Kind").filter(|kind| KINDS.contains(kind)),
        None => KINDS
            .iter()
            .copied()
            .find(|kind| entry.text.starts_with(&format!("- [{kind}] "))),
    };
    if kind.is_none() {
        problems.push(format!("states no kind; one of {KINDS:?}"));
    }
    if !has_citation(&entry.text) {
        problems.push("cites no `file:line`, `file::symbol` or `file` (`symbol`)".to_string());
    }
    if !names_reference(&entry.text) {
        problems.push("names no reference listed under References".to_string());
    }
    if let Some((cells, header)) = table {
        if section == DEVIATIONS && column(header, cells, "Owner").is_none_or(str::is_empty) {
            problems.push("names no owner".to_string());
        }
        if section == DELIBERATE && kind == Some("language-neutral") {
            if !column(header, cells, "Reference and reason").is_some_and(has_citation) {
                problems.push("a language-neutral difference argues from a citation".to_string());
            }
            let measurement = column(header, cells, "Measurement");
            if measurement == Some(BEHAVIOUR_ONLY) {
                if !column(header, cells, "Reference and reason").is_some_and(has_snake_name) {
                    problems
                        .push("a behaviour difference names the test that holds it".to_string());
                }
            } else if !measurement.is_some_and(is_measurement) {
                problems.push(
                    "a language-neutral difference states its measurement: the platform and the figures"
                        .to_string(),
                );
            }
        }
    }
    problems
}

fn title(entry: &Entry) -> String {
    if let Some(cells) = &entry.cells {
        return cells.first().cloned().unwrap_or_default();
    }
    let title = entry.text.split("**").nth(1).unwrap_or(&entry.text);
    title.chars().take(60).collect()
}

pub(crate) fn cells(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for c in line.trim().trim_start_matches('|').chars() {
        if c == '|' && !escaped {
            cells.push(cell.trim().to_string());
            cell.clear();
        } else {
            cell.push(c);
        }
        escaped = c == '\\';
    }
    if !cell.trim().is_empty() {
        cells.push(cell.trim().to_string());
    }
    cells
}

fn column<'a>(header: &[String], cells: &'a [String], name: &str) -> Option<&'a str> {
    let index = header.iter().position(|column| column == name)?;
    cells.get(index).map(String::as_str)
}

fn spans(text: &str) -> Vec<(&str, &str)> {
    let pieces: Vec<&str> = text.split('`').collect();
    pieces
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 2 == 1 && index + 1 < pieces.len())
        .map(|(index, span)| (*span, pieces[index + 1]))
        .collect()
}

pub(crate) fn has_citation(text: &str) -> bool {
    let spans = spans(text);
    spans.iter().enumerate().any(|(index, (span, after))| {
        is_citation(span)
            || (is_file(span)
                && *after == " ("
                && spans
                    .get(index + 1)
                    .is_some_and(|(next, _)| is_symbol(next)))
    })
}

fn is_citation(span: &str) -> bool {
    if let Some((file, symbol)) = span.split_once("::") {
        return is_file(file) && is_symbol(symbol);
    }
    span.rsplit_once(':').is_some_and(|(file, lines)| {
        is_file(file)
            && lines
                .split([',', '-'])
                .all(|number| !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()))
    })
}

fn is_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some((stem, extension)) = name.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && (1..=4).contains(&extension.len())
        && extension.starts_with(|c: char| c.is_ascii_alphabetic())
        && extension.chars().all(|c| c.is_ascii_alphanumeric())
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./".contains(c))
}

fn is_symbol(span: &str) -> bool {
    span.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && span
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn is_measurement(text: &str) -> bool {
    PLATFORMS.iter().any(|platform| has_word(text, platform))
        && text.char_indices().any(|(at, c)| {
            c.is_ascii_digit()
                && !text[..at]
                    .ends_with(|before: char| before.is_ascii_alphanumeric() || before == '_')
        })
}

fn has_snake_name(text: &str) -> bool {
    spans(text).iter().any(|(span, _)| {
        span.starts_with(|c: char| c.is_ascii_lowercase())
            && span.contains('_')
            && span
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    })
}

pub(crate) fn names_reference(text: &str) -> bool {
    NAMES.iter().any(|name| has_word(text, name))
}

fn has_word(text: &str, word: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(start, _)| {
        let end = start + word.len();
        !text[..start].ends_with(is_word) && !text[end..].starts_with(is_word)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVIATION: &str = "| A | language-neutral | x | mihomo `a/b.go:12` | transport owner |\n";
    const MATCH: &str = "- [runtime-bound] **M** sing-tun `stack.go::Run`\n  goes on.\n";
    const MEASURED: &str = "Linux arm64: Jain 1.000 against 0.564";
    const DIFFERENCE: &str = "| D | language-neutral | Go reads less (`conn.go:834-846`). | Linux arm64: Jain 1.000 against 0.564 |\n";

    fn document(deviation: &str, matching: &str, difference: &str) -> String {
        let names = NAMES.join(", ");
        format!(
            "# R\n\n## References\n\n- {names}\n\n## Deviations To Resolve\n\nIntro.\n\n\
             | Area | Kind | Concord | References | Owner |\n|---|---|---|---|---|\n{deviation}\n\
             ## To Verify\n\n| free | text |\n\n## Matching The References\n\nIntro.\n\n{matching}\n\
             ## Deliberate Differences\n\n| Area | Kind | Reference and reason | Measurement |\n\
             |---|---|---|---|\n{difference}\n## Data-Path Constants\n\nfree\n"
        )
    }

    fn found(deviation: &str, matching: &str, difference: &str) -> Vec<String> {
        problems(&document(deviation, matching, difference))
    }

    #[test]
    fn the_reference_choices_entries_keep_their_shape() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn complete_entries_pass_and_other_sections_are_free() {
        assert_eq!(found(DEVIATION, MATCH, DIFFERENCE), Vec::<String>::new());
    }

    #[test]
    fn a_missing_section_or_reference_name_is_reported() {
        let text = document(DEVIATION, MATCH, DIFFERENCE)
            .replace("## Matching The References", "## Matching");
        assert!(problems(&text).iter().any(|p| p.contains("is missing")));
        let text = document(DEVIATION, MATCH, DIFFERENCE).replace("Tokio", "tokio");
        assert!(
            problems(&text)
                .iter()
                .any(|p| p.contains("`Tokio` is not named"))
        );
    }

    #[test]
    fn an_entry_without_a_kind_is_reported() {
        let row = DEVIATION.replace("language-neutral", "neutral");
        assert!(
            found(&row, MATCH, DIFFERENCE)
                .iter()
                .any(|p| p.contains("states no kind"))
        );
        let bullet = MATCH.replace("[runtime-bound] ", "");
        assert!(
            found(DEVIATION, &bullet, DIFFERENCE)
                .iter()
                .any(|p| p.contains("states no kind"))
        );
    }

    #[test]
    fn a_citation_needs_a_line_or_a_symbol() {
        for span in [
            "a/b.go:12",
            "b.go:64-70",
            "h2_bundle.go:7358,7363",
            "copy.go::Copy",
            "Cargo.toml:50",
        ] {
            assert!(is_citation(span), "{span}");
        }
        for span in [
            "a/b.go",
            "transport/hysteria/congestion",
            ":7363",
            "v0.5.8:1",
            "b.go:x",
        ] {
            assert!(!is_citation(span), "{span}");
        }
        assert!(has_citation(
            "mihomo `session/session.go` (`writeConn`, `writeData`)"
        ));
        assert!(!has_citation("mihomo `session/session.go` and `writeConn`"));
        let bare = MATCH.replace("`stack.go::Run`", "`stack.go`");
        assert!(
            found(DEVIATION, &bare, DIFFERENCE)
                .iter()
                .any(|p| p.contains("cites no"))
        );
    }

    #[test]
    fn an_entry_naming_no_reference_is_reported() {
        let row = DEVIATION.replace("mihomo", "upstream");
        assert!(
            found(&row, MATCH, DIFFERENCE)
                .iter()
                .any(|p| p.contains("names no reference"))
        );
    }

    #[test]
    fn a_deviation_without_an_owner_is_reported() {
        let row = DEVIATION.replace("transport owner", "");
        assert!(
            found(&row, MATCH, DIFFERENCE)
                .iter()
                .any(|p| p.contains("names no owner"))
        );
    }

    #[test]
    fn a_language_neutral_difference_needs_a_measurement() {
        for unmeasured in [
            "not measured",
            "Linux arm64, better",
            "Jain 1.000 against 0.564",
        ] {
            let row = DIFFERENCE.replace(MEASURED, unmeasured);
            assert!(
                found(DEVIATION, MATCH, &row)
                    .iter()
                    .any(|p| p.contains("states its measurement")),
                "{unmeasured}"
            );
        }
        let row = DIFFERENCE.replace(MEASURED, "not measured");
        let runtime = row.replace("language-neutral", "runtime-bound");
        assert_eq!(found(DEVIATION, MATCH, &runtime), Vec::<String>::new());
    }

    #[test]
    fn a_behaviour_difference_names_its_test_instead_of_a_run() {
        let row = DIFFERENCE.replace(MEASURED, BEHAVIOUR_ONLY);
        assert!(
            found(DEVIATION, MATCH, &row)
                .iter()
                .any(|p| p.contains("names the test that holds it"))
        );
        let tested = row.replace("). |", "); `reads_one_record` holds it. |");
        assert_eq!(found(DEVIATION, MATCH, &tested), Vec::<String>::new());
    }

    #[test]
    fn stray_text_and_ragged_rows_are_reported() {
        let stray = format!("{MATCH}Unchecked paragraph.\n");
        assert!(
            found(DEVIATION, &stray, DIFFERENCE)
                .iter()
                .any(|p| p.contains("text outside an entry"))
        );
        let ragged = DIFFERENCE.replace(" | Linux", " | extra | Linux");
        assert!(
            found(DEVIATION, MATCH, &ragged)
                .iter()
                .any(|p| p.contains("5 cells; the header has 4"))
        );
        let bullet = "- [runtime-bound] Go `a.go:1`\n";
        assert!(
            found(DEVIATION, MATCH, &format!("{DIFFERENCE}{bullet}"))
                .iter()
                .any(|p| p.contains("this section takes table rows"))
        );
    }
}

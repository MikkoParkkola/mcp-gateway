// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source pin for the config-timing rows: on every route that runs the
//! relay witness hook, the hook runs before the first generation read in
//! that route's handler. A hook placed after a read would let a re-read of
//! the live config before it go unseen by every config-timing row.

/// The hook call: a site is any code line calling it, however it is written
/// or commented. Matched in source whose comments and literals are blanked
/// (`test_source_text::sanitize`), so neither hides code nor fakes a call.
const HOOK: &str = "relay_witness_hook::run(";

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The byte offset of the line opening the function enclosing `line`: the
/// nearest earlier code line naming `fn ` at a shallower indent.
fn enclosing_fn(lines: &[&str], line: usize) -> usize {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let depth = indent(lines[line]);
    let at = (0..line)
        .rev()
        .find(|&i| {
            let l = lines[i].trim_start();
            !l.starts_with("//") && indent(lines[i]) < depth && l.contains("fn ")
        })
        .unwrap_or_else(|| panic!("no function encloses hook line {}", line + 1));
    lines[..at].iter().map(|l| l.len() + 1).sum()
}

/// The body of the function opening at `start` in `source`, braces matched.
fn body(source: &str, start: usize) -> &str {
    let open = start + source[start..].find('{').expect("a body");
    let mut depth = 0usize;
    for (i, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced body at byte {start}");
}

/// A code line that reads the live config or a generation itself.
fn reads_directly(line: &str) -> bool {
    ["generation", "live_config", "check_relay", "relay_block_message"]
        .iter()
        .any(|read| line.contains(read))
}

/// The names of production functions whose body reads a generation itself,
/// so a call to one is a read wherever it is written. Keyed by name alone: a
/// name any such function has counts for every function of that name.
/// ponytail: one level deep; following calls further by name marks most of
/// the crate (names collide), so a helper reaching the read through another
/// helper, or through a method call, is not seen here.
fn readers() -> &'static std::collections::HashSet<String> {
    static READERS: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    READERS.get_or_init(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&root.join("src"), &mut files);
        let mut names = std::collections::HashSet::new();
        for path in files {
            let shown = path.display().to_string();
            if shown.contains("_tests") || shown.contains("/tests/") || shown.contains("test_support") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
            let code = crate::test_source_text::sanitize(&source);
            for (at, _) in code.match_indices("fn ") {
                // `fn ` as a keyword, not the tail of an identifier.
                if code[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                let rest = &code[at + 3..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // A declaration with no body (`;` before `{`) reads nothing.
                let open = rest.find('{');
                let has_body = open.is_some_and(|o| rest.find(';').is_none_or(|s| o < s));
                if name.is_empty() || !has_body {
                    continue;
                }
                if body(&code, at).lines().any(reads_directly) {
                    names.insert(name);
                }
            }
        }
        names
    })
}

/// The function names a line calls as free or path calls (`f(`, `a::f(`);
/// method calls (`.f(`) are left out, their names collide too widely.
fn called(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !word(bytes[i]) || (i > 0 && word(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && word(bytes[i]) {
            i += 1;
        }
        let after = line[i..].trim_start();
        let method = start > 0 && bytes[start - 1] == b'.';
        if after.starts_with('(') && !method {
            out.push(&line[start..i]);
        }
    }
    out
}

/// A code line that reads a generation itself or calls a function that does.
fn reads_generation(line: &str) -> bool {
    reads_directly(line) || called(line).iter().any(|f| readers().contains(*f))
}

/// Check every hook site in `source` (named `name` in messages): each runs
/// in a handler that calls the hook once, before its first generation read.
/// The number of sites found, or the first misplaced one.
fn check_sites(name: &str, source: &str) -> Result<usize, String> {
    let code = crate::test_source_text::sanitize(source);
    let lines: Vec<&str> = code.lines().collect();
    let mut sites = 0;
    for hook in (0..lines.len()).filter(|&i| lines[i].contains(HOOK)) {
        sites += 1;
        let start = enclosing_fn(&lines, hook);
        let signature = lines[code[..start].lines().count()].trim();
        let where_ = format!("{name}: {signature}");
        let body: Vec<&str> = body(&code, start)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        let hooks: Vec<usize> = (0..body.len())
            .filter(|&i| body[i].contains(HOOK))
            .collect();
        if hooks.len() != 1 {
            return Err(format!("{where_}: the handler runs the witness hook once"));
        }
        let read = body
            .iter()
            .position(|line| reads_generation(line))
            .ok_or_else(|| format!("{where_}: no generation read found"))?;
        if read <= hooks[0] {
            return Err(format!(
                "{where_}: the witness hook must run before the first generation \
                 read on the route, found after `{}`",
                body[read].trim()
            ));
        }
    }
    Ok(sites)
}

#[test]
fn the_witness_hook_runs_before_the_first_generation_read_on_every_route() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut sites = 0;
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        sites +=
            check_sites(&path.display().to_string(), &source).unwrap_or_else(|e| panic!("{e}"));
    }
    // The routes the config-timing rows drive; fewer means the scan missed some.
    assert!(sites >= 5, "the scan found {sites} hook sites");
}

/// A generation read after a string literal holding `//`, before the hook,
/// is still a read: the literal is blanked, not taken as a comment.
#[test]
fn a_read_after_a_slashed_literal_is_still_seen() {
    // A later read follows the hook, so a scan that lost the first read
    // would pass the handler.
    let source = "fn route() {\n    let url = \"http://x\"; let generation = url;\n    \
                  crate::security::firewall::relay_witness_hook::run();\n    \
                  let _ = generation;\n}\n";
    let found = check_sites("row", source);
    assert!(
        found.as_ref().is_err_and(|e| e.contains("must run before")),
        "a read after a slashed literal went unseen: {found:?}"
    );
}

/// Taking the request's recorded refusal reads the audit record, not a
/// generation, so it may come before the hook.
#[test]
fn taking_the_recorded_refusal_before_the_hook_is_not_a_read() {
    let source = "fn route() {\n    let _ = crate::gateway::meta_mcp::invoke::audit::take_refusal();\n    \
                  crate::security::firewall::relay_witness_hook::run();\n    \
                  let _ = firewall_refusal(generation);\n}\n";
    assert_eq!(check_sites("row", source), Ok(1));
}

/// A refusal helper that reads the generation still counts before the hook.
#[test]
fn a_generation_reading_refusal_before_the_hook_is_still_a_read() {
    let source = "fn route() {\n    let _ = firewall_refusal(policy);\n    \
                  crate::security::firewall::relay_witness_hook::run();\n    \
                  let _ = relay_refusal(policy);\n}\n";
    let found = check_sites("row", source);
    assert!(
        found.as_ref().is_err_and(|e| e.contains("found after `let _ = firewall_refusal(policy);`")),
        "a refusal helper before the hook went unseen: {found:?}"
    );
}

/// A call to a function whose body reads the generation is a read, however
/// the function is named: here the withheld verdict, which authorizes against
/// the request's generation.
#[test]
fn a_call_to_a_function_reading_the_generation_is_a_read() {
    let source = "fn route() {\n    let _ = direct_preflight::withheld_verdict(state, auth);\n    \
                  crate::security::firewall::relay_witness_hook::run();\n    \
                  let _ = generation;\n}\n";
    let found = check_sites("row", source);
    assert!(
        found.as_ref().is_err_and(|e| e.contains("withheld_verdict")),
        "a call into a generation read before the hook went unseen: {found:?}"
    );
}

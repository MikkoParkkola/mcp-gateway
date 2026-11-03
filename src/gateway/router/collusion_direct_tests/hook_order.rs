// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source pin for the config-timing rows: on every route that runs the
//! relay witness hook, the hook runs before the first generation read in
//! that route's handler. A hook placed after a read would let a re-read of
//! the live config before it go unseen by every config-timing row.

/// The hook call as a statement; the site list is every line ending in it.
const HOOK: &str = "relay_witness_hook::run();";

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

/// A code line that reads the live config or a generation, or calls a
/// witness helper that reads one.
fn reads_generation(line: &str) -> bool {
    [
        "generation",
        "live_config",
        "_refusal(",
        "check_relay",
        "relay_block_message",
    ]
    .iter()
    .any(|read| line.contains(read))
}

#[test]
fn the_witness_hook_runs_before_the_first_generation_read_on_every_route() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut sites = 0;
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        let lines: Vec<&str> = source.lines().collect();
        for hook in (0..lines.len()).filter(|&i| lines[i].trim_end().ends_with(HOOK)) {
            sites += 1;
            let start = enclosing_fn(&lines, hook);
            let signature = lines[source[..start].lines().count()].trim();
            let where_ = format!("{}: {signature}", path.display());
            let code: Vec<&str> = body(&source, start)
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect();
            let hooks: Vec<usize> = (0..code.len())
                .filter(|&i| code[i].trim_end().ends_with(HOOK))
                .collect();
            assert_eq!(
                hooks.len(),
                1,
                "{where_}: the handler runs the witness hook once"
            );
            let read = code
                .iter()
                .position(|line| reads_generation(line))
                .unwrap_or_else(|| panic!("{where_}: no generation read found"));
            assert!(
                hooks[0] < read,
                "{where_}: the witness hook must run before the first generation \
                 read on the route, found after `{}`",
                code[read].trim()
            );
        }
    }
    // The routes the config-timing rows drive; fewer means the scan missed some.
    assert!(sites >= 5, "the scan found {sites} hook sites");
}

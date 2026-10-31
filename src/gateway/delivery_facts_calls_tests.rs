// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G3: the production calls of what a delivery learns about its sends, by
//! file. A settlement that stops reading `unsent`, a pre-send exit that stops
//! recording its refusal, or a send outside the counted one changes a count
//! here, and the row changes with it in review.

use std::collections::BTreeMap;
use std::path::Path;

/// The names pinned. `presend` is `before_send` as `request_attempted`
/// imports it; `before_send` itself is pinned too, with no reviewed call, so
/// a wrap that calls it by its own name elsewhere fails here.
const NAMES: [&str; 8] = [
    "counted_send",
    "presend",
    "before_send",
    "refused_before_send",
    "unsent",
    "nothing_sent",
    "refused_before_send_seen",
    "after_a_send",
];

/// (name, file) -> calls, as reviewed.
const REVIEWED: [(&str, &str, usize); 14] = [
    ("after_a_send", "src/capability/executor/mcp_rounds.rs", 1),
    ("after_a_send", "src/transport/http/transport_impl.rs", 1),
    ("counted_send", "src/backend/ops.rs", 1),
    ("nothing_sent", "src/gateway/delivery_facts.rs", 1),
    (
        "nothing_sent",
        "src/gateway/meta_mcp/invoke/legacy_bridge.rs",
        1,
    ),
    ("presend", "src/backend/ops.rs", 7),
    ("refused_before_send", "src/backend/ops.rs", 1),
    (
        "refused_before_send_seen",
        "src/gateway/delivery_facts.rs",
        1,
    ),
    (
        "refused_before_send_seen",
        "src/gateway/meta_mcp/invoke/post_dispatch.rs",
        1,
    ),
    (
        "refused_before_send_seen",
        "src/gateway/router/backend_handlers/direct_dispatch.rs",
        1,
    ),
    ("unsent", "src/gateway/meta_mcp/invoke/bridge_settle.rs", 1),
    ("unsent", "src/gateway/meta_mcp/invoke/post_dispatch.rs", 1),
    ("unsent", "src/gateway/router/backend_handlers.rs", 1),
    (
        "unsent",
        "src/gateway/router/backend_handlers/direct_dispatch.rs",
        1,
    ),
];

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Calls of `name` in `source`: `name(` not preceded by a word character
/// and not a definition (`fn name(`), outside comment lines.
fn calls(source: &str, name: &str) -> usize {
    let needle = format!("{name}(");
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            line.match_indices(&needle)
                .filter(|(at, _)| {
                    let before = &line[..*at];
                    !before.ends_with(is_word) && !before.trim_end().ends_with("fn")
                })
                .count()
        })
        .sum()
}

fn production_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a readable source directory") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" {
                production_files(&path, out);
            }
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
            && !name.ends_with("_tests.rs")
            && !name.contains("test_support")
        {
            out.push(path);
        }
    }
}

#[test]
fn the_send_facts_are_called_exactly_where_reviewed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    production_files(&root.join("src"), &mut files);
    let mut found = BTreeMap::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("a readable source file");
        // Joined with `/` on every OS, so the keys read the same on Windows
        // as the reviewed table does.
        let rel = file
            .strip_prefix(root)
            .expect("under the crate")
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        for name in NAMES {
            let n = calls(&source, name);
            if n > 0 {
                found.insert((name, rel.clone()), n);
            }
        }
    }
    let reviewed: BTreeMap<(&str, String), usize> = REVIEWED
        .iter()
        .map(|(name, file, n)| ((*name, (*file).to_owned()), *n))
        .collect();
    assert_eq!(found, reviewed, "the send facts' production calls changed");
}

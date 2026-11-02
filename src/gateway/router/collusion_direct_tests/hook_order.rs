// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source pin for the config-timing rows: on every route that runs the
//! relay witness hook, the hook runs before the first generation read in
//! that route's handler. A hook placed after a read would let a re-read of
//! the live config before it go unseen by every config-timing row.

/// Each hook site: the file and the handler's signature.
const SITES: [(&str, &str); 5] = [
    (
        "src/gateway/router/backend_handlers.rs",
        "async fn guard_tool_call(",
    ),
    (
        "src/gateway/router/backend_handlers/direct_dispatch.rs",
        "async fn guard_and_sanitize(",
    ),
    ("src/gateway/meta_mcp/invoke/relay.rs", "fn refuse_relay("),
    (
        "src/gateway/meta_mcp/invoke/relay.rs",
        "fn refuse_relaying_round(",
    ),
    (
        "src/gateway/meta_mcp/invoke/relay_catalogue.rs",
        "async fn forward_catalogue(",
    ),
];

const HOOK: &str = "relay_witness_hook::run()";

/// The body of the function `signature` opens in `source`, braces matched.
fn body<'a>(source: &'a str, signature: &str) -> &'a str {
    assert_eq!(source.matches(signature).count(), 1, "{signature}");
    let start = source.find(signature).expect("counted above");
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
    panic!("{signature}: unbalanced body");
}

/// A code line that reads a generation, or calls the witness that reads one.
fn reads_generation(line: &str) -> bool {
    line.contains("generation") || line.contains("_refusal(")
}

#[test]
fn the_witness_hook_runs_before_the_first_generation_read_on_every_route() {
    for (path, signature) in SITES {
        let source = std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let code: Vec<&str> = body(&source, signature)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        let hooks: Vec<usize> = code
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(HOOK))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hooks.len(),
            1,
            "{path} {signature}: the handler runs the witness hook once"
        );
        let read = code
            .iter()
            .position(|line| reads_generation(line))
            .unwrap_or_else(|| panic!("{path} {signature}: no generation read found"));
        assert!(
            hooks[0] < read,
            "{path} {signature}: the witness hook must run before the first generation \
             read on the route, found after `{}`",
            code[read].trim()
        );
    }
}

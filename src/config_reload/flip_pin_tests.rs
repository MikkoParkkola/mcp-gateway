// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The multi-user flip check exists once and is called only where listed: a
//! key list that changes whether the gateway is multi-user is judged by one
//! predicate on every path, never a copy that could drift.

use std::path::Path;

use crate::test_source_files::rust_files;

/// Where production code calls the flip check, per file. The key routes no
/// longer call it themselves: they ask the first-key question, which does.
const CALLERS: &[(&str, usize)] = &[
    ("src/config_reload/first_key.rs", 1),
    ("src/config_reload/generation.rs", 1),
];

fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            if relative.split('/').any(|part| {
                part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
            }) {
                return None;
            }
            let text = std::fs::read_to_string(&path).ok()?;
            let code =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
            Some((relative, code))
        })
        .collect()
}

#[test]
fn the_flip_check_is_called_only_where_listed() {
    let mut found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter_map(|(file, code)| {
            let count = code.matches("refuse_multi_user_flip(").count()
                - code.matches("fn refuse_multi_user_flip(").count();
            (count > 0).then_some((file, count))
        })
        .collect();
    found.sort();
    let want: Vec<(String, usize)> = CALLERS
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(found, want, "a new caller of the flip check: list it here");
}

/// Production files as written, with only test modules taken out: string
/// literals kept, for pins on a wire code.
fn production_texts() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    production_sources()
        .into_iter()
        .filter_map(|(file, _)| {
            let text = std::fs::read_to_string(root.join(&file)).ok()?;
            Some((file, crate::test_source_text::production_text(&text)))
        })
        .collect()
}

/// The files of `sources` whose text matches `count` more than zero times,
/// with that count.
fn files_with(
    sources: Vec<(String, String)>,
    count: impl Fn(&str) -> usize,
) -> Vec<(String, usize)> {
    let mut found: Vec<(String, usize)> = sources
        .into_iter()
        .filter_map(|(file, code)| {
            let n = count(&code);
            (n > 0).then_some((file, n))
        })
        .collect();
    found.sort();
    found
}

/// R6: the waiting keys of a restart-pending answer are built only inside
/// the shared decision's module, so every such answer names what it found.
#[test]
fn r6_waiting_keys_are_built_only_by_the_decision() {
    let found = files_with(production_sources(), |code| {
        code.matches("WaitingKeys(").count() + code.matches("WaitingKeys::new(").count()
            - code.matches("struct WaitingKeys(").count()
    });
    let files: Vec<&str> = found.iter().map(|(file, _)| file.as_str()).collect();
    assert_eq!(files, ["src/config_reload/first_key.rs"], "{found:?}");
}

/// R6: the shared decision's callers, by file: the writer's check before a
/// write, the revoke's compute, and the create's guard.
#[test]
fn r6_the_decision_is_asked_only_where_listed() {
    let found = files_with(production_sources(), |code| {
        code.matches("restart_pending_decision(").count()
            - code.matches("fn restart_pending_decision(").count()
            + code.matches("restart_pending_guard(").count()
            - code.matches("fn restart_pending_guard(").count()
    });
    assert_eq!(
        found,
        [
            ("src/config_reload/replace_validate.rs".to_owned(), 1),
            ("src/gateway/ui/keys_create.rs".to_owned(), 1),
            ("src/gateway/ui/keys_revoke.rs".to_owned(), 1),
        ],
        "a new caller of the shared decision: list it here"
    );
}

/// R6: the wire code `restart_pending` is written by the one 409 builder.
#[test]
fn r6_the_restart_pending_code_is_written_once() {
    let found = files_with(production_texts(), |text| {
        text.matches("\"restart_pending\"").count()
    });
    assert_eq!(
        found,
        [("src/gateway/ui/errors.rs".to_owned(), 1)],
        "{found:?}"
    );
}

/// R9: the status rule's sentence travels only inside the question: no
/// production file but the question's own reads `Waiting::Yes`'s `status`,
/// so it reaches no refusal, ledger or route text.
#[test]
fn r9_the_status_rule_sentence_stays_in_the_question() {
    let binds_status = |code: &str| {
        code.match_indices("Yes {")
            .filter(|(at, _)| {
                let rest = &code[*at..];
                let end = rest.find('}').unwrap_or(rest.len());
                rest[..end]
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|word| word == "status")
            })
            .count()
    };
    let found = files_with(production_sources(), binds_status);
    let files: Vec<&str> = found.iter().map(|(file, _)| file.as_str()).collect();
    assert_eq!(files, ["src/config_reload/first_key.rs"], "{found:?}");
}

#[test]
fn the_flip_comparison_exists_once() {
    let copies: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, code)| code.contains("implies_multi_user(oidc) !="))
        .map(|(file, _)| file)
        .collect();
    assert_eq!(copies, ["src/config_reload/generation.rs"], "{copies:?}");
}

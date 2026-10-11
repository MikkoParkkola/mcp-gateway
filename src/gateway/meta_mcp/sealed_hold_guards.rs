// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 stage 4 structural guards (test plan t3, Part A).
//!
//! A1: a retained copy of an answer (a stored task, a cached replay) may reach
//! the wire only through a function that takes it as `Held<…>` or calls
//! `.deliver(`, which moves its holds into the reader's scope or frame. Every
//! production projection of such a payload is found by source shape and must
//! sit in such a function, on [`DECISION_ONLY`] with the reason it never
//! reaches the wire, or on [`OWNED_ELSEWHERE`] with who owns its holds. Each
//! entry excuses one projection shape in one fn, nothing else in it.
use std::path::{Path, PathBuf};

/// Shapes that project a retained payload: a task's wire form or stored
/// result, a cached replay, and the task envelope builder itself.
const PROJECTIONS: &[&str] = &[
    r"\.wire\(\)",
    r"\.result\(\)",
    r"GuardOutcome::CachedResult\(",
    r"SyncAdmission::Replay\(",
    r"\bfn task_envelope\(",
];

/// `(file under src/gateway, enclosing fn, the one projection shape excused,
/// why)`: projections that only decide and never reach the wire. Only the
/// named shape is excused: another projection added to the same fn fails A1.
const DECISION_ONLY: &[(&str, &str, &str, &str)] = &[
    (
        "task_service/record.rs",
        "backend_result",
        r"\.result\(\)",
        "staged into the relay receipt (task_replay.rs), never serialized to a client",
    ),
    (
        "task_service/store_targets.rs",
        "settle_bounded_blocking",
        r"\.result\(\)",
        "re-filters the offered holds against the committed result (MIK-8176 M1); the result is only matched, never serialized",
    ),
];

/// `(file under src/gateway, enclosing fn, the one projection shape excused,
/// why)`: projections that DO reach the wire, with their holds owned
/// elsewhere. Only the named shape is excused.
const OWNED_ELSEWHERE: &[(&str, &str, &str, &str)] = &[
    (
        "router/backend_handlers/direct_dispatch.rs",
        "admit",
        r"GuardOutcome::CachedResult\(",
        "a CachedResult carries no question the cache was handed directly (final-only store; nested-question output is routed to execution admission). An envelope can reach a cached answer only after playbook interpolation hands it to a step backend, which can also return it uncached, so cache ownership would not close it; MIK-8323 closes it at interpolation (a step argument never carries a sealed envelope). Pinned by the_idempotency_cache_keeps_no_question_it_was_handed_directly, a_playbook_handing_a_request_state_to_a_step_is_refused and a_cached_answer_needs_its_own_arguments_to_replay",
    ),
    (
        "meta_mcp/invoke/pre_dispatch.rs",
        "admit_idempotency_key",
        r"GuardOutcome::CachedResult\(",
        "same as direct_dispatch.rs::admit: the cache keeps no question it is handed directly; the interpolation path is MIK-8323",
    ),
    (
        "meta_mcp/admission.rs",
        "admit_operation",
        r"SyncAdmission::Replay\(",
        "builds the SyncAdmission::Replay right after `ExecutionAdmission::admit` adopted the stored delivery's holds into this request's scope (MIK-8176); pinned by rows C1 and C1-stdio",
    ),
    (
        "router/handlers/dispatch_tools_call.rs",
        "tools_call",
        r"SyncAdmission::Replay\(",
        "a SyncAdmission::Replay whose stored delivery's holds `ExecutionAdmission::admit` already adopted into this request's scope (MIK-8176); pinned by row C1",
    ),
    (
        "server/stdio_dispatch.rs",
        "dispatch_tools_call",
        r"SyncAdmission::Replay\(",
        "a SyncAdmission::Replay whose stored delivery's holds `ExecutionAdmission::admit` already adopted into this request's scope (MIK-8176); pinned by row C1-stdio",
    ),
];

/// Which `.rs` files [`sources`] collects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Files {
    /// Test and fixture files excluded.
    Production,
    /// Every file, tests included.
    All,
}

/// The `.rs` files under `sub` (relative to the crate root).
fn sources(sub: &str, files: Files) -> Vec<PathBuf> {
    fn walk(dir: &Path, files: Files, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a source directory is readable") {
            let path = entry.expect("a directory entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // A test file names `test`/`tests` as a whole word (`tests`,
            // `x_tests.rs`, `test_x.rs`, `x_test_support.rs`); a production
            // module that merely contains the letters (`attestation.rs`) is
            // still scanned.
            let test_file = name
                .split(['_', '.'])
                .any(|word| word == "test" || word == "tests")
                || name.contains("fixture");
            if files == Files::Production && test_file {
                continue;
            }
            if path.is_dir() {
                walk(&path, files, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(sub);
    let mut out = Vec::new();
    walk(&root, files, &mut out);
    out
}

/// The function whose body holds line `at`: its name and its text, from its
/// `fn` line to the next item-level `fn` (or the end of the file).
fn enclosing_fn(lines: &[&str], at: usize) -> Option<(String, String)> {
    let header = regex::Regex::new(r"\bfn\s+(\w+)").expect("a valid pattern");
    let start = (0..=at).rev().find(|&i| header.is_match(lines[i]))?;
    let name = header.captures(lines[start])?[1].to_owned();
    let indent = lines[start].len() - lines[start].trim_start().len();
    let end = (start + 1..lines.len())
        .find(|&i| {
            let line = lines[i];
            header.is_match(line) && line.len() - line.trim_start().len() <= indent
        })
        .unwrap_or(lines.len());
    Some((name, lines[start..end].join("\n")))
}

/// A1, red on base: every retained-payload projection is guarded or listed.
#[test]
fn every_retained_output_projection_delivers_its_holds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway");
    let shapes: Vec<regex::Regex> = PROJECTIONS
        .iter()
        .map(|p| regex::Regex::new(p).expect("a valid pattern"))
        .collect();
    // A renamed import of a guarded item would hide a projection from the
    // shapes above: rejected outright, never added as another pattern.
    let alias = regex::Regex::new(r"\buse\b.*\b(wire|result|CachedResult|task_envelope)\b.*\bas\b")
        .expect("a valid pattern");
    let mut unguarded = Vec::new();
    for file in sources("src/gateway", Files::Production) {
        let text = std::fs::read_to_string(&file).expect("a readable source file");
        let rel = file.strip_prefix(&root).expect("under src/gateway");
        let rel = rel.to_string_lossy().replace('\\', "/");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if alias.is_match(line) {
                unguarded.push(format!("{rel}:{}: renamed import of a guarded item", i + 1));
                continue;
            }
            if !shapes.iter().any(|s| s.is_match(line)) {
                continue;
            }
            let Some((name, body)) = enclosing_fn(&lines, i) else {
                unguarded.push(format!("{rel}:{}: projection outside any fn", i + 1));
                continue;
            };
            let guarded = body.contains("Held<") || body.contains(".deliver(");
            // Excused only for the shape the entry names, on this very line.
            let listed = DECISION_ONLY
                .iter()
                .chain(OWNED_ELSEWHERE)
                .any(|(f, n, shape, _)| {
                    *f == rel
                        && *n == name
                        && regex::Regex::new(shape)
                            .expect("a valid pattern")
                            .is_match(line)
                });
            if !guarded && !listed {
                unguarded.push(format!("{rel}:{}: {name}", i + 1));
            }
        }
    }
    assert!(
        unguarded.is_empty(),
        "retained output reaches the wire without delivering its holds:\n{}",
        unguarded.join("\n")
    );
}

/// What `Held` may expose: its constructor and `deliver` (the only way to the
/// payload). Exactly the methods that exist: a name listed ahead of its
/// method would let a later method of that name hand the payload out.
/// Anything else in `held.rs` fails A2.
const HELD_SURFACE: &[&str] = &["new", "deliver"];

/// A2 (N2, lead pin): `Held` hands its payload out only through `deliver`.
/// Its fields are private to `held.rs`, so the compiler confines every access
/// to that file; this reads the file and pins what it exposes.
#[test]
fn held_exposes_nothing_but_deliver_and_decisions() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/meta_mcp/sealed_hold/held.rs");
    let text = std::fs::read_to_string(path).expect("held.rs is readable");
    let code: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let field = regex::Regex::new(r"^\s+pub(\(\w+\))?\s+\w+\s*:").expect("a valid pattern");
    let method = regex::Regex::new(r"\bfn\s+(\w+)").expect("a valid pattern");
    let trait_impl = regex::Regex::new(r"\bimpl\b.*\bfor\s+Held\b").expect("a valid pattern");
    let mut exposed = Vec::new();
    for line in &code {
        if field.is_match(line) {
            exposed.push(format!("public field: {}", line.trim()));
        }
        if trait_impl.is_match(line) {
            exposed.push(format!("trait impl: {}", line.trim()));
        }
        if let Some(name) = method.captures(line).map(|c| c[1].to_owned())
            && !HELD_SURFACE.contains(&name.as_str())
        {
            exposed.push(format!("method outside the surface: {name}"));
        }
    }
    assert!(exposed.is_empty(), "Held exposes its payload: {exposed:#?}");
}

/// A2's positive control: the allowed path compiles, moves the holds onto the
/// frame, and a frame that hands them off keeps the slot after the retained
/// copy is gone.
#[tokio::test]
async fn deliver_moves_the_holds_onto_a_frame() {
    use super::{CarriedHolds, Held, HoldSink, carried, hand_off, register, scoped};
    use crate::protocol::continuation::{ContinuationState, now_unix_secs};
    let continuation = std::sync::Arc::new(ContinuationState::new());
    let now = now_unix_secs();
    let key = continuation
        .begin_exchange(
            "alpha".into(),
            None,
            "fp".into(),
            &crate::protocol::continuation::QuotaKey::for_test("fp"),
            "digest".into(),
            now,
        )
        .await
        .expect("a fresh state has a slot")
        .hold_key;
    let answer = serde_json::json!({ "requestState": "env-retained" });
    let holds = scoped(async {
        register(&continuation, &key, "env-retained");
        carried(&answer)
    })
    .await;
    let mut frame = CarriedHolds::none();
    let value = Held::new(answer.clone(), holds).deliver(HoldSink::Frame(&mut frame));
    assert_eq!(value, answer);
    assert_eq!(frame.0.len(), 1, "the hold moved onto the frame");
    hand_off(&frame);
    drop(frame);
    assert_eq!(
        continuation.in_flight().len(now_unix_secs()).await,
        1,
        "a handed-off frame keeps the slot"
    );
}

/// The production call sites of `name` under `src/`, as `file` paths
/// relative to `src/`, deduplicated and sorted.
fn callers_of(name: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let call = regex::Regex::new(&format!(r"sealed_hold::{name}\(")).expect("a valid pattern");
    let mut found: Vec<String> = sources("src", Files::Production)
        .into_iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .lines()
                .any(|l| !l.trim_start().starts_with("//") && call.is_match(l))
        })
        .map(|f| {
            f.strip_prefix(&root)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// The mint sites: a new one fails here, so it cannot slip in without its
/// matrix rows.
const MINT_SITES: &[&str] = &[
    "gateway/meta_mcp/confirmation.rs",
    "gateway/meta_mcp/invoke/continuation.rs",
    "gateway/meta_mcp/task_confirmation.rs",
];

/// Every boundary that opens a hold scope (one cell per route or
/// transport), and the matrix test that covers it.
const BOUNDARY_CELLS: &[(&str, &str)] = &[
    (
        "gateway/router/backend_handlers/direct_audit.rs",
        "a_question_withheld_after_finalization_gives_its_slot_back",
    ),
    ("gateway/router/handlers.rs", "slot_release_matrix"),
    (
        "gateway/server/stdio_loop.rs",
        "a_delivered_stdio_question_keeps_its_slot",
    ),
    (
        "gateway/task_service/execution.rs",
        "slot_release_matrix_tasks",
    ),
];

/// A3 (MATRIX.1, t3): the mint sites are exactly the pinned set, every
/// scope-opening boundary is listed, and each listed cell exists as a test.
#[test]
fn every_mint_site_and_scope_boundary_has_its_matrix_cell() {
    assert_eq!(callers_of("register"), MINT_SITES, "the mint sites changed");
    let boundaries = callers_of("scoped");
    let listed: Vec<&str> = BOUNDARY_CELLS.iter().map(|(file, _)| *file).collect();
    assert_eq!(boundaries, listed, "a scope boundary has no matrix cell");
    let text: String = sources("src/gateway", Files::All)
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap_or_default())
        .collect();
    let missing: Vec<&str> = BOUNDARY_CELLS
        .iter()
        .map(|(_, cell)| *cell)
        .filter(|cell| !text.contains(&format!("fn {cell}(")))
        .collect();
    assert!(missing.is_empty(), "matrix cells missing: {missing:?}");
}

/// H2 (MIK-8176 D9): the release points that predate scoped holds are gone
/// from production code. A slot is released only by its scope (or its
/// retained owner) dropping a hold that was never handed off; a second,
/// explicit release path would race it. The names are assembled so this
/// file does not match itself.
#[test]
fn the_pre_scope_release_points_are_gone() {
    let retired = [
        ["release_unsent", "_hold"].concat(),
        ["release_unless", "_carried"].concat(),
        ["release_direct", "_hold"].concat(),
        ["sealed", "_question"].concat(),
        ["unsent", "_hold"].concat(),
    ];
    let word = |name: &str| regex::Regex::new(&format!(r"\b{name}\b")).expect("a valid pattern");
    let patterns: Vec<_> = retired.iter().map(|name| word(name)).collect();
    let mut found = Vec::new();
    for file in sources("src", Files::Production) {
        let text = std::fs::read_to_string(&file).expect("a source file is readable");
        for (name, pattern) in retired.iter().zip(&patterns) {
            if pattern.is_match(&text) {
                found.push(format!("{}: {name}", file.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "retired release points are back: {found:?}"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 C1c: a receipt is publicly signed only in the request that minted
//! it, once. These rows pin the seal points, the one mint site and the writers
//! of `public_signature`, matched by file plus enclosing function name.
//! C1d extends the seal set to the task worker's native settle paths.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every non-test Rust file under `src/`, walked as in `tests/mik_6704_acs.rs`.
fn src_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir)
        .expect("source tree readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            src_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name.contains("test") {
                continue;
            }
            if path.components().any(|c| c.as_os_str() == "tests") {
                continue;
            }
            out.push(path);
        }
    }
}

/// The name a `fn` definition line defines, if it defines one.
fn fn_defined(line: &str) -> Option<String> {
    let code = line.split("//").next().unwrap_or("");
    for part in code.split("fn ").skip(1) {
        let name: String = part
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after = &part[name.len()..];
        let opens = after.starts_with('(') || after.starts_with('<');
        if !name.is_empty() && opens {
            return Some(name);
        }
    }
    None
}

/// The innermost `fn` enclosing line `at`: the nearest definition at or above
/// it, so a call inside a closure still attributes to its function.
fn enclosing_fn(lines: &[&str], at: usize) -> String {
    lines[..=at]
        .iter()
        .rev()
        .find_map(|line| fn_defined(line))
        .unwrap_or_else(|| "<top>".to_owned())
}

/// Every `(src-relative path, enclosing fn, location)` whose code line matches
/// `wanted`, outside test files. Comment-only matches are skipped.
fn hits(wanted: impl Fn(&str) -> bool) -> Vec<(String, String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    src_files(&root.join("src"), &mut files);
    let mut out = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if !wanted(code) {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((
                rel,
                enclosing_fn(&lines, n),
                format!("{}:{}", path.display(), n + 1),
            ));
        }
    }
    out.sort();
    out
}

#[test]
fn public_seals_happen_only_at_the_seven_seal_points() {
    let expected: BTreeSet<(String, String)> = [
        (
            "src/gateway/meta_mcp/response_security.rs",
            "finalize_routed",
        ),
        (
            "src/gateway/router/backend_handlers/direct_dispatch.rs",
            "finish_tail",
        ),
        ("src/gateway/meta_mcp/search/chain_exec.rs", "execute_chain"),
        ("src/gateway/meta_mcp/playbook_invoker.rs", "invoke"),
        ("src/gateway/meta_mcp/upstream.rs", "recover_gated"),
        (
            "src/gateway/task_service/execution/worker.rs",
            "run_dispatched",
        ),
        (
            "src/gateway/task_service/execution/input_round.rs",
            "resume_flow",
        ),
    ]
    .into_iter()
    .map(|(file, func)| (file.to_owned(), func.to_owned()))
    .collect();
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    let mut strays = Vec::new();
    for (file, func, at) in hits(|code| code.contains("seal_public_provenance(")) {
        if file == "src/gateway/meta_mcp/invoke/provenance_stamp.rs"
            && func == "seal_public_provenance"
        {
            continue;
        }
        let pair = (file, func);
        if !expected.contains(&pair) {
            strays.push(format!("{at} in {}", pair.1));
        }
        found.insert(pair);
    }
    assert!(
        strays.is_empty(),
        "a public seal outside the seven seal points signs a receipt at a position \
         this request never minted (MIK-8398 C1c: seal only what this request minted): {strays:?}"
    );
    for pair in &expected {
        assert!(
            found.contains(pair),
            "the {} seal point in {} is gone: a receipt minted there would \
             never be sealed (MIK-8398 C1c: seal only what this request minted)",
            pair.1,
            pair.0,
        );
    }
}

#[test]
fn only_the_mint_records_a_receipt_as_minted() {
    let found = hits(|code| code.contains("MINTED") && code.contains(".insert("));
    assert_eq!(
        found.len(),
        1,
        "exactly one site records a mint, so a seal consumes the mint it checks \
         (MIK-8398 C1c: seal only what this request minted): {found:?}"
    );
    let (file, func, _) = &found[0];
    assert_eq!(
        (file.as_str(), func.as_str()),
        (
            "src/gateway/meta_mcp/invoke/provenance_stamp.rs",
            "maybe_stamp_provenance"
        ),
        "the mint record belongs to the stamping chokepoint, so every mint site \
         (live, replay, cache, recovery, direct) records through it \
         (MIK-8398 C1c: seal only what this request minted)"
    );
}

#[test]
fn public_signature_is_written_only_by_the_seal_and_the_event_mint() {
    let expected: BTreeSet<(String, String)> = [
        (
            "src/gateway/meta_mcp/invoke/provenance_stamp.rs",
            "seal_receipt",
        ),
        ("src/trust/provenance_public.rs", "provenance_value"),
    ]
    .into_iter()
    .map(|(file, func)| (file.to_owned(), func.to_owned()))
    .collect();
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    let mut strays = Vec::new();
    for (file, func, at) in hits(|code| code.contains("insert(\"public_signature\"")) {
        let pair = (file, func);
        if !expected.contains(&pair) {
            strays.push(format!("{at} in {}", pair.1));
        }
        found.insert(pair);
    }
    assert!(
        strays.is_empty(),
        "a `public_signature` writer outside the seal and the event mint signs \
         outside the mint rule (MIK-8398 C1c: seal only what this request minted): {strays:?}"
    );
    for pair in &expected {
        assert!(
            found.contains(pair),
            "the `public_signature` writer in {} ({}) is gone \
             (MIK-8398 C1c: seal only what this request minted)",
            pair.1,
            pair.0,
        );
    }
}

#[test]
fn provenance_value_is_called_only_from_event_services() {
    let mut found = false;
    let mut strays = Vec::new();
    for (file, func, at) in hits(|code| code.contains("provenance_value(")) {
        if file == "src/trust/provenance_public.rs" && func == "provenance_value" {
            continue;
        }
        if file == "src/events/services.rs" && func == "provenance" {
            found = true;
            continue;
        }
        strays.push(format!("{at} in {func}"));
    }
    assert!(
        strays.is_empty(),
        "`provenance_value` mints and signs in one function with no result digest; \
         calling it elsewhere binds a different shape to the same member \
         (MIK-8398 C1c: seal only what this request minted): {strays:?}"
    );
    assert!(
        found,
        "the event mint in `provenance` (src/events/services.rs) no longer signs: \
         event receipts lost their public part \
         (MIK-8398 C1c: seal only what this request minted)"
    );
}

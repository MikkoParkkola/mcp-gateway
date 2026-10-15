// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7979: `Error::BackendUnavailable` is on the `is_pre_dispatch` allowlist
//! because it is constructed only before a request is sent. This scan holds
//! that to a reviewed list of files: a new file that constructs the variant
//! fails the build until a reviewer adds it here with its pre-send proof, and
//! a listed file that no longer constructs it fails as stale.
//!
//! Threat model: honest edits, not adversarial ones. It catches a contributor
//! who builds the variant somewhere new without knowing the invariant. It is
//! a text scan, not a parser: comments, string and char literals and
//! `#[cfg(test)]` items are blanked first, and match patterns are told apart
//! from constructions by shape. Someone set on evading it can; review is the
//! control for that.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Files (relative to `src/`) allowed to construct `BackendUnavailable`, each
/// raising it only before the request is sent (design MIK-7979, addendum 1).
const PRE_SEND_SITES: &[&str] = &[
    // Cold tools/list timeout and cooldown fast-fail; rebuilds a stored refusal.
    "backend/fill_check.rs",
    // The dispatch's started slot was replaced before its era was read: refused
    // before the wire, to be retried (MIK-8186, `start_judged`).
    "backend/era.rs",
    // Start loop exhausted, connect policy changed, publish refused, and
    // `pre_send_start_error`.
    "backend/lifecycle.rs",
    // Stale tools refresh refused in cooldown.
    "backend/metadata.rs",
    // Start refused: package cache still locked, or its rename timed out.
    "backend/package_cache.rs",
    // Concurrency semaphore closed (request and notify paths).
    "backend/ops.rs",
    // Health probe with no shared transport (not tool dispatch).
    "backend/probe.rs",
    // Warm start (not tool dispatch).
    "gateway/server/warmstart.rs",
];

/// `src` with comments, string literals and char literals replaced by spaces,
/// newlines kept so positions stay meaningful.
fn sanitize(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            while i < b.len() {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if b[i] == b'r' && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#')) {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                i += 1;
                continue;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            i += 2 + hashes;
            while i < b.len() && !b[i..].starts_with(&close) {
                i += 1;
            }
            i = (i + close.len()).min(b.len());
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else if b[i] == b'\'' && (b.get(i + 1) == Some(&b'\\') || b.get(i + 2) == Some(&b'\'')) {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else {
            i += 1;
            continue;
        }
        blank(&mut out, start, i.min(b.len()));
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Blank every item a `#[cfg(test)]` attribute guards: up to the first `;`
/// for a declaration, or through the matching `}` of its body.
fn strip_test_items(src: &str) -> String {
    let mut out = src.as_bytes().to_vec();
    let mut from = 0;
    while let Some(at) = src[from..].find("#[cfg(test)]").map(|p| p + from) {
        let rest = &src.as_bytes()[at..];
        let semi = rest.iter().position(|c| *c == b';');
        let brace = rest.iter().position(|c| *c == b'{');
        let end = match (semi, brace) {
            (Some(s), Some(o)) if s < o => at + s + 1,
            (_, Some(o)) => {
                let mut depth = 0usize;
                let mut j = at + o;
                loop {
                    match out.get(j) {
                        Some(b'{') => depth += 1,
                        Some(b'}') => {
                            depth -= 1;
                            if depth == 0 {
                                break j + 1;
                            }
                        }
                        None => break j,
                        _ => {}
                    }
                    j += 1;
                }
            }
            (Some(s), None) => at + s + 1,
            (None, None) => src.len(),
        };
        for c in &mut out[at..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        from = end;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// How many times `src` constructs `BackendUnavailable`: a call, a function
/// value or an import. A match pattern is not one: `(_)`/`(..)`, a group
/// followed by `=>` or `|`, or one preceded by `|`. The enum's own
/// `BackendUnavailable(String)` declaration is not one either.
fn constructions(src: &str) -> usize {
    constructions_of(src, "BackendUnavailable")
}

/// [`constructions`] for any `NAME`: a variant, or a function whose result
/// `is_pre_dispatch` trusts.
fn constructions_of(src: &str, name: &str) -> usize {
    let clean = strip_test_items(&sanitize(src));
    let b = clean.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let next_non_ws = |from: usize| b[from..].iter().position(|c| !c.is_ascii_whitespace());
    let mut count = 0;
    for (at, _) in clean.match_indices(name) {
        let end = at + name.len();
        if (at > 0 && ident(b[at - 1])) || b.get(end).copied().is_some_and(ident) {
            continue;
        }
        let path_start = b[..at]
            .iter()
            .rposition(|c| !(ident(*c) || *c == b':'))
            .map_or(0, |p| p + 1);
        let before = b[..path_start]
            .iter()
            .rposition(|c| !c.is_ascii_whitespace());
        let after_alt = before.is_some_and(|p| b[p] == b'|' && (p == 0 || b[p - 1] != b'|'));
        let open = next_non_ws(end).map(|p| end + p);
        let Some(open) = open.filter(|p| b[*p] == b'(') else {
            count += 1;
            continue;
        };
        let mut depth = 0usize;
        let mut close = open;
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = clean[open + 1..close].trim();
        let rest = clean[close + 1..].trim_start();
        let alt_after = rest.starts_with('|') && !rest.starts_with("||");
        let pattern = matches!(inner, "_" | ".." | "String")
            || rest.starts_with("=>")
            || alt_after
            || after_alt;
        if !pattern {
            count += 1;
        }
    }
    count
}

/// The non-test files under `src/` that construct `name`.
fn files_constructing(name: &str) -> BTreeSet<String> {
    construction_counts(name).into_keys().collect()
}

/// How many times each non-test file under `src/` constructs `name`.
fn construction_counts(name: &str) -> BTreeMap<String, usize> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = BTreeMap::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("src is readable");
        let path = entry.path();
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // Test-only by the repo's naming: `*tests.rs`, `*_test.rs`, or under a
        // `tests`/`*_tests` directory.
        let in_test_dir = path
            .strip_prefix(&root)
            .ok()
            .and_then(Path::parent)
            .is_some_and(|dir| {
                dir.components()
                    .any(|c| c.as_os_str().to_str().is_some_and(|s| s.ends_with("tests")))
            });
        let test_only = file.ends_with("tests.rs") || file.ends_with("_test.rs") || in_test_dir;
        if test_only || path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("readable source");
        let count = constructions_of(&src, name);
        if count > 0 {
            let rel = path.strip_prefix(&root).expect("under src");
            found.insert(rel.to_string_lossy().replace('\\', "/"), count);
        }
    }
    found
}

#[test]
fn backend_unavailable_is_constructed_only_at_reviewed_pre_send_sites() {
    let found = files_constructing("BackendUnavailable");
    let allowed: BTreeSet<String> = PRE_SEND_SITES.iter().map(|s| (*s).to_string()).collect();
    let unreviewed: Vec<_> = found.difference(&allowed).collect();
    let stale: Vec<_> = allowed.difference(&found).collect();
    assert!(
        unreviewed.is_empty(),
        "BackendUnavailable frees an idempotency key, so it may be built only before \
         the request is sent; an after-send failure is Transport or BackendTimeout. \
         Unreviewed files: {unreviewed:?}"
    );
    assert!(stale.is_empty(), "no longer build it, drop them: {stale:?}");
}

#[test]
fn the_scan_tells_constructions_from_patterns_comments_and_tests() {
    let ignored = r#"
// Error::BackendUnavailable("comment".into())
const S: &str = "Error::BackendUnavailable(x)";
enum E { BackendUnavailable(String), }
fn f(e: &Error) -> bool { matches!(e, Error::BackendUnavailable(_)) }
fn g(e: Error) {
    match e {
        Error::BackendUnavailable(m) => drop(m),
        Error::Transport(m) | Error::BackendUnavailable(m) => drop(m),
        _ => {}
    }
}
#[cfg(test)]
mod tests { fn t() { let _ = Error::BackendUnavailable("test".into()); } }
"#;
    assert_eq!(constructions(ignored), 0);
    let call = r#"fn h() -> Error { Error::BackendUnavailable(format!("{}", 1)) }"#;
    assert_eq!(constructions(call), 1);
    assert_eq!(constructions("let f = Error::BackendUnavailable;"), 1);
    assert_eq!(
        constructions("use crate::Error::BackendUnavailable as Down;"),
        1
    );
}

/// Call sites (per file, relative to `src/`) allowed to build the sealed
/// transient, each only before anything reaches the backend (MIK-8428):
/// `is_pre_dispatch` reads its seal, so it frees an idempotency key. Counted
/// per file, so a new call in a listed file fails the scan too. A builder's
/// own definition counts as one.
const TRANSIENT_SITES: &[(&str, usize)] = &[
    // `transient_retry_error`'s definition.
    ("personal_accounts/refusal.rs", 1),
    // `transient_mint_refusal`'s definition and its one build.
    ("identity_propagation/account_strategies_view.rs", 2),
    // A capability mint's resolve or refresh admission (`resolve`), and the
    // lease recheck before the send (`revalidate`, from three callers).
    ("identity_propagation/account_strategies.rs", 2),
    // A per-user mint's admission, before the dispatch.
    ("gateway/meta_mcp/invoke/propagation.rs", 1),
    // The task intake answer: no task, nothing dispatched.
    ("gateway/meta_mcp/call_dispatch.rs", 1),
    // The caller verdict's view Busy, answered before the backend.
    ("gateway/meta_mcp/invoke/caller_verdict.rs", 1),
    // A stored task read: no dispatch at all.
    ("gateway/meta_mcp/task_replay.rs", 1),
];

#[test]
fn the_sealed_transient_is_built_only_at_reviewed_pre_send_sites() {
    let mut found = construction_counts("transient_retry_error");
    for (file, count) in construction_counts("transient_mint_refusal") {
        *found.entry(file).or_default() += count;
    }
    let allowed: BTreeMap<String, usize> = TRANSIENT_SITES
        .iter()
        .map(|(file, count)| ((*file).to_string(), *count))
        .collect();
    assert_eq!(
        found, allowed,
        "the sealed transient frees an idempotency key, so it may be built only \
         before anything reaches the backend: review every new or removed call \
         site (left: found, right: reviewed)"
    );
}

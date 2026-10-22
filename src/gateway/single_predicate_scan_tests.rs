// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 T1c + T2: one API-key predicate, one caller principal.
//!
//! A new inline copy of either predicate fails here until it is routed
//! through the shared body. Text scan, not a parser: comments, strings and
//! `#[cfg(test)]` items are blanked first, as in
//! `error_pre_send_scan_tests.rs`.

use std::path::Path;

/// Files (relative to `src/`) allowed to compare against `ApiKey`.
/// Each entry is a reviewed site, not a whole-file exemption for new copies:
/// the scan still reports any other comparison in these files, but today
/// they hold only the listed shape.
const API_KEY_ALLOWLIST: &[(&str, &str)] = &[
    ("gateway/auth.rs", "the one predicate, api_key_identity"),
    ("gateway/auth_resolved.rs", "mint literal"),
    ("events/records.rs", "delivery lifetime"),
    ("gateway/router/handlers/events.rs", "live-binding arm"),
    ("events/services.rs", "subscription admission"),
    (
        "security/audit.rs",
        "defines the enum and CredentialKind::of",
    ),
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

/// Every non-test `.rs` file under `src/`, as `(relative path, clean text)`.
fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("src is readable");
        let path = entry.path();
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
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
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        files.push((rel, strip_test_items(&sanitize(&src))));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// Whether `line` compares against the `ApiKey` variant: `==`, `matches!`,
/// a `filter` closure, or any `::ApiKey` path in a comparison. `ApiKeyDigest`,
/// `ApiKeyConfig` and friends are not the variant: the path must end at
/// `ApiKey`, not continue into a longer identifier.
fn is_api_key_comparison(line: &str) -> bool {
    let mut has_variant = false;
    for (at, _) in line.match_indices("::ApiKey") {
        let end = at + "::ApiKey".len();
        let continues = line
            .as_bytes()
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
        if !continues {
            has_variant = true;
            break;
        }
    }
    if !has_variant {
        return false;
    }
    line.contains("==") || line.contains("matches!") || line.contains("filter")
}

/// MIK-8659 T1c (RED): no `ApiKey` comparison outside the allowlist.
/// Today the F0 copies in the caller context, the direct dispatcher, the
/// events hook and the dashboard link are still inline, so this fails.
#[test]
fn t1c_no_api_key_comparison_outside_the_predicate() {
    let allowlisted = |file: &str| {
        if API_KEY_ALLOWLIST
            .iter()
            .any(|(allowed, _)| *allowed == file)
        {
            return true;
        }
        // Any file that only defines the enum or its `of` constructor.
        file == "security/audit.rs"
    };
    let mut offending = Vec::new();
    for (file, clean) in production_sources() {
        if allowlisted(&file) {
            // The allowlisted files still fail on a NEW comparison: only the
            // reviewed shapes may appear there. Today they hold only those,
            // except the events live-binding file, which also holds the F0
            // `fn api_key` copy that PR-1 routes through the predicate.
            // That copy is reported below like any other.
            if file != "gateway/router/handlers/events.rs" {
                continue;
            }
        }
        for (index, line) in clean.lines().enumerate() {
            if !is_api_key_comparison(line) {
                continue;
            }
            // The live-binding arm is a match arm, not a comparison, so the
            // shape above never matches it; this guard documents that.
            if file == "gateway/router/handlers/events.rs" && !line.contains("==") {
                continue;
            }
            offending.push(format!("{}:{}", file, index + 1));
        }
    }
    assert!(
        offending.is_empty(),
        "new ApiKey comparison outside auth::api_key_name (route it through the predicate): {}",
        offending.join(", ")
    );
}

/// MIK-8659 T2 scan (RED): no `authenticated && !...is_empty()` outside
/// `gateway/auth.rs`. Today the nine F-PRINCIPAL sites are still inline.
#[test]
fn t2_no_principal_conjunct_outside_auth() {
    let mut offending = Vec::new();
    for (file, clean) in production_sources() {
        if file == "gateway/auth.rs" {
            continue;
        }
        let lines: Vec<&str> = clean.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            // Same-line conjunct: `authenticated && !...is_empty()`.
            let same_line = (line.contains("authenticated") || line.contains("Authenticated"))
                && line.contains("is_empty");
            // Split conjunct: `Authenticated` and a negated `is_empty` within
            // six lines (projection's filter, credential_owner's guard).
            let joined = lines
                .iter()
                .skip(index)
                .take(6)
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            let split = joined.contains("Authenticated")
                && joined.contains('!')
                && joined.contains("is_empty")
                && (joined.contains("credential_principal")
                    || joined.contains("principal")
                    || joined.contains("digest"));
            // Authenticated-only filter: a missing non-empty conjunct
            // (direct_preflight's binding).
            let filter_alone =
                line.contains(".filter") && line.contains("authenticated") && !line.contains("&&");
            if !(same_line || filter_alone || split) {
                continue;
            }
            // The split window reports once, at its first line; same-line and
            // filter-alone report at their own line.
            if split && !same_line && !filter_alone {
                // Only report the window's first line if it opens the
                // conjunct (holds `Authenticated` or the `is_empty`).
                let opens = line.contains("Authenticated") || line.contains("is_empty");
                if !opens {
                    continue;
                }
                // Avoid reporting every line of one window: only the first
                // line that opens it, then skip the next five.
                let earlier_opens = (index.saturating_sub(5)..index).any(|prev| {
                    lines.get(prev).is_some_and(|other| {
                        other.contains("Authenticated") || other.contains("is_empty")
                    }) && {
                        let earlier_window = lines
                            .iter()
                            .skip(prev)
                            .take(6)
                            .copied()
                            .collect::<Vec<_>>()
                            .join("\n");
                        earlier_window.contains("Authenticated")
                            && earlier_window.contains("is_empty")
                    }
                });
                if earlier_opens {
                    continue;
                }
            }
            // `is_empty` about something else (headers, vecs) is not a
            // principal check: the line or its window must name one.
            let names_principal = line.contains("principal")
                || line.contains("digest")
                || line.contains("credential_principal")
                || line.contains("Authenticated")
                || split;
            if !names_principal {
                continue;
            }
            offending.push(format!("{}:{}", file, index + 1));
        }
    }
    // Deduplicate windows that overlap.
    offending.sort();
    offending.dedup();
    assert!(
        offending.is_empty(),
        "principal conjunct outside auth::authenticated_principal (route it through the predicate): {}",
        offending.join(", ")
    );
}

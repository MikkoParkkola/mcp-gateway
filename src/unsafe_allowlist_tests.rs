// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-016: `unsafe` lives in exactly the scoped modules named here. A new
//! site fails this test until an ADR names it (ADR-028 rule 10 adds the
//! Windows credential module when it lands).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Product and test-helper files allowed to hold `unsafe`.
const ALLOWED: &[&str] = &["src/win_acl.rs", "src/gateway/server/tests/alloc_meter.rs"];

/// Integration tests with their own `unsafe` exemption (environment mutation
/// in single-threaded test binaries), recorded so a new one is a decision.
const TEST_EXEMPT: &[&str] = &[
    "tests/agent_key_env_tests.rs",
    "tests/capability_default_directories.rs",
    "tests/capability_egress_env_proxy.rs",
    "tests/capability_egress_proxy_opt_in.rs",
    "tests/common/era_probe_cap.rs",
    "tests/hardened_backend_env_proxy.rs",
    "tests/loopback_backend_env_proxy.rs",
    "tests/redact_memory_peak.rs",
    "tests/secret_injection_tests.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Whether `text` opts into or uses `unsafe`. This file's own patterns are
/// split so it does not match itself.
fn uses_unsafe(text: &str) -> bool {
    let unsafe_word = concat!("uns", "afe");
    [
        format!("allow({unsafe_word}_code)"),
        format!("expect({unsafe_word}_code)"),
        format!("{unsafe_word} {{"),
        format!("{unsafe_word} fn "),
        format!("{unsafe_word} impl "),
    ]
    .iter()
    .any(|pattern| text.contains(pattern.as_str()))
}

fn sites(root: &Path, dirs: &[&str]) -> BTreeSet<String> {
    let mut files = Vec::new();
    for dir in dirs {
        let path = root.join(dir);
        if path.is_file() {
            files.push(path);
        } else {
            rust_files(&path, &mut files);
        }
    }
    files
        .into_iter()
        .filter(|path| std::fs::read_to_string(path).is_ok_and(|text| uses_unsafe(&text)))
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn a18_unsafe_appears_only_in_the_scoped_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = sites(root, &["src", "benches", "examples", "build.rs"]);
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|path| (*path).to_owned()).collect();
    assert_eq!(
        found, allowed,
        "unsafe outside ADR-016/ADR-028's list, or a listed module without it"
    );
}

#[test]
fn a18_test_exemptions_are_the_recorded_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = sites(root, &["tests"]);
    let exempt: BTreeSet<String> = TEST_EXEMPT.iter().map(|path| (*path).to_owned()).collect();
    assert_eq!(found, exempt, "a new unsafe site in tests/");
}

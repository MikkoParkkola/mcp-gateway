// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 slice 1b: the record key's resolution, rows K1-K7 and D2.

use std::path::Path;

use super::*;
use crate::config::EnvOverlay;

const KEY_A5: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn fallback(dir: &Path) -> crate::Result<RecordPrincipalKey> {
    resolve_key(None, &EnvOverlay::none(), dir)
}

fn temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != KEY_FILE)
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// K1: an empty data dir gets a 64-hex key file, owner-only, and the same key
// on the next start.
#[test]
fn k1_an_empty_data_dir_gets_an_owner_only_hex_key_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = fallback(dir.path()).expect("created");
    let path = dir.path().join(KEY_FILE);
    let text = std::fs::read_to_string(&path).expect("key file");
    let hex = text.strip_suffix('\n').expect("one trailing newline");
    assert_eq!(hex.len(), 64, "{text:?}");
    assert!(
        hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{text:?}"
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    let again = fallback(dir.path()).expect("read back");
    assert_eq!(first.identity(), again.identity());
    assert_eq!(
        first.identity(),
        RecordPrincipalKey::from_text(hex).expect("key").identity()
    );
    assert!(temps(dir.path()).is_empty(), "{:?}", temps(dir.path()));
}

// K2: an existing valid file is read, never rewritten, and is the key in use.
#[test]
fn k2_an_existing_key_file_is_read_and_never_rewritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(KEY_FILE);
    crate::gateway::test_helpers::write_owner_only(&path, format!("{KEY_A5}\n").as_bytes())
        .expect("fixture");
    let before = std::fs::metadata(&path).expect("metadata");
    let key = fallback(dir.path()).expect("read");
    let after = std::fs::metadata(&path).expect("metadata");
    assert_eq!(before.modified().ok(), after.modified().ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(before.ino(), after.ino());
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("key"),
        format!("{KEY_A5}\n")
    );
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(KEY_A5)
            .expect("key")
            .identity()
    );
}

// K3b: a malformed file is refused, naming its path, never replaced.
#[test]
fn k3b_a_malformed_key_file_is_refused_naming_its_path() {
    for bad in [
        &KEY_A5[..63],
        "A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A55A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A",
        &"zz".repeat(32),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEY_FILE);
        crate::gateway::test_helpers::write_owner_only(&path, format!("{bad}\n").as_bytes())
            .expect("fixture");
        let Err(err) = fallback(dir.path()) else {
            panic!("{bad:?} was accepted as a key file");
        };
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("kept"),
            format!("{bad}\n")
        );
    }
}

// K3a, K3c: an unreadable or group/world-readable file is refused, naming it.
#[cfg(unix)]
#[test]
fn k3ac_an_unreadable_or_shared_key_file_is_refused() {
    for m in [0o000, 0o640, 0o604] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEY_FILE);
        crate::gateway::test_helpers::write_owner_only(&path, format!("{KEY_A5}\n").as_bytes())
            .expect("fixture");
        set_mode(&path, m);
        let Err(err) = fallback(dir.path()) else {
            panic!("mode {m:o} was accepted");
        };
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{m:o}: {err}"
        );
    }
}

// K4: a data dir that cannot be written, with no key file, stops startup.
#[cfg(unix)]
#[test]
fn k4_an_unwritable_data_dir_without_a_key_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    set_mode(dir.path(), 0o500);
    let result = fallback(dir.path());
    set_mode(dir.path(), 0o700);
    let Err(err) = result else {
        panic!("a key was produced without a file");
    };
    assert!(
        err.to_string()
            .contains(&dir.path().join(KEY_FILE).display().to_string()),
        "{err}"
    );
}

// K5: two first starts on one empty dir agree on one key and leave one file.
#[test]
fn k5_racing_first_starts_agree_on_one_key() {
    for _ in 0..20 {
        let dir = tempfile::tempdir().expect("tempdir");
        let barrier = std::sync::Barrier::new(2);
        let ids: Vec<String> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        fallback(dir.path()).expect("resolved").identity()
                    })
                })
                .collect();
            racers
                .into_iter()
                .map(|r| r.join().expect("racer"))
                .collect()
        });
        assert_eq!(ids[0], ids[1]);
        assert!(temps(dir.path()).is_empty(), "{:?}", temps(dir.path()));
    }
}

// K6: a temp left by a crash before publishing is ignored.
#[test]
fn k6_a_stray_temp_from_a_crash_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stray = dir.path().join(format!("{KEY_FILE}.1234.deadbeef.tmp"));
    crate::gateway::test_helpers::write_owner_only(&stray, b"a5a5").expect("fixture");
    let key = fallback(dir.path()).expect("created");
    let text = std::fs::read_to_string(dir.path().join(KEY_FILE)).expect("key file");
    assert_eq!(text.len(), 65, "{text:?}");
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(text.trim_end())
            .expect("key")
            .identity()
    );
}

// K7: a configured key is used and no file is created; a short or
// unresolvable one stops startup, naming the field.
#[test]
fn k7_a_configured_key_is_used_and_no_file_is_created() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = resolve_key(Some(KEY_A5), &EnvOverlay::none(), dir.path()).expect("literal");
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(KEY_A5)
            .expect("key")
            .identity()
    );
    assert!(!dir.path().join(KEY_FILE).exists());
    for bad in ["short", "env:MIK_8697_UNSET_RECORD_KEY_VARIABLE"] {
        let Err(err) = resolve_key(Some(bad), &EnvOverlay::none(), dir.path()) else {
            panic!("{bad} was accepted");
        };
        assert!(err.to_string().contains(KEY_FIELD), "{bad}: {err}");
    }
    assert!(!dir.path().join(KEY_FILE).exists());
}

// D2: the fallback file and the same file named as a SecretRef are one key.
#[test]
fn d2_the_key_file_promoted_to_a_secret_ref_keeps_every_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from_file = fallback(dir.path()).expect("created");
    let reference = format!("file:{}", dir.path().join(KEY_FILE).display());
    let other = tempfile::tempdir().expect("tempdir");
    let from_ref = resolve_key(Some(&reference), &EnvOverlay::none(), other.path()).expect("ref");
    assert_eq!(from_file.identity(), from_ref.identity());
    let p = InternalPrincipal::new("3f2a9c0d1e7b".to_owned());
    assert_eq!(p.record_form(&from_file), p.record_form(&from_ref));
}

// G-KEY (lead, 2026-10-23): no fixed record key ships. A `const …RECORD_KEY`
// or the fixture value outside test code would be a secret-shaped constant
// in the release crate, so each hit in src/ must be test-only: a `_tests.rs`
// or `/tests/` file, or an item under `#[cfg(test)]` on the line above.
#[test]
fn g_key_no_fixed_record_key_ships_outside_test_code() {
    fn walk(dir: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, hits);
                continue;
            }
            let rel = path.to_string_lossy().replace('\\', "/");
            if !rel.ends_with(".rs") || rel.ends_with("_tests.rs") || rel.contains("/tests/") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                let shaped = (line.contains("const ") && line.contains("RECORD_KEY"))
                    || line.contains("test-record-key-");
                let test_only = n > 0 && lines[n - 1].trim() == "#[cfg(test)]";
                if shaped && !test_only && !line.trim_start().starts_with("//") {
                    hits.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut hits,
    );
    assert!(
        hits.is_empty(),
        "a fixed record key outside test code: {hits:?}"
    );
}

/// Brace depth outside strings, raw strings, char literals and comments,
/// carried across lines.
#[derive(Default)]
struct Braces {
    depth: usize,
    in_str: bool,
    raw_hashes: Option<usize>,
    in_block_comment: bool,
}

impl Braces {
    fn feed(&mut self, line: &str) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if self.in_block_comment {
                if b[i..].starts_with(b"*/") {
                    self.in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(hashes) = self.raw_hashes {
                let closes = b[i] == b'"'
                    && b.len() > i + hashes
                    && b[i + 1..=i + hashes].iter().all(|&c| c == b'#');
                if closes {
                    self.raw_hashes = None;
                    i += 1 + hashes;
                } else {
                    i += 1;
                }
                continue;
            }
            if self.in_str {
                match b[i] {
                    b'\\' => i += 2,
                    b'"' => {
                        self.in_str = false;
                        i += 1;
                    }
                    _ => i += 1,
                }
                continue;
            }
            let ident_before = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => break,
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    self.in_block_comment = true;
                    i += 2;
                }
                b'r' if !ident_before => {
                    let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
                    if b.get(i + 1 + hashes) == Some(&b'"') {
                        self.raw_hashes = Some(hashes);
                        i += 2 + hashes;
                    } else {
                        i += 1;
                    }
                }
                b'"' => {
                    self.in_str = true;
                    i += 1;
                }
                // A char literal ('{', '\''); a lifetime has no closing quote.
                b'\'' if b.get(i + 1) == Some(&b'\\') => {
                    i += 3;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                }
                b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
                b'{' => {
                    self.depth += 1;
                    i += 1;
                }
                b'}' => {
                    self.depth = self.depth.saturating_sub(1);
                    i += 1;
                }
                _ => i += 1,
            }
        }
    }
}

/// The lines of `text` outside inline test modules, with their 0-based
/// numbers. A test module is `#[cfg(test)]` then `mod NAME {` and runs to its
/// matching `}`: classified by its extent, so production code after it is
/// still scanned. A `#[cfg(test)]` on a field, a fn or an out-of-line
/// `mod x;` marks no section (the lesson of the first cfg(test) line).
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut braces = Braces::default();
    let mut armed = false;
    // The depth the open test module closes back to.
    let mut test_until: Option<usize> = None;
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let opens = armed
            && test_until.is_none()
            && trimmed.split_whitespace().any(|w| w == "mod")
            && trimmed.ends_with('{');
        if opens {
            test_until = Some(braces.depth);
        }
        let in_test = test_until.is_some() || trimmed == "#[cfg(test)]";
        if trimmed == "#[cfg(test)]" {
            armed = true;
        } else if !trimmed.is_empty() && !trimmed.starts_with("#[") && !trimmed.starts_with("//") {
            armed = false;
        }
        braces.feed(line);
        if !in_test {
            out.push((n, *line));
        }
        if test_until.is_some_and(|d| braces.depth == d) && !opens {
            test_until = None;
        }
    }
    out
}

/// The scan classifies by enclosing item: production code after an inline
/// test module's closing brace is production, and braces in strings, char
/// literals and comments inside the module do not end it early.
#[test]
fn production_lines_classify_by_enclosing_item() {
    let src = r##"fn early() {}
#[cfg(test)]
pub(crate) value: u8,
#[cfg(test)]
mod key_tests;
#[cfg(test)]
mod tests {
    fn t() {
        let _ = "}}}";
        let _ = r#"}"#;
        let _ = '}';
        // }
        /* } */
        if true { let _ = 1; }
    }
}
fn after_the_test_module() {}
"##;
    let kept: Vec<&str> = production_lines(src).into_iter().map(|(_, l)| l).collect();
    assert!(kept.contains(&"fn early() {}"), "{kept:?}");
    assert!(kept.contains(&"pub(crate) value: u8,"), "{kept:?}");
    assert!(kept.contains(&"mod key_tests;"), "{kept:?}");
    assert!(kept.contains(&"fn after_the_test_module() {}"), "{kept:?}");
    assert!(
        !kept
            .iter()
            .any(|l| l.contains("fn t()") || l.contains("\"}}}\"")),
        "{kept:?}"
    );
}

// G-META (lead, 2026-10-23): `MetaMcp::record_key` panics when no key was
// installed, which is acceptable only if no production MetaMcp can lack one.
// (1) Outside test code, MetaMcp is constructed only in build_meta_mcp
// (src/gateway/server/build_meta.rs). (2) That function installs the key at
// its top level, never under a condition.
#[test]
fn g_meta_every_production_meta_mcp_gets_the_record_key() {
    // Files included only under `#[cfg(test)]` from elsewhere, so nothing in
    // them marks them as test code; each named with where it is included.
    const TEST_ONLY_INCLUDES: &[&str] = &[
        "src/gateway/meta_mcp/search_disclosure_e2e", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/meta_mcp/list_paging_e2e.rs",    // surface_compaction_tests.rs
        "src/gateway/meta_mcp/account_resolver_",     // account_resolver_fixture (tests)
        "src/gateway/meta_mcp/account_rest_fixture.rs", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/meta_mcp/slot_verdict_fixture.rs", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/router/direct_guards_fixture.rs", // router/mod.rs, #[cfg(test)]
        // #[path] from stored_replay_liveness_token_exchange_tests.rs
        "src/gateway/router/stored_replay_liveness_idp_fixture.rs",
    ];
    const BUILD_META: &str = "src/gateway/server/build_meta.rs";
    fn walk(dir: &Path, root: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, hits);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if !rel.ends_with(".rs")
                || rel.contains("_tests")
                || rel.contains("/tests/")
                || rel.ends_with("tests.rs")
                || rel == BUILD_META
                || TEST_ONLY_INCLUDES.iter().any(|p| rel.starts_with(p))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for (n, line) in production_lines(&text) {
                let constructs = line.contains("MetaMcp::new(")
                    || line.contains("MetaMcp::with_features(")
                    || line.contains("MetaMcp::with_features_and_clock(");
                if constructs && !line.trim_start().starts_with("//") {
                    hits.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), root, &mut hits);
    assert!(
        hits.is_empty(),
        "a production MetaMcp built outside build_meta_mcp could lack the record key: {hits:?}"
    );
    let build_meta = std::fs::read_to_string(root.join(BUILD_META)).expect("build_meta");
    let installs: Vec<&str> = build_meta
        .lines()
        .filter(|l| l.contains("meta_mcp_builder.set_record_key("))
        .collect();
    assert_eq!(
        installs.len(),
        1,
        "build_meta_mcp installs the record key exactly once"
    );
    assert!(
        installs[0].starts_with("        meta_mcp_builder"),
        "the install is at the function's top level, not under a condition: {:?}",
        installs[0]
    );
}

// G-LOGSITES (lead, 2026-10-23): a logger opened in test code starts keyed,
// so this proves the production openers by source. Outside test code the
// logger is opened in two places: build_meta_mcp, which installs the record
// key on the logger it opens, and the governance store, whose records never
// carry a `caller_key` (the only field the logger keys), so it needs none.
#[test]
fn g_logsites_every_production_logger_is_keyed_or_never_keys() {
    // Included only under `#[cfg(test)]`, each named with where.
    const TEST_ONLY: &[&str] = &[
        "src/gateway/meta_mcp/account_resolver_", // account_resolver_fixture (tests)
        "src/gateway/meta_mcp/account_rest_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/meta_mcp/grant_audit_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/meta_mcp/slot_verdict_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/router/direct_guards_fixture_quota.rs", // direct_guards_fixture.rs
        "src/gateway/router/stored_replay_liveness_idp_fixture.rs", // its _tests.rs
        "src/gateway/server/tools_changed/audience_fixture.rs", // tools_changed.rs
    ];
    const OPENERS: &[&str] = &[
        "src/gateway/server/build_meta.rs",
        "src/gateway/server/control_plane_store.rs",
    ];
    fn walk(dir: &Path, root: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, hits);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if !rel.ends_with(".rs")
                || rel.contains("_tests")
                || rel.contains("/tests/")
                || rel.ends_with("tests.rs")
                || TEST_ONLY.iter().any(|p| rel.starts_with(p))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for (_, line) in production_lines(&text) {
                if line.contains("TransparencyLogger::open(")
                    && !line.trim_start().starts_with("//")
                {
                    hits.push(rel.clone());
                }
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), root, &mut hits);
    hits.sort();
    hits.dedup();
    assert_eq!(hits, OPENERS, "a new production logger opener");
    let build_meta = std::fs::read_to_string(root.join(OPENERS[0])).expect("build_meta");
    assert!(
        build_meta.contains(".with_record_key(Arc::clone(&record_key))"),
        "build_meta_mcp keys the logger it opens"
    );
    fn mentions_caller_key(dir: &Path) -> bool {
        std::fs::read_dir(dir).expect("dir").flatten().any(|e| {
            let p = e.path();
            if p.is_dir() {
                return mentions_caller_key(&p);
            }
            std::fs::read_to_string(&p).is_ok_and(|t| t.contains("caller_key"))
        })
    }
    assert!(
        !mentions_caller_key(&root.join("src/control_plane")),
        "a governance record now carries caller_key, so its logger needs the record key"
    );
}

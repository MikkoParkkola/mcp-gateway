// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: the clock module's own rows.

use super::test_clock;
use super::*;

#[test]
fn a_clock_before_the_epoch_is_an_error_in_every_form() {
    let _clock = test_clock::before_epoch();
    assert_eq!(unix_secs(), Err(ClockBeforeEpoch));
    assert_eq!(utc_now(), Err(ClockBeforeEpoch));
}

#[test]
fn an_access_check_on_an_unreadable_clock_is_expired_whatever_it_compares() {
    let _clock = test_clock::before_epoch();
    assert_eq!(expired_by(|_| Validity::Live), Validity::Expired);
    assert_eq!(expired_by_utc(|_| Validity::Live), Validity::Expired);
}

#[test]
fn a_readable_clock_runs_the_sites_own_comparison() {
    let _clock = test_clock::at_secs(1_000);
    assert_eq!(unix_secs(), Ok(1_000));
    let expiry = |exp: u64| {
        expired_by(|now| {
            if now >= exp {
                Validity::Expired
            } else {
                Validity::Live
            }
        })
    };
    assert_eq!(expiry(1_001), Validity::Live);
    assert_eq!(expiry(1_000), Validity::Expired);
    assert_eq!(
        utc_now().map(|now| now.timestamp()),
        Ok(1_000),
        "the chrono form reads the same clock"
    );
}

#[test]
fn the_guard_restores_the_real_clock() {
    {
        let _clock = test_clock::before_epoch();
    }
    assert!(unix_secs().is_ok());
}

fn at(secs: u64) -> JwtClaimTime {
    JwtClaimTime::At(secs)
}

#[test]
fn the_jwt_window_near_the_epoch_neither_underflows_nor_admits_the_expired() {
    let _clock = test_clock::at_secs(100);
    // 30 + 60 < 100: expired. 50 + 60 >= 100: within the leeway.
    assert_eq!(
        jwt_window(at(30), JwtClaimTime::Absent, 60),
        Validity::Expired
    );
    assert_eq!(jwt_window(at(50), JwtClaimTime::Absent, 60), Validity::Live);
    // Closer than the leeway to the epoch: nothing subtracts, nothing wraps.
    let _clock = test_clock::at_secs(10);
    assert_eq!(jwt_window(at(0), JwtClaimTime::Absent, 60), Validity::Live);
}

#[test]
fn the_jwt_window_boundaries_and_malformed_claims() {
    let _clock = test_clock::at_secs(1_000);
    assert_eq!(
        jwt_window(at(940), JwtClaimTime::Absent, 60),
        Validity::Live,
        "exp + leeway == now"
    );
    assert_eq!(
        jwt_window(at(939), JwtClaimTime::Absent, 60),
        Validity::Expired
    );
    assert_eq!(
        jwt_window(at(2_000), at(1_060), 60),
        Validity::Live,
        "nbf == now + leeway"
    );
    assert_eq!(
        jwt_window(at(2_000), at(1_061), 60),
        Validity::Expired,
        "immature"
    );
    assert_eq!(
        jwt_window(at(u64::MAX), JwtClaimTime::Absent, 60),
        Validity::Expired,
        "overflow"
    );
    assert_eq!(
        jwt_window(at(2_000), JwtClaimTime::Malformed, 60),
        Validity::Expired
    );
    assert_eq!(
        jwt_window(JwtClaimTime::Malformed, JwtClaimTime::Absent, 60),
        Validity::Expired
    );
}

#[test]
fn the_jwt_window_on_an_unreadable_clock_is_expired() {
    let _clock = test_clock::before_epoch();
    assert_eq!(
        jwt_window(at(u64::MAX - 1), JwtClaimTime::Absent, 0),
        Validity::Expired
    );
}

/// MIK-8202 E4: an audit row is stamped with the time on a readable clock,
/// and kept undated (`null`, `clock_invalid: true`) on one before 1970.
#[test]
fn an_audit_row_is_kept_undated_on_an_unreadable_clock() {
    let mut dated = serde_json::Map::new();
    stamp_audit_row(&mut dated);
    assert!(dated["timestamp"].is_string(), "{dated:?}");
    assert!(!dated.contains_key("clock_invalid"), "{dated:?}");
    let _clock = test_clock::before_epoch();
    let mut undated = serde_json::Map::new();
    stamp_audit_row(&mut undated);
    assert_eq!(undated["timestamp"], serde_json::Value::Null);
    assert_eq!(undated["clock_invalid"], true);
}

/// MIK-8202 P4a r4.2, the twin-copy invariant: clock.rs compiles into the
/// library and the binary, so any state in it exists twice and an override
/// set through one copy never reaches the other. A lexical check of its own
/// source: the only `static` items sit inside the `test_clock` `thread_local!`
/// block, and no lock, atomic or once-cell appears in code. Comment lines are
/// skipped (the module doc names the forbidden types).
#[test]
fn clock_rs_holds_no_shared_mutable_state() {
    let code: Vec<&str> = include_str!("clock.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let block_start = code
        .iter()
        .position(|line| line.trim() == "thread_local! {")
        .expect("the test_clock thread_local! block");
    let block_end = block_start
        + code[block_start..]
            .iter()
            .position(|line| line.trim() == "}")
            .expect("the thread_local! block closes");
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    for (i, line) in code.iter().enumerate() {
        for (at, _) in line.match_indices("static") {
            let before = line[..at].chars().next_back();
            let after = line[at + "static".len()..].chars().next();
            let a_static_item =
                !before.is_some_and(|c| is_ident(c) || c == '\'') && !after.is_some_and(is_ident);
            assert!(
                !a_static_item || (block_start < i && i < block_end),
                "a static outside the test_clock thread_local! block: {line}"
            );
        }
        for forbidden in ["Mutex", "RwLock", "Atomic", "OnceLock", "LazyLock"] {
            assert!(
                !line.contains(forbidden),
                "shared mutable state ({forbidden}) in clock.rs: {line}"
            );
        }
    }
}

/// Test-only by the repo's naming (as error_pre_send_scan_tests.rs reads it):
/// `*tests.rs`, `*_test.rs`, or under a `tests`/`*_tests` directory.
fn a_test_file(rel: &std::path::Path) -> bool {
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let in_test_dir = rel.parent().is_some_and(|dir| {
        dir.components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.ends_with("tests")))
    });
    name.ends_with("tests.rs") || name.ends_with("_test.rs") || in_test_dir
}

/// A file's product code: comment lines dropped, and every `#[cfg(test)]`
/// item (its attributes, then a `;` line or a brace-balanced block) removed.
/// ponytail: braces inside string literals are counted too; no src file
/// opens a test item with one today, and a miss only widens what is scanned.
fn product_code(src: &str) -> String {
    let lines: Vec<&str> = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].trim().starts_with("#[cfg(test)]") {
            out.push(lines[i]);
            i += 1;
            continue;
        }
        i += 1;
        while i < lines.len() && lines[i].trim_start().starts_with("#[") {
            i += 1;
        }
        let (mut depth, mut opened) = (0_i64, false);
        while i < lines.len() {
            let line = lines[i];
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            i += 1;
            if (opened && depth <= 0) || (!opened && line.trim_end().ends_with(';')) {
                break;
            }
        }
    }
    out.join("\n")
}

/// The brace-balanced block that opens at the first `{` from `from`.
fn block_from(code: &str, from: usize) -> &str {
    let Some(start) = code[from..].find('{').map(|at| from + at) else {
        return "";
    };
    let mut depth = 0_i64;
    for (at, c) in code[start..].char_indices() {
        depth += match c {
            '{' => 1,
            '}' => -1,
            _ => 0,
        };
        if depth == 0 {
            return &code[start..=start + at];
        }
    }
    &code[start..]
}

/// What the guard found in one product file: aliases of a clock type, and
/// `disallowed_methods` allows whose scope holds a clock read.
fn clock_lint_holes(rel: &str, src: &str) -> Vec<String> {
    // The tokens are assembled here so this file holds no raw read itself.
    let epoch = concat!("UNIX", "_EPOCH");
    let jwt = concat!("get_current", "_timestamp");
    let alias = regex::Regex::new(&format!(
        r"\buse\b[^;]*\b(?:Utc|Local|SystemTime|{epoch}|{jwt})\s+as\s+\w+|\btype\s+\w+\s*=\s*(?:[\w:]*::)?(?:Utc|Local|SystemTime)\s*;|\b(?:const|static)\s+\w+\s*:\s*[\w:]*SystemTime\s*=\s*[\w:]*{epoch}\b"
    ))
    .expect("alias pattern");
    let read = regex::Regex::new(&format!(
        r"\b(?:SystemTime|Utc|{epoch}|{jwt})\b|\bLocal\s*::\s*now\b"
    ))
    .expect("read pattern");
    let code = product_code(src);
    let mut holes: Vec<String> = alias
        .find_iter(&code)
        .map(|m| format!("{rel}: a clock type aliased: {}", m.as_str()))
        .collect();
    for (at, _) in code.match_indices("disallowed_methods") {
        let open = code[..at].rfind('#').unwrap_or(0);
        let close = code[at..].find(']').map_or(code.len(), |end| at + end + 1);
        let attr: String = code[open..close].split_whitespace().collect();
        if attr.contains("cfg_attr(test,") {
            // Scoped to test builds: the product build is linted.
            continue;
        }
        let scope = if attr.starts_with("#!") {
            code.as_str()
        } else {
            block_from(&code, close)
        };
        if read.is_match(scope) {
            holes.push(format!(
                "{rel}: a clock read inside a disallowed_methods allow"
            ));
        }
    }
    holes
}

/// MIK-8202 AC.9, P4b design r2 F (allow-scope hole) with r3/r4 F (alias
/// refusal: the `use … as`, `type X = …` and const/static epoch shapes, in
/// non-test code under src/ outside src/clock.rs). Once the baseline script
/// goes, clippy's `disallowed_methods` is the lint; this test is the guard the
/// baseline gave for two spots clippy cannot see: a product function that
/// already carries `allow(clippy::disallowed_methods)` for another entry (the
/// `dirs::*` lookups in src/home_dir.rs) would let a clock read inside it pass,
/// and an alias imported at module level could reach such a body.
/// Green on base (a guard). Mutant Fm, and the four r2 plants (an aliasing
/// `use`, a `type` alias, the const epoch alias, a clock read inside
/// home_dir's allowed body), each make the final `assert!` below fail, naming
/// the file; a `#[cfg(test)]` item holding an alias, and a
/// `cfg_attr(test, allow(..))` scope, are controls that stay green.
#[test]
fn no_disallowed_methods_allow_or_clock_alias_hides_a_clock_read() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut holes = Vec::new();
    let mut allows = 0;
    for entry in walkdir::WalkDir::new(root.join("src")) {
        let entry = entry.expect("src is readable");
        let path = entry.path();
        let rel = path.strip_prefix(root).expect("under the crate root");
        let rel_text = rel.to_string_lossy().replace('\\', "/");
        if path.extension().is_none_or(|e| e != "rs")
            || rel_text == "src/clock.rs"
            || a_test_file(rel)
        {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("readable source");
        allows += product_code(&src).matches("disallowed_methods").count();
        holes.extend(clock_lint_holes(&rel_text, &src));
    }
    assert!(
        allows > 0,
        "the scan found no disallowed_methods allow at all (src/home_dir.rs holds four): it is reading nothing"
    );
    assert!(holes.is_empty(), "{holes:#?}");
}

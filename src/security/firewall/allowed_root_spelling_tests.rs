// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Equivalent-spelling and directory rows (R33c-R33l, W12): the gateway
//! refuses a path a backend could respell onto another entry. Batch 2e.

use serde_json::json;

use super::super::*;
use super::tree::{Fx, Seen, both, code, root_rule};

fn refused(reason: RootReason) -> Seen {
    Seen::Refused(code(reason))
}

fn read(fx: &Fx, rel: &str) -> Seen {
    both(fx, "read_file", &json!({"path": fx.path(rel)}))
}

fn mkdir(fx: &Fx, rel: &str) {
    std::fs::create_dir_all(fx.dir.path().join(rel)).expect("mkdir");
}

/// R33c: missing `safe/a b` beside an existing `safe/a\u{a0}b` that links
/// out is `equivalent_spelling`; control: without the look-alike, allowed.
#[cfg(unix)]
#[test]
fn r33c_missing_name_with_a_look_alike_is_refused() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(read(&fx, "safe/a b/secret"), Seen::Allowed);
    mkdir(&fx, "outside/secret");
    std::os::unix::fs::symlink(
        fx.dir.path().join("outside"),
        fx.dir.path().join("safe/a\u{a0}b"),
    )
    .expect("link");
    assert_eq!(
        read(&fx, "safe/a b/secret"),
        refused(RootReason::EquivalentSpelling)
    );
}

/// R33f: directories `a b` and `a\u{a0}b`, root `a b`: a call under it is
/// refused, as more than one entry shares the key; control: only `a b`.
#[test]
fn r33f_two_entries_sharing_a_key_refuse_the_root_spelling() {
    let rule = |safe: String| {
        let root = format!("{safe}/a b");
        std::fs::create_dir_all(&root).expect("mkdir");
        vec![root_rule(
            "read_file",
            &[root],
            &["path"],
            FirewallAction::Block,
        )]
    };
    let fx = Fx::with_rules(rule);
    assert_eq!(read(&fx, "safe/a b/secret"), Seen::Allowed);
    mkdir(&fx, "safe/a\u{a0}b");
    assert_eq!(
        read(&fx, "safe/a b/secret"),
        refused(RootReason::EquivalentSpelling)
    );
}

/// R33f2: two existing entries whose spaces differ (`a\u{a0}b`, `a\u{2003}b`)
/// share a key: a call through either is refused, so the same-entry rule
/// cannot reopen the escape.
#[test]
fn r33f2_existing_entries_sharing_a_key_are_refused() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    mkdir(&fx, "safe/a\u{a0}b");
    assert_eq!(read(&fx, "safe/a\u{a0}b/x"), Seen::Allowed);
    mkdir(&fx, "safe/a\u{2003}b");
    assert_eq!(
        read(&fx, "safe/a\u{a0}b/x"),
        refused(RootReason::EquivalentSpelling)
    );
}

/// R33d (Linux keeps NFC and NFD distinct): an NFD spelling of a missing
/// name beside the NFC entry is refused; control: the NFC spelling.
#[cfg(target_os = "linux")]
#[test]
fn r33d_nfd_beside_nfc_is_refused_on_linux() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    mkdir(&fx, "safe/caf\u{e9}");
    assert_eq!(read(&fx, "safe/caf\u{e9}/x"), Seen::Allowed);
    let nfd = "safe/cafe\u{301}/x";
    assert_eq!(read(&fx, nfd), refused(RootReason::EquivalentSpelling));
}

/// R33d's macOS twin: APFS resolves the NFD request to the one NFC entry,
/// so the backend can reach nothing else: allowed.
#[cfg(target_os = "macos")]
#[test]
fn r33d_nfd_resolving_to_the_one_entry_is_allowed_on_macos() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    mkdir(&fx, "safe/caf\u{e9}");
    std::fs::write(fx.dir.path().join("safe/caf\u{e9}/x"), "x").expect("write");
    assert_eq!(read(&fx, "safe/cafe\u{301}/x"), Seen::Allowed);
}

/// R33j: a nested create under a missing directory is allowed: the check
/// stops after the first missing component.
#[test]
fn r33j_nested_create_under_a_missing_directory_is_allowed() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(read(&fx, "safe/new/sub/file"), Seen::Allowed);
}

/// R33e, R33k: a checked component's directory over the entry cap refuses
/// even an existing file; control: at the cap, allowed.
#[test]
fn r33k_directory_over_the_cap_is_refused() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    mkdir(&fx, "safe/big");
    let big = fx.dir.path().join("safe/big");
    for i in 0..DIRECTORY_ENTRY_CAP {
        std::fs::write(big.join(format!("e{i}")), "").expect("write");
    }
    assert_eq!(read(&fx, "safe/big/e0"), Seen::Allowed);
    std::fs::write(big.join("one-more"), "").expect("write");
    assert_eq!(
        read(&fx, "safe/big/e0"),
        refused(RootReason::DirectoryTooLarge)
    );
}

/// R33l (Linux): a non-UTF-8 entry is compared by bytes only, so it neither
/// matches a UTF-8 request falsely nor stops the request resolving.
#[cfg(target_os = "linux")]
#[test]
fn r33l_non_utf8_entry_is_compared_by_bytes() {
    use std::os::unix::ffi::OsStrExt as _;
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let odd = std::ffi::OsStr::from_bytes(b"a\xffb");
    std::fs::write(fx.dir.path().join("safe").join(odd), "").expect("write");
    assert_eq!(read(&fx, "safe/f"), Seen::Allowed);
    assert_eq!(read(&fx, "safe/a b"), Seen::Allowed);
    // The UTF-8 name a lossy comparison would confuse with `a\xffb`: its
    // bytes differ, so it is a distinct missing name and allowed.
    assert_eq!(read(&fx, "safe/a\u{fffd}b"), Seen::Allowed);
}

/// W12 (macOS): root `<tmp>/Safe`, call `<tmp>/safe/f`. On a
/// case-insensitive volume both canonicalise to the stored case: allowed,
/// a new file too. On a case-sensitive one `safe` is missing and resolves
/// outside. The row reads the volume first and asserts what follows.
#[cfg(target_os = "macos")]
#[test]
fn w12_differently_cased_spelling_follows_the_volume() {
    let fx = Fx::with_rules(|safe| {
        let root = format!("{safe}/Safe");
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::write(format!("{root}/f"), "in").expect("write");
        vec![root_rule(
            "read_file",
            &[root],
            &["path"],
            FirewallAction::Block,
        )]
    });
    let insensitive = fx.dir.path().join("safe/SAFE").exists();
    let want = if insensitive {
        Seen::Allowed
    } else {
        Seen::Outside(FirewallAction::Block)
    };
    assert_eq!(read(&fx, "safe/safe/f"), want);
    assert_eq!(read(&fx, "safe/safe/new.txt"), want);
    assert_eq!(read(&fx, "outside/f"), Seen::Outside(FirewallAction::Block));
}

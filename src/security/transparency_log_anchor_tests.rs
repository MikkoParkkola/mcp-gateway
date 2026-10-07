// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7713: `audit verify --anchor` checks the log against an off-host copy
//! of `.hwm`, so a wipe, rollback or replacement that rewrites the local
//! `.hwm` with it still fails. Each fixture keeps the existing chain, seam
//! and high-water checks passing, so only the anchor rule can fail it.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::rotation_tests::{SECRET, append, cfg, event, lines, log_path, rotate_n};
use super::segments::{self, HighWater, list_segments, sibling};
use super::*;

const MODES: [VerifyMode; 2] = [VerifyMode::Live, VerifyMode::Archive];

fn logger(path: &Path, retain: u32, signed: bool) -> TransparencyLogger {
    TransparencyLogger::open(cfg(path, retain, signed)).unwrap()
}

/// Copy `<path>.hwm` off-host, as an operator would.
fn copy_anchor(path: &Path, name: &str) -> PathBuf {
    let to = path.with_file_name(name);
    std::fs::copy(sibling(path, "hwm"), &to).unwrap();
    to
}

/// Write `hw` as an anchor file, MAC'd with `secret` when non-empty.
fn write_anchor(path: &Path, name: &str, hw: &HighWater, secret: &str) -> PathBuf {
    let to = path.with_file_name(name);
    std::fs::write(
        &to,
        segments::encode_hwm(hw, secret.as_bytes(), "test").unwrap(),
    )
    .unwrap();
    to
}

fn check(path: &Path, anchor: &Path, mode: VerifyMode, signed: bool) -> io::Result<VerifyResult> {
    verify_audit_log(path, &cfg(path, 12, signed), mode, Some(anchor))
}

/// The verdict fails, located at `at`, naming `needle`.
fn assert_fails(r: &VerifyResult, at: u64, needle: &str) {
    assert!(!r.ok, "passed: {r:?}");
    assert_eq!(r.error_at_counter, Some(at), "{r:?}");
    let msg = r.error_message.as_deref().unwrap_or_default();
    assert!(msg.contains(needle), "{msg}");
}

/// The log's files oldest first: sealed segments, then the active file.
fn files(path: &Path) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = list_segments(path)
        .unwrap()
        .into_iter()
        .map(|s| s.path)
        .collect();
    if path.exists() {
        all.push(path.to_path_buf());
    }
    all
}

/// Apply `edit` to every record (file index, line index), then re-chain the
/// whole log: each recomputed hash replaces its old value wherever a later
/// record or `.hwm` names it. Unsigned; `.hwm` is rewritten to match.
fn rechain(path: &Path, mut edit: impl FnMut(usize, usize, &mut Value)) {
    let mut renamed = std::collections::HashMap::<String, String>::new();
    for (f, file) in files(path).iter().enumerate() {
        let mut body = String::new();
        for (i, mut v) in lines(file).into_iter().enumerate() {
            for k in ["prev_entry_hash", "prev_segment_final_hash"] {
                if let Some(new) = v
                    .get(k)
                    .and_then(Value::as_str)
                    .and_then(|h| renamed.get(h))
                {
                    v[k] = new.clone().into();
                }
            }
            edit(f, i, &mut v);
            let old = v["entry_hash"].as_str().unwrap().to_string();
            let new = recompute_entry_hash(&v).unwrap();
            v["entry_hash"] = new.clone().into();
            if new != old {
                renamed.insert(old, new);
            }
            body += &(v.to_string() + "\n");
        }
        std::fs::write(file, body).unwrap();
    }
    if let Some(mut hw) = segments::read_hwm(path, b"", "test") {
        if let Some(new) = renamed.get(&hw.entry_hash) {
            hw.entry_hash = new.clone();
        }
        set_hwm(path, &hw);
    }
}

/// Rewrite the local `.hwm` (unsigned), as an attacker who controls the host.
fn set_hwm(path: &Path, hw: &HighWater) {
    let bytes = segments::encode_hwm(hw, b"", "test").unwrap();
    segments::write_hwm(path, &bytes, false).unwrap();
}

/// The local `.hwm` naming the last record of the active file.
fn hwm_at_tail(path: &Path) {
    let last = lines(path).pop().unwrap();
    let seq = segments::active_segment_seq(path, 0);
    set_hwm(
        path,
        &HighWater {
            counter: last["counter"].as_u64().unwrap(),
            entry_hash: last["entry_hash"].as_str().unwrap().to_string(),
            segment_seq: seq,
        },
    );
}

fn anchor_counter(anchor: &Path) -> u64 {
    let raw = std::fs::read_to_string(anchor).unwrap();
    raw.split('\t').next().unwrap().parse().unwrap()
}

/// A fresh unsigned log of `n` invocations; the logger is closed.
fn fresh(path: &Path, n: usize) {
    let l = logger(path, 12, false);
    for i in 0..n {
        append(&l, i);
    }
}

fn passes_without_anchor(path: &Path, mode: VerifyMode) {
    let r = verify_audit_log(path, &cfg(path, 12, false), mode, None).unwrap();
    assert!(r.ok, "the fixture must pass the checks that exist: {r:?}");
}

/// ANCHOR.EMPTY: `.hwm` deleted and the active file cut to empty reads as a
/// fresh log without an anchor (#2276).
#[test]
fn an_emptied_log_fails_against_its_anchor() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        fresh(&path, 5);
        let anchor = copy_anchor(&path, "anchor.hwm");
        std::fs::remove_file(sibling(&path, "hwm")).unwrap();
        std::fs::write(&path, "").unwrap();
        passes_without_anchor(&path, mode);
        let r = check(&path, &anchor, mode, false).unwrap();
        assert_fails(&r, anchor_counter(&anchor), "behind its anchor");
    }
}

/// ANCHOR.REPLACE: a same-length chain with other content, `.hwm` rewritten.
#[test]
fn a_replaced_log_fails_against_its_anchor() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        fresh(&path, 5);
        let anchor = copy_anchor(&path, "anchor.hwm");
        rechain(&path, |_, i, v| {
            if i >= 2 {
                v["note"] = "forged".into();
            }
        });
        passes_without_anchor(&path, mode);
        let r = check(&path, &anchor, mode, false).unwrap();
        assert_fails(&r, anchor_counter(&anchor), "not the anchored one");
    }
}

/// ANCHOR.ROLLBACK: the active file cut back and `.hwm` rewritten to match.
#[test]
fn a_rolled_back_log_fails_against_its_anchor() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        fresh(&path, 5);
        let anchor = copy_anchor(&path, "anchor.hwm");
        let kept: String = lines(&path)[..3]
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect();
        std::fs::write(&path, kept).unwrap();
        hwm_at_tail(&path);
        passes_without_anchor(&path, mode);
        let r = check(&path, &anchor, mode, false).unwrap();
        assert_fails(&r, anchor_counter(&anchor), "behind its anchor");
    }
}

/// ANCHOR.WIPED: every file gone is a failed verdict at the anchor, not an
/// IO error.
#[test]
fn a_wiped_log_fails_at_its_anchor() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        fresh(&path, 5);
        let anchor = copy_anchor(&path, "anchor.hwm");
        std::fs::remove_file(sibling(&path, "hwm")).unwrap();
        std::fs::remove_file(&path).unwrap();
        let none = verify_audit_log(&path, &cfg(&path, 12, false), mode, None);
        assert_eq!(none.unwrap_err().kind(), io::ErrorKind::NotFound);
        let r = check(&path, &anchor, mode, false).unwrap();
        assert_fails(&r, anchor_counter(&anchor), "behind its anchor");
    }
}

/// ANCHOR.OK: an older anchor, now in a sealed segment, and one at the tail
/// both pass an intact log.
#[test]
fn an_intact_log_passes_its_anchors() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = logger(&path, 12, false);
        for i in 0..3 {
            append(&l, i);
        }
        let older = copy_anchor(&path, "older.hwm");
        rotate_n(&l, &path, 1);
        append(&l, 0);
        let tail = copy_anchor(&path, "tail.hwm");
        for anchor in [&older, &tail] {
            let r = check(&path, anchor, mode, false).unwrap();
            assert!(r.ok, "{r:?}");
        }
    }
}

/// A retention-2 log whose segments 0..=2 expired, plus an anchor copied
/// after the first append (its counter now lies in an expired segment).
fn expired_log(path: &Path, signed: bool) -> PathBuf {
    let l = logger(path, 2, signed);
    append(&l, 0);
    let early = copy_anchor(path, "early.hwm");
    let mut spins = 0;
    while list_segments(path).unwrap().first().map(|s| s.seq) != Some(3) {
        append(&l, 0);
        spins += 1;
        assert!(spins < 5_000, "no expiry happened");
    }
    early
}

/// The oldest survivor's open record.
fn oldest_open(path: &Path) -> Value {
    let first = list_segments(path).unwrap()[0].path.clone();
    let open = lines(&first).remove(0);
    assert_eq!(event(&open), Some(rotation::EV_OPENED));
    open
}

/// An anchor at the expired boundary the oldest survivor links to, MAC'd
/// with `secret` when non-empty.
fn boundary_anchor(path: &Path, secret: &str) -> PathBuf {
    let open = oldest_open(path);
    let hw = HighWater {
        counter: open["counter"].as_u64().unwrap() - 1,
        entry_hash: open["prev_segment_final_hash"].as_str().unwrap().into(),
        segment_seq: open["prev_segment_seq"].as_u64().unwrap(),
    };
    write_anchor(path, "boundary.hwm", &hw, secret)
}

/// ANCHOR.EXPIRED: an anchor inside an expired range is refused. One at the
/// linked boundary passes only for a signed log: without HMAC an attacker
/// who wiped the log can forge an open record and an expiry record naming
/// the anchored counter and hash.
#[test]
fn an_anchor_in_an_expired_range_fails_and_the_boundary_needs_a_signed_log() {
    for (signed, secret) in [(false, ""), (true, SECRET)] {
        for mode in MODES {
            let dir = tempfile::tempdir().unwrap();
            let path = log_path(&dir);
            let early = expired_log(&path, signed);
            let config = cfg(&path, 12, signed);
            assert!(verify_audit_log(&path, &config, mode, None).unwrap().ok);
            let r = check(&path, &early, mode, signed).unwrap();
            assert_fails(&r, anchor_counter(&early), "predates the retained range");
            let boundary = boundary_anchor(&path, secret);
            let r = check(&path, &boundary, mode, signed).unwrap();
            if signed {
                assert!(r.ok, "{r:?}");
            } else {
                assert_fails(&r, anchor_counter(&boundary), "unsigned");
            }
        }
    }
}

/// LINK.SPLIT: the oldest survivor seeds its chain from `prev_entry_hash`
/// but links to the expired boundary through `prev_segment_final_hash`; a
/// legitimate log has them equal.
#[test]
fn an_oldest_survivor_split_from_its_link_fails() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        expired_log(&path, false);
        let boundary = boundary_anchor(&path, "");
        rechain(&path, |f, i, v| {
            if f == 0 && i == 0 {
                v["prev_entry_hash"] = format!("sha256:{}", "0".repeat(64)).into();
            }
        });
        let at = oldest_open(&path)["counter"].as_u64().unwrap();
        let r = verify_audit_log(&path, &cfg(&path, 12, false), mode, None).unwrap();
        assert_fails(&r, at, "links to final hash");
        let r = check(&path, &boundary, mode, false).unwrap();
        assert!(!r.ok, "{r:?}");
    }
}

/// The error an anchor file is refused with.
fn refused(path: &Path, anchor: &Path, mode: VerifyMode, signed: bool) -> io::Error {
    let e = check(path, anchor, mode, signed).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    e
}

/// ANCHOR.FORGED: a bad MAC, a torn, oversized, unparseable or missing
/// anchor is refused, never ignored.
#[test]
fn a_bad_anchor_file_is_refused() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = logger(&path, 12, true);
        for i in 0..3 {
            append(&l, i);
        }
        let good = std::fs::read(sibling(&path, "hwm")).unwrap();
        let mut bad_mac = good.clone();
        let end = bad_mac.iter().rposition(u8::is_ascii_hexdigit).unwrap();
        bad_mac[end] = if bad_mac[end] == b'0' { b'1' } else { b'0' };
        let mut oversized = good.clone();
        oversized.extend_from_slice(b"0123456789");
        let cases: [(&str, Vec<u8>); 4] = [
            ("bad-mac.hwm", bad_mac),
            ("torn.hwm", good[..good.len() - 1].to_vec()),
            ("oversized.hwm", oversized),
            ("garbage.hwm", vec![b'x'; segments::HWM_LEN]),
        ];
        for (name, bytes) in cases {
            let anchor = path.with_file_name(name);
            std::fs::write(&anchor, bytes).unwrap();
            let e = refused(&path, &anchor, mode, true);
            assert!(e.to_string().contains("anchor"), "{name}: {e}");
        }
        let gone = path.with_file_name("missing.hwm");
        assert!(
            refused(&path, &gone, mode, true)
                .to_string()
                .contains("anchor")
        );
        let ok = copy_anchor(&path, "good.hwm");
        assert!(check(&path, &ok, mode, true).unwrap().ok);
    }
}

/// ANCHOR.DOWNGRADE: a signed log stripped of every `sig`, its `.hwm`
/// rewritten unsigned, verified with no secret against the signed anchor.
/// The signed-entry check cannot fire (no `sig` is left), so only the
/// anchor's own MAC field shows the log was signed.
#[test]
fn a_signed_anchor_refuses_a_hash_only_verify() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = logger(&path, 12, true);
        for i in 0..3 {
            append(&l, i);
        }
        drop(l);
        let anchor = copy_anchor(&path, "signed.hwm");
        rechain(&path, |_, _, v| {
            let o = v.as_object_mut().unwrap();
            o.remove("sig");
            o.remove("key_id");
        });
        assert!(!log_contains_signed_entry(&path).unwrap());
        passes_without_anchor(&path, mode);
        let e = refused(&path, &anchor, mode, false);
        assert!(e.to_string().contains("signed"), "{e}");
    }
}

/// The forged-expiry attack on an unsigned log: wipe it, then write an open
/// record and an expiry record that name the anchored counter and hash as
/// the expired boundary, with a matching local `.hwm`.
#[test]
fn a_forged_expiry_boundary_does_not_satisfy_an_unsigned_anchor() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        fresh(&path, 5);
        let anchor = copy_anchor(&path, "anchor.hwm");
        let hw = segments::read_hwm(&path, b"", "test").unwrap();
        let config = cfg(&path, 12, false);
        let open = serde_json::json!({
            "event": rotation::EV_OPENED,
            "segment_seq": 1,
            "prev_segment_seq": 0,
            "prev_segment_final_hash": hw.entry_hash,
        });
        let expiry = serde_json::json!({
            "event": rotation::EV_EXPIRED,
            "segment_seq": 0,
            "last_counter": hw.counter,
            "final_hash": hw.entry_hash,
        });
        let (first, h1) = chain_line(
            &config,
            open.as_object().unwrap().clone(),
            hw.counter + 1,
            &hw.entry_hash,
        )
        .unwrap();
        let (second, _) = chain_line(
            &config,
            expiry.as_object().unwrap().clone(),
            hw.counter + 2,
            &h1,
        )
        .unwrap();
        std::fs::write(&path, format!("{first}\n{second}\n")).unwrap();
        hwm_at_tail(&path);
        passes_without_anchor(&path, mode);
        let r = check(&path, &anchor, mode, false).unwrap();
        assert_fails(&r, hw.counter, "unsigned");
    }
}

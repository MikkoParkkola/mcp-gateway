// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer's half of the signing anchor (`.sigstart`): when the logger
//! writes it, what it records, and the events an open writes. The reader's
//! half (what every reader then shows) is in the Activity sigstate rows.

use serde_json::Value;

use super::sigstart_fixture::{Fixture, events, write_v3};
use crate::security::audit::AuditEnvelope;

const REBUILT: &str = "audit_segment_sigstart_rebuilt";
const MIGRATED: &str = "audit_segment_sigstart_migrated";
const UNANCHORED: &str = "audit_segment_sigstart_unanchored";
const INVALID: &str = "audit_segment_sigstart_invalid";

/// The sidecar as JSON; panics when absent, so a row names what it expected.
fn sidecar(fx: &Fixture) -> Value {
    let raw = std::fs::read_to_string(fx.sidecar())
        .unwrap_or_else(|e| panic!("no .sigstart beside the log: {e}"));
    serde_json::from_str(raw.trim_end()).expect("the sidecar is one JSON object")
}

fn all_events(fx: &Fixture) -> [usize; 4] {
    [REBUILT, MIGRATED, UNANCHORED, INVALID].map(|e| events(&fx.path, e))
}

/// R9: a first start with a secret and no history writes an `open` sidecar
/// at the log's start, with no event; a log without a secret writes none.
#[test]
fn r9_first_start_writes_an_open_sidecar_without_an_event() {
    let fx = Fixture::new();
    let plain = fx.open(false, 0);
    Fixture::calls(&plain, 0, 2);
    assert!(!fx.sidecar().exists(), "no secret, no sidecar");
    drop(plain);

    let log = fx.open(true, 0);
    Fixture::calls(&log, 2, 2);
    let s = sidecar(&fx);
    assert_eq!(s["state"], "open");
    assert_eq!(
        all_events(&fx),
        [0, 0, 0, 0],
        "a first start is not an event"
    );
    // P sits after the two unsigned records written before the secret.
    let recs = fx.records();
    let first_signed = recs
        .iter()
        .find(|(_, v)| v.get("sig").is_some())
        .expect("a signed record");
    assert!(s["offset"].as_u64().unwrap() <= first_signed.0);
    assert!(
        recs.iter()
            .filter(|(_, v)| v.get("sig").is_none())
            .all(|(at, _)| *at < s["offset"].as_u64().unwrap()),
        "every unsigned record lies below P"
    );
}

/// R25 (lead condition 1): a v3.5.1 log migrates once: the anchor at its
/// first signed record, one migrated record; with the sidecar removed later,
/// the next open is the tamper branch, never a second migration.
#[test]
fn r25_a_v3_log_migrates_once() {
    let fx = Fixture::new();
    write_v3(&fx.path, 1, 2, 3);
    let first_signed = fx.records()[2].0;
    drop(fx.open(true, 0));
    let s = sidecar(&fx);
    assert_eq!(s["state"], "open");
    assert_eq!(s["offset"].as_u64(), Some(first_signed));
    assert_eq!(s["announced"], true);
    assert_eq!(all_events(&fx), [0, 1, 0, 0]);

    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["state"], "closed");
    assert_eq!(
        all_events(&fx),
        [1, 1, 0, 0],
        "a tamper event, no second migration"
    );
}

/// R27 (lead ruling): a v3 log whose head was trimmed is unanchored legacy:
/// one warning record, P at its first surviving signed record, flagged.
#[test]
fn r27_a_trimmed_v3_log_is_unanchored_legacy() {
    let fx = Fixture::new();
    write_v3(&fx.path, 40, 5, 6);
    let first_signed = fx.records()[5].0;
    drop(fx.open(true, 0));
    let s = sidecar(&fx);
    assert_eq!(s["state"], "open");
    assert_eq!(s["unanchored"], true);
    assert_eq!(s["offset"].as_u64(), Some(first_signed));
    assert_eq!(all_events(&fx), [0, 0, 1, 0]);
    drop(fx.open(true, 0));
    assert_eq!(
        all_events(&fx),
        [0, 0, 1, 0],
        "a second open writes nothing"
    );
}

/// R7 (condition 4b): a deleted sidecar on a signed v4 log is the tamper
/// branch: one rebuilt record, a `closed` sidecar, and nothing more after.
#[test]
fn r7_a_deleted_sidecar_rebuilds_closed_with_one_event() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["state"], "closed");
    assert_eq!(all_events(&fx), [1, 0, 0, 0]);
    drop(fx.open(true, 0));
    assert_eq!(
        all_events(&fx),
        [1, 0, 0, 0],
        "a closed sidecar raises nothing again"
    );
}

/// R23 (round 2 HI2): a caller cannot append a record named like one.
#[test]
fn r23_callers_cannot_forge_sigstart_records() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    for event in [REBUILT, MIGRATED, UNANCHORED, INVALID] {
        let mut fields = serde_json::Map::new();
        fields.insert("event".into(), event.into());
        assert!(
            log.append_event(fields, &AuditEnvelope::gateway()).is_err(),
            "{event} was accepted"
        );
    }
}

/// R6 (condition 4a), writer half: a sidecar edited to point later keeps
/// its old MAC, so it is broken: the open raises the invalid record and
/// leaves the file byte-identical as evidence (Q1).
#[test]
fn r6_an_edited_sidecar_is_kept_and_raised() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    let mut s = sidecar(&fx);
    s["offset"] = (s["offset"].as_u64().unwrap() + 400).into();
    let edited = s.to_string() + "\n";
    std::fs::write(fx.sidecar(), &edited).unwrap();
    drop(fx.open(true, 0));
    assert_eq!(all_events(&fx), [0, 0, 0, 1]);
    assert_eq!(std::fs::read_to_string(fx.sidecar()).unwrap(), edited);
}

/// R10: every signature stripped and the sidecar deleted, but `.hwm` still
/// carries a valid MAC: the tamper branch, with `signed_found: false`.
#[test]
fn r10_strip_all_with_a_keyed_hwm_is_tamper() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    assert!(fx.hwm().exists());
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        super::sigstart_fixture::strip_sig(&mut v);
        out.push_str(&(v.to_string() + "\n"));
    }
    std::fs::write(&fx.path, out).unwrap();
    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["state"], "closed");
    let rebuilt: Vec<Value> = fx
        .records()
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| v.get("event").and_then(Value::as_str) == Some(REBUILT))
        .collect();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0]["signed_found"], false);
}

/// R26 (lead condition 3): a rotated v4 log with its open records, `.hwm`
/// and `.sigstart` deleted is tampered, never migrated or unanchored: v3
/// never wrote v4 segment files.
#[test]
fn r26_a_rotated_v4_log_with_files_deleted_is_tamper() {
    let fx = Fixture::new();
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 0, 12);
    drop(log);
    let sealed = crate::security::transparency_log::segments::list_segments(&fx.path).unwrap();
    assert!(!sealed.is_empty(), "the fixture rotated");
    for file in sealed
        .iter()
        .map(|s| s.path.clone())
        .chain([fx.path.clone()])
    {
        let text = std::fs::read_to_string(&file).unwrap();
        let kept: String = text
            .lines()
            .filter(|l| {
                !l.contains("\"audit_segment_opened\"") && !l.contains("\"audit_log_identified\"")
            })
            .flat_map(|l| [l, "\n"])
            .collect();
        std::fs::write(&file, kept).unwrap();
    }
    std::fs::remove_file(fx.hwm()).unwrap();
    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 1024));
    assert_eq!(sidecar(&fx)["state"], "closed");
    assert_eq!(all_events(&fx), [1, 0, 0, 0]);
}

/// R22 (round 2 H2, round 3 J5): enabling the secret on an unsigned log
/// with a torn last line is a first start, not tamper: the repair's own
/// signed record lies below P.
#[test]
fn r22_first_signing_after_a_torn_tail_is_a_first_start() {
    let fx = Fixture::new();
    let plain = fx.open(false, 0);
    Fixture::calls(&plain, 0, 3);
    drop(plain);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&fx.path)
        .unwrap();
    std::io::Write::write_all(&mut f, b"{\"torn\":").unwrap();
    drop(f);
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["state"], "open");
    assert_eq!(all_events(&fx), [0, 0, 0, 0]);
}

use super::sigstart::{self, Fault, LegacyFile, SigStart, State};

fn body(offset: u64, legacy: Vec<LegacyFile>) -> SigStart {
    SigStart {
        log_id: "id".into(),
        state: State::Open,
        segment_seq: 0,
        offset,
        counter: 3,
        legacy,
        unanchored: false,
        announced: true,
    }
}

/// R14 (round 3 J6): encode/decode round trip; torn, garbled, extended and
/// wrong-key bytes are refused; the log id is outside the MAC (round 3 J4).
#[test]
fn r14_sidecar_bytes_round_trip_and_refuse_damage() {
    let secret = super::sigstart_fixture::SECRET.as_bytes();
    let b = body(10, Vec::new());
    let bytes = sigstart::encode(&b, secret).unwrap();
    assert_eq!(sigstart::decode(&bytes, secret), Ok(b.clone()));
    assert_eq!(
        sigstart::decode(&bytes[..bytes.len() - 2], secret),
        Err(Fault::Torn)
    );
    assert_eq!(sigstart::decode(b"{not json}\n", secret), Err(Fault::Torn));
    let mut extended = bytes.clone();
    extended.extend_from_slice(b"{}\n");
    assert_eq!(sigstart::decode(&extended, secret), Err(Fault::Torn));
    assert_eq!(sigstart::decode(&bytes, b"another-secret"), Err(Fault::Mac));
    // A changed log id still verifies; a changed offset does not.
    let text = String::from_utf8(bytes).unwrap();
    let renamed = text.replace("\"log_id\":\"id\"", "\"log_id\":\"other\"");
    assert!(sigstart::decode(renamed.as_bytes(), secret).is_ok());
    let moved = text.replace("\"offset\":10", "\"offset\":11");
    assert_eq!(sigstart::decode(moved.as_bytes(), secret), Err(Fault::Mac));
}

/// A one-file log whose first `p` bytes are legacy, frozen.
#[cfg(feature = "webui")]
fn frozen(fx: &Fixture, bytes: &[u8], p: u64) -> super::sigstart::Anchor {
    use super::sigstart::{Anchor, CHUNK};
    std::fs::write(&fx.path, bytes).unwrap();
    let chunks = (0..p.div_ceil(CHUNK))
        .map(|i| {
            let s = usize::try_from(i * CHUNK).unwrap();
            let e = usize::try_from(((i + 1) * CHUNK).min(p)).unwrap();
            hex::encode(super::sha256_raw(&bytes[s..e]))
        })
        .collect();
    Anchor::Known(body(
        p,
        vec![LegacyFile {
            seq: 0,
            len: p,
            chunks,
        }],
    ))
}

/// R24 (round 2 HI1): positions P-1, P and P+1 against an anchor at P.
#[cfg(feature = "webui")]
#[test]
fn r24_the_boundary_is_at_p() {
    use super::sigstart::{Checked, LinePos, Placed};
    let fx = Fixture::new();
    let a = frozen(&fx, &[b'x'; 64], 32);
    let at = |offset| LinePos::At {
        segment: 0,
        offset,
        len: 1,
    };
    let mut c = Checked::default();
    assert_eq!(
        a.place(&fx.path, at(31), &mut c),
        Placed::Legacy { unanchored: false }
    );
    assert_eq!(
        a.place(&fx.path, at(32), &mut c),
        Placed::Invalid("sig_missing")
    );
    assert_eq!(
        a.place(&fx.path, at(33), &mut c),
        Placed::Invalid("sig_missing")
    );
    // A line that starts below P but runs past it is not legacy (round 3 J1).
    let crossing = LinePos::At {
        segment: 0,
        offset: 30,
        len: 4,
    };
    assert_eq!(
        a.place(&fx.path, crossing, &mut c),
        Placed::Invalid("legacy_unlisted")
    );
}

/// R31 (round 3 J7): a record near the end of a 5 MiB legacy range hashes
/// only the chunks its line touches, and classifies without the rest.
#[cfg(feature = "webui")]
#[test]
fn r31_a_large_legacy_file_hashes_only_the_touched_chunks() {
    use super::sigstart::{CHUNK, Checked, LinePos, Placed};
    let fx = Fixture::new();
    let p = 5 * CHUNK;
    let a = frozen(&fx, &vec![b'y'; usize::try_from(p).unwrap()], p);
    let mut c = Checked::default();
    let near_end = LinePos::At {
        segment: 0,
        offset: p - CHUNK / 2,
        len: 100,
    };
    assert_eq!(
        a.place(&fx.path, near_end, &mut c),
        Placed::Legacy { unanchored: false }
    );
    assert_eq!(c.hashed(), 1, "one chunk hashed, not five");
}

// ── Crash rows: a child opens the signed log and aborts at a boundary ──────

const SIG_KILL_AT: &str = "MCP_GW_TEST_SIGSTART_KILL_AT";
const SIG_KILL_DIR: &str = "MCP_GW_TEST_SIGSTART_KILL_DIR";
const SIG_MARKER: &str = "killed";

/// Open the signed log in `fx` in a child killed at `at`; assert it died
/// there (a marker, and no clean exit).
fn open_killed_at(fx: &Fixture, at: super::kill::At) {
    let dir = fx.path.parent().unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "security::transparency_log::sigstart_tests::sigstart_child",
            "--ignored",
            "--nocapture",
        ])
        .env(SIG_KILL_AT, format!("{at:?}"))
        .env(SIG_KILL_DIR, dir)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the child exited cleanly instead of aborting at {at:?}"
    );
    assert!(
        dir.join(SIG_MARKER).exists(),
        "the child never reached {at:?}:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_file(dir.join(SIG_MARKER)).unwrap();
}

#[test]
#[ignore = "run by the sigstart crash rows, in a child that aborts"]
fn sigstart_child() {
    use super::kill::{self, At};
    let (Ok(at), Some(dir)) = (std::env::var(SIG_KILL_AT), std::env::var_os(SIG_KILL_DIR)) else {
        return;
    };
    let at = match at.as_str() {
        "AfterSigstart" => At::AfterSigstart,
        "BeforeAnnounce" => At::BeforeAnnounce,
        other => panic!("no such boundary: {other}"),
    };
    let dir = std::path::PathBuf::from(dir);
    kill::arm(at, dir.join(SIG_MARKER));
    let fx = Fixture::at(dir.join("audit.jsonl"));
    drop(fx.open(true, 0));
}

/// R13: killed after an `open` sidecar is published on a first start,
/// before the open record: the reopen keeps it and raises nothing.
#[test]
fn r13_a_kill_after_the_first_start_sidecar_keeps_it() {
    let fx = Fixture::new();
    let plain = fx.open(false, 0);
    Fixture::calls(&plain, 0, 2);
    drop(plain);
    open_killed_at(&fx, super::kill::At::AfterSigstart);
    let before = std::fs::read(fx.sidecar()).expect("published before the kill");
    drop(fx.open(true, 0));
    assert_eq!(
        std::fs::read(fx.sidecar()).unwrap(),
        before,
        "kept, not rebuilt"
    );
    assert_eq!(all_events(&fx), [0, 0, 0, 0]);
}

/// R13b (round 1 G5, round 3 J4): a genesis killed after its sidecar and
/// before its open record re-mints its id on reopen; the sidecar still
/// verifies (no id in the MAC), so nothing is raised.
#[test]
fn r13b_a_genesis_kill_does_not_break_the_sidecar() {
    let fx = Fixture::new();
    open_killed_at(&fx, super::kill::At::AfterSigstart);
    assert!(fx.sidecar().exists());
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 1);
    drop(log);
    assert_eq!(sidecar(&fx)["state"], "open");
    assert_eq!(all_events(&fx), [0, 0, 0, 0]);
}

/// R30 (round 3 J3): killed after the `closed` sidecar, before its rebuilt
/// record: the next open writes the record and marks it announced; the one
/// after writes nothing.
#[test]
fn r30_a_kill_before_the_announce_retries_the_event_once() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    std::fs::remove_file(fx.sidecar()).unwrap();
    open_killed_at(&fx, super::kill::At::BeforeAnnounce);
    assert_eq!(sidecar(&fx)["announced"], false);
    assert_eq!(all_events(&fx), [0, 0, 0, 0]);
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["announced"], true);
    assert_eq!(all_events(&fx), [1, 0, 0, 0]);
    drop(fx.open(true, 0));
    assert_eq!(all_events(&fx), [1, 0, 0, 0]);
}

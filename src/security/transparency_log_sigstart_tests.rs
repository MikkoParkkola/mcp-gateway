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
    // The anchor's own file is frozen up to the anchor, not to its end: the
    // signed records above P are judged by their signatures.
    assert_eq!(s["legacy"][0]["len"].as_u64(), Some(first_signed));
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
    // P is taken after the repair: it falls on a line start, every unsigned
    // record lies below it, and every record this open wrote after it (the
    // missing-mark record an unkeyed `.hwm` causes) is signed.
    let p = sidecar(&fx)["offset"].as_u64().unwrap();
    let recs = fx.records();
    assert!(recs.iter().any(|(at, _)| *at == p), "P {p} is a line start");
    for (at, v) in &recs {
        let signed = v.get("sig").is_some();
        // The repair's own record, if it wrote one, sits below P, frozen.
        let repair = v["event"] == "audit_segment_torn_tail_dropped";
        assert!(
            signed == (*at >= p) || (repair && *at < p),
            "record at {at} vs P {p}: {v}"
        );
    }
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
        signed_found: true,
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

/// A one-file log of JSON lines `{"n":i}` padded to `width` bytes each
/// (newline included), its first `p` bytes frozen as legacy.
#[cfg(feature = "webui")]
fn frozen(fx: &Fixture, lines: usize, width: usize, p: u64) -> super::sigstart::Anchor {
    use super::sigstart::{Anchor, CHUNK};
    let mut bytes = Vec::new();
    for i in 0..lines {
        let mut l = format!("{{\"n\":{i}}}");
        l.push_str(&" ".repeat(width - 1 - l.len()));
        l.push('\n');
        bytes.extend_from_slice(l.as_bytes());
    }
    std::fs::write(&fx.path, &bytes).unwrap();
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

/// Line `i` of a [`frozen`] file: its position (newline excluded) and record.
#[cfg(feature = "webui")]
fn nth(i: u64, width: u64) -> (super::sigstart::LinePos, serde_json::Value) {
    let pos = super::sigstart::LinePos::At {
        segment: 0,
        offset: i * width,
        len: width - 1,
    };
    (pos, serde_json::json!({ "n": i }))
}

/// R24 (round 2 HI1): positions before, at and after P, with P on a line
/// boundary; a line crossing P is not legacy (round 3 J1).
#[cfg(feature = "webui")]
#[test]
fn r24_the_boundary_is_at_p() {
    use super::sigstart::{Checked, LinePos, Placed};
    let fx = Fixture::new();
    let a = frozen(&fx, 8, 16, 64);
    let mut c = Checked::default();
    let (before, e3) = nth(3, 16);
    assert_eq!(
        a.place(&fx.path, before, &e3, &mut c),
        Placed::Legacy { unanchored: false }
    );
    let (at_p, e4) = nth(4, 16);
    assert_eq!(
        a.place(&fx.path, at_p, &e4, &mut c),
        Placed::Invalid("sig_missing")
    );
    let (after, e5) = nth(5, 16);
    assert_eq!(
        a.place(&fx.path, after, &e5, &mut c),
        Placed::Invalid("sig_missing")
    );
    let crossing = LinePos::At {
        segment: 0,
        offset: 48,
        len: 20,
    };
    assert_eq!(
        a.place(&fx.path, crossing, &e3, &mut c),
        Placed::Invalid("legacy_unlisted")
    );
}

/// R38 (code review C2): a record the reader serves must be the one in the
/// verified bytes: the right position with another record is an edit.
#[cfg(feature = "webui")]
#[test]
fn r38_the_served_record_must_be_the_verified_one() {
    use super::sigstart::{Checked, Placed};
    let fx = Fixture::new();
    let a = frozen(&fx, 8, 16, 64);
    let mut c = Checked::default();
    let (pos, _) = nth(2, 16);
    let forged = serde_json::json!({ "n": 99 });
    assert_eq!(
        a.place(&fx.path, pos, &forged, &mut c),
        Placed::Invalid("legacy_edited")
    );
}

/// R31 (round 3 J7): a record near the end of a 5 MiB legacy range hashes
/// only the chunk its line sits in.
#[cfg(feature = "webui")]
#[test]
fn r31_a_large_legacy_file_hashes_only_the_touched_chunks() {
    use super::sigstart::{CHUNK, Checked, Placed};
    let fx = Fixture::new();
    let width = 64_u64;
    let lines = 5 * CHUNK / width;
    let a = frozen(&fx, usize::try_from(lines).unwrap(), 64, lines * width);
    let mut c = Checked::default();
    let (pos, e) = nth(lines - 10, width);
    assert_eq!(
        a.place(&fx.path, pos, &e, &mut c),
        Placed::Legacy { unanchored: false }
    );
    assert_eq!(c.hashed(), 1, "one chunk hashed, not five");
}

/// R42 (code review): an edited chunk is hashed once per request; every
/// other row in it fails closed from memory, not by re-reading the chunk.
#[cfg(feature = "webui")]
#[test]
fn r42_an_edited_chunk_is_hashed_once() {
    use super::sigstart::{Checked, Placed};
    let fx = Fixture::new();
    let a = frozen(&fx, 8, 16, 128);
    // Edit a byte inside the frozen range: the chunk's digest now differs.
    let mut bytes = std::fs::read(&fx.path).unwrap();
    bytes[5] = b'9';
    std::fs::write(&fx.path, &bytes).unwrap();
    let mut c = Checked::default();
    for i in 1..8 {
        let (pos, e) = nth(i, 16);
        assert_eq!(
            a.place(&fx.path, pos, &e, &mut c),
            Placed::Invalid("legacy_edited"),
            "row {i}"
        );
    }
    assert_eq!(c.hashed(), 1, "the failed chunk is remembered");
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
/// verifies (its stored id is never compared with the log's), so nothing is
/// raised. R14 pins that the id is outside the MAC.
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

/// The `segment_seq` the active file's open record names.
fn active_seq(fx: &Fixture) -> u64 {
    fx.records()
        .iter()
        .find(|(_, v)| v["event"] == "audit_segment_opened")
        .and_then(|(_, v)| v["segment_seq"].as_u64())
        .expect("an open record")
}

/// R15 (b): a first start's predicted seq is the seq `reopen_tail` gives the
/// new active file, for a genesis and for a log whose active file is gone
/// (q17).
#[test]
fn r15b_the_predicted_seq_is_the_new_active_files() {
    let fx = Fixture::new();
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["segment_seq"].as_u64(), Some(active_seq(&fx)));

    let fx = Fixture::new();
    let plain = fx.open(false, 1024);
    Fixture::calls(&plain, 0, 12);
    drop(plain);
    assert!(!super::segments::list_segments(&fx.path).unwrap().is_empty());
    std::fs::remove_file(&fx.path).unwrap();
    drop(fx.open(true, 1024));
    assert_eq!(sidecar(&fx)["segment_seq"].as_u64(), Some(active_seq(&fx)));
    assert_eq!(sidecar(&fx)["offset"], 0);
}

/// R36: an unrotated v4 log with its identity records and `.sigstart`
/// deleted but its `.hwm` kept is tampered: v3.5.1 never wrote `.hwm`, so
/// the migration shape does not hold (q27).
#[test]
fn r36_a_kept_hwm_rules_out_the_v3_shape() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    assert!(fx.hwm().exists());
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let kept: String = text
        .lines()
        .filter(|l| {
            !l.contains("\"audit_segment_opened\"") && !l.contains("\"audit_log_identified\"")
        })
        .flat_map(|l| [l, "\n"])
        .collect();
    std::fs::write(&fx.path, kept).unwrap();
    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 0));
    assert_eq!(sidecar(&fx)["state"], "closed");
}

/// R30 (b) (code review M5): a keyed-`.hwm`-only rebuild killed before its
/// record still reports `signed_found: false` when the next open writes it.
#[test]
fn r30b_a_delayed_rebuilt_record_keeps_signed_found() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 3);
    drop(log);
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        super::sigstart_fixture::strip_sig(&mut v);
        out.push_str(&(v.to_string() + "\n"));
    }
    std::fs::write(&fx.path, out).unwrap();
    std::fs::remove_file(fx.sidecar()).unwrap();
    open_killed_at(&fx, super::kill::At::BeforeAnnounce);
    assert_eq!(all_events(&fx), [0, 0, 0, 0]);
    drop(fx.open(true, 0));
    let rebuilt: Vec<Value> = fx
        .records()
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| v["event"] == REBUILT)
        .collect();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0]["signed_found"], false);
}

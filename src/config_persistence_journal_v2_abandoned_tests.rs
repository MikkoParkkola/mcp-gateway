// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Frame rows: each reports its cases one by one instead of stopping at the first.

use super::super::fixtures::{AUDIT_WHO_PRINCIPAL, collect_case};
use super::super::{IntentId, JournalV2, ParkReason, TokenState};
use super::fixtures::{
    ATTRIBUTION_JSON, HANDED_OVER_JSON, HANDED_OVER_LEN, HANDED_OVER_SHA, RECORD_0_JSON,
    RECORD_0_LEN, attributed_journal, attribution, donor, file, frame_bytes, handed_over, parked,
    record_0, record_1, reframe, root,
};
use super::{
    Cause, FrameFault, Inspection, OwnerFacts, Slot, Tail, canonical_frames, decode_frames,
    encode_frame, inspect,
};
use crate::security::audit::AuditWho;
use crate::security::transparency_log::settle::{Attribution, IntentKind, Role};

fn writer() -> IntentId {
    IntentId("writer-1".to_owned())
}

#[test]
fn golden_abandoned_attribution_decode() {
    const ROW: &str = "golden_abandoned_attribution_decode";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "decode_and_re_encode",
        "exact actor with its principal, stable frame bytes",
        || {
            let bytes = attribution();
            let read = decode_frames(&bytes).expect(ROW);
            assert_eq!(read.tail, Tail::Clean, "{ROW}: the whole file is consumed");
            assert_eq!(read.frames.len(), 1, "{ROW}: one frame");
            let frame = &read.frames[0];
            assert_eq!(frame.intent_id, writer(), "{ROW}: token");
            assert_eq!(frame.slot, Slot::Intent, "{ROW}: slot");
            assert_eq!(
                frame.log_id.as_str(),
                "opaque-log:fixture",
                "{ROW}: binding"
            );
            assert_eq!(
                frame.record.role,
                Role::Intent(IntentKind::KeyCreate),
                "{ROW}: role"
            );
            let actor = AuditWho::from_persisted(AUDIT_WHO_PRINCIPAL).expect(ROW);
            assert_eq!(
                frame.record.attribution,
                Some(Attribution { actor }),
                "{ROW}: the actor, principal included"
            );
            assert_eq!(
                frame.record.payload_json,
                br#"{"kind":"settle.key_create","subject":"deploy-bot"}"#.to_vec(),
                "{ROW}: the key name stays in the payload"
            );
            assert_eq!(
                frame.owner,
                Some(OwnerFacts {
                    decision: None,
                    handed_over: false,
                    intent_counter: None,
                    root: false,
                }),
                "{ROW}: owner facts"
            );
            assert_eq!(
                encode_frame(frame).expect(ROW),
                bytes,
                "{ROW}: re-encoding gives the golden bytes"
            );
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "invalid_principal",
        "a principal the persisted decoder rejects is a field fault",
        || {
            let broken = ATTRIBUTION_JSON.replace("0123ab45cd67", "0123AB45CD678");
            assert_eq!(
                decode_frames(&reframe(&broken)).map(|read| read.frames.len()),
                Err(FrameFault::Field),
                "{ROW}: never admitted unvalidated"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn golden_abandoned_root_decode() {
    const ROW: &str = "golden_abandoned_root_decode";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "root_marker_survives",
        "version, root marker and no settles retained exactly",
        || {
            let bytes = root();
            let read = decode_frames(&bytes).expect(ROW);
            assert_eq!(read.frames.len(), 1, "{ROW}: one frame");
            let frame = &read.frames[0];
            assert_eq!(
                frame.intent_id,
                IntentId("attempt-1".to_owned()),
                "{ROW}: token"
            );
            assert_eq!(frame.record.role, Role::RecoveryIntent, "{ROW}: role");
            assert_eq!(
                frame.owner.as_ref().map(|owner| owner.root),
                Some(true),
                "{ROW}: the root marker"
            );
            let payload = String::from_utf8(frame.record.payload_json.clone()).expect(ROW);
            assert!(
                !payload.contains("settles"),
                "{ROW}: a root names no settles"
            );
            assert_eq!(
                encode_frame(frame).expect(ROW),
                bytes,
                "{ROW}: stable bytes"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn golden_abandoned_parked_decode() {
    const ROW: &str = "golden_abandoned_parked_decode";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "parked_state_survives",
        "reason, rejected bytes and the false delivered flag retained exactly",
        || {
            let bytes = parked();
            let read = decode_frames(&bytes).expect(ROW);
            assert_eq!(read.frames.len(), 1, "{ROW}: one frame");
            let record = &read.frames[0].record;
            assert_eq!(
                record.parked,
                Some(ParkReason::InvalidPayload),
                "{ROW}: reason"
            );
            assert_eq!(
                record.payload_json,
                b"{invalid".to_vec(),
                "{ROW}: the rejected bytes are not parsed as JSON"
            );
            assert!(!record.delivered, "{ROW}: a parked record is not delivered");
            assert_eq!(
                encode_frame(&read.frames[0]).expect(ROW),
                bytes,
                "{ROW}: stable bytes"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn golden_abandoned_handed_over_decode() {
    const ROW: &str = "golden_abandoned_handed_over_decode";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "transferred_ownership_survives",
        "frame identity and bytes retained; the donor stays handed over",
        || {
            let bytes = handed_over();
            let read = decode_frames(&bytes).expect(ROW);
            let frame = &read.frames[0];
            assert_eq!(
                frame.owner.as_ref().map(|owner| owner.handed_over),
                Some(true),
                "{ROW}: transferred ownership"
            );
            let donor = donor();
            let token = donor.writer.as_ref().expect(ROW);
            assert!(token.handed_over, "{ROW}: the donor stays handed over");
            assert_eq!(frame.intent_id, token.intent_id, "{ROW}: the donor's token");
            assert_eq!(
                frame.record, token.intent,
                "{ROW}: the donor's intent record"
            );
            assert_eq!(
                encode_frame(frame).expect(ROW),
                bytes,
                "{ROW}: stable bytes"
            );
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "token_with_two_more_records",
        "every record keeps its own delivered flag and slot",
        || {
            let bytes = file(&[&handed_over(), &record_0(), &record_1()]);
            let read = decode_frames(&bytes).expect(ROW);
            assert_eq!(read.tail, Tail::Clean, "{ROW}: whole file consumed");
            let slots: Vec<_> = read.frames.iter().map(|frame| frame.slot).collect();
            assert_eq!(
                slots,
                vec![Slot::Intent, Slot::Record(0), Slot::Record(1)],
                "{ROW}: slots in order"
            );
            let delivered: Vec<_> = read.frames.iter().map(|f| f.record.delivered).collect();
            assert_eq!(
                delivered,
                vec![false, true, false],
                "{ROW}: delivered flags"
            );
            let donor = donor();
            let token = donor.writer.as_ref().expect(ROW);
            assert_eq!(
                read.frames[1].record, token.records[0],
                "{ROW}: first record"
            );
            assert_eq!(
                read.frames[2].record, token.records[1],
                "{ROW}: second record"
            );
            assert_eq!(
                canonical_frames(&donor),
                vec![
                    (writer(), Slot::Intent),
                    (writer(), Slot::Record(0)),
                    (writer(), Slot::Record(1)),
                ],
                "{ROW}: the donor's canonical sequence"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn attribution_round_trip() {
    const ROW: &str = "attribution_round_trip";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "journal_and_frame_agree",
        "the same Some(Attribution { actor }) at every hop",
        || {
            let journal = attributed_journal();
            let from_journal = journal
                .writer
                .as_ref()
                .expect(ROW)
                .intent
                .attribution
                .clone();
            assert!(
                from_journal.is_some(),
                "{ROW}: the journal carries the actor"
            );
            let read = decode_frames(&attribution()).expect(ROW);
            let frame = &read.frames[0];
            assert_eq!(
                frame.record.attribution, from_journal,
                "{ROW}: journal to frame"
            );
            let again = decode_frames(&encode_frame(frame).expect(ROW)).expect(ROW);
            assert_eq!(
                again.frames[0].record.attribution, from_journal,
                "{ROW}: frame to frame"
            );
            let reopened =
                super::super::JournalV2::decode(&journal.encode().expect(ROW)).expect(ROW);
            assert_eq!(
                reopened.writer.as_ref().expect(ROW).intent.attribution,
                from_journal,
                "{ROW}: journal to journal"
            );
            let wire: serde_json::Value = serde_json::from_str(ATTRIBUTION_JSON).expect(ROW);
            let keys: Vec<_> = wire.as_object().expect(ROW).keys().cloned().collect();
            assert_eq!(
                keys,
                ["log_id", "owner", "record", "slot", "token", "v"],
                "{ROW}: no envelope subject beside the actor"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

/// The first `n` bytes of a frame: a tail torn mid-frame.
fn torn(frame: &[u8], n: usize) -> Vec<u8> {
    frame[..n].to_vec()
}

fn corrupt(at: usize, cause: Cause) -> Inspection {
    Inspection::Corrupt { at, cause }
}

fn tail_without_donor() {
    let (first, second) = (handed_over(), record_0());
    let bytes = file(&[&first, &torn(&second, 10)]);
    let read = decode_frames(&bytes).expect("a torn tail is not a fault");
    assert_eq!(
        read.tail,
        Tail::Incomplete { start: first.len() },
        "the tail starts where the torn frame starts"
    );
    assert_eq!(
        inspect(&bytes, None),
        corrupt(1, Cause::TailWithoutDonor),
        "no donor: never repairable"
    );
}

fn complete_corrupt_frames() {
    let (first, second, third) = (handed_over(), record_0(), record_1());
    let bad_sum = frame_bytes(RECORD_0_JSON, RECORD_0_LEN, &"0".repeat(64));
    let donor = donor();
    for donor in [None, Some(&donor)] {
        let middle = file(&[&first, &bad_sum, &third]);
        assert_eq!(
            inspect(&middle, donor),
            corrupt(1, Cause::Wire(FrameFault::Checksum)),
            "a corrupt middle frame, donor {}",
            donor.is_some()
        );
        let last = file(&[&first, &second, &bad_sum]);
        assert_eq!(
            inspect(&last, donor),
            corrupt(2, Cause::Wire(FrameFault::Checksum)),
            "a corrupt final frame, donor {}",
            donor.is_some()
        );
        let not_json = file(&[&first, &reframe("not json at all")]);
        assert_eq!(
            inspect(&not_json, donor),
            corrupt(1, Cause::Wire(FrameFault::Json)),
            "a checksum-valid frame that is not JSON, donor {}",
            donor.is_some()
        );
    }
}

fn altered_frames_match_no_donor() {
    let donor = donor();
    let tail = torn(&record_0(), 10);
    let variants = [
        ("delivered", r#""delivered":false"#, r#""delivered":true"#),
        (
            "parked",
            r#""parked":null"#,
            r#""parked":"invalid_payload""#,
        ),
        (
            "caller digest",
            r#""caller_digest":"8db5"#,
            r#""caller_digest":"9db5"#,
        ),
        (
            "payload bytes",
            r#""payload_json":[123,34,107"#,
            r#""payload_json":[123,34,108"#,
        ),
        (
            "role",
            r#""role":"config_save_intent""#,
            r#""role":"config_recovery_intent""#,
        ),
        (
            "owner facts",
            r#""intent_counter":null"#,
            r#""intent_counter":7"#,
        ),
        (
            "binding",
            r#""log_id":"opaque-log:fixture""#,
            r#""log_id":"opaque-log:other""#,
        ),
    ];
    for (what, from, to) in variants {
        assert!(
            HANDED_OVER_JSON.contains(from),
            "the {what} variant must change the golden"
        );
        let altered = reframe(&HANDED_OVER_JSON.replace(from, to));
        let bytes = file(&[&altered, &tail]);
        assert_eq!(
            inspect(&bytes, Some(&donor)),
            corrupt(0, Cause::DonorMismatch),
            "a checksum-valid frame differing only in its {what}"
        );
    }
}

fn unrelated_owner_proves_nothing() {
    let mut state: JournalV2 = donor();
    let writer = state.writer.as_mut().expect("writer");
    writer.handed_over = false;
    let attempt = TokenState {
        intent_id: IntentId("attempt-1".to_owned()),
        intent: writer.intent.clone(),
        intent_counter: None,
        decision: None,
        records: Vec::new(),
        handed_over: true,
    };
    state.attempts.push(attempt);
    // The intent frame honestly says "not handed over", as the donor's writer is: the owner
    // facts then agree, and only the writer's own handed-over flag can refuse the tail.
    let honest = HANDED_OVER_JSON.replace(r#""handed_over":true"#, r#""handed_over":false"#);
    assert_ne!(
        honest, HANDED_OVER_JSON,
        "the control must change the golden"
    );
    let bytes = file(&[&reframe(&honest), &torn(&record_0(), 10)]);
    assert_eq!(
        inspect(&bytes, Some(&state)),
        corrupt(0, Cause::DonorMismatch),
        "another owner's handover does not prove this token's"
    );
}

fn early_newline_is_a_length_fault() {
    // Declared longer than the JSON that precedes the newline: a complete corrupt frame,
    // never a torn tail, so a matching donor must not make it repairable.
    let longer = frame_bytes(HANDED_OVER_JSON, HANDED_OVER_LEN + 5, HANDED_OVER_SHA);
    let bytes = file(&[&handed_over(), &longer]);
    assert_eq!(
        decode_frames(&bytes).map(|read| read.frames.len()),
        Err(FrameFault::Length),
        "decode"
    );
    let donor = donor();
    assert_eq!(
        inspect(&bytes, Some(&donor)),
        corrupt(1, Cause::Wire(FrameFault::Length)),
        "inspect with a matching donor"
    );
}

fn newline_in_a_header_field_is_a_length_fault() {
    // A newline ends the header line: a later tab must not pull the lines together into one
    // torn header, or a donor could license repair of a corrupt file.
    let donor = donor();
    for (what, bytes) in [
        ("in the checksum", b"100\tbad\n5\t".as_slice()),
        ("in the length", b"10\n0\tbad\t".as_slice()),
        ("right after the length", b"100\n5\t".as_slice()),
    ] {
        let mut with_prefix = handed_over();
        with_prefix.extend_from_slice(bytes);
        for (label, bytes) in [("alone", bytes.to_vec()), ("after a frame", with_prefix)] {
            assert_eq!(
                decode_frames(&bytes).map(|read| read.frames.len()),
                Err(FrameFault::Length),
                "decode {what} {label}"
            );
            assert!(
                matches!(
                    inspect(&bytes, Some(&donor)),
                    Inspection::Corrupt {
                        cause: Cause::Wire(FrameFault::Length),
                        ..
                    }
                ),
                "inspect {what} {label}"
            );
        }
    }
}

fn over_cap_is_refused_before_allocation() {
    let header = format!("99999999\t{HANDED_OVER_SHA}\t{HANDED_OVER_JSON}\n");
    assert_eq!(
        decode_frames(header.as_bytes()).map(|read| read.frames.len()),
        Err(FrameFault::Length),
        "an over-cap declared length is a length fault"
    );
    assert_eq!(
        inspect(header.as_bytes(), None),
        corrupt(0, Cause::Wire(FrameFault::Length)),
        "inspect agrees"
    );
    // No newline in the body: only the cap, not the early-newline rule, can refuse it.
    let unterminated = format!("99999999\t{HANDED_OVER_SHA}\t{HANDED_OVER_JSON}");
    assert_eq!(
        decode_frames(unterminated.as_bytes()).map(|read| read.frames.len()),
        Err(FrameFault::Length),
        "an over-cap declared length is refused even when the body is cut short"
    );
}

fn surplus_bytes_are_a_length_fault() {
    let mut bytes = attribution();
    bytes.pop();
    bytes.extend_from_slice(b"xx\n");
    assert_eq!(
        decode_frames(&bytes).map(|read| read.frames.len()),
        Err(FrameFault::Length),
        "bytes between the declared JSON and the newline"
    );
    // The newline replaced by one stray byte at the end of the file: nothing after it can
    // raise a second fault, so only the frame's own terminator check refuses it.
    let mut replaced = attribution();
    replaced.pop();
    replaced.push(b'x');
    assert_eq!(
        decode_frames(&replaced).map(|read| read.frames.len()),
        Err(FrameFault::Length),
        "a frame whose terminator is not a newline"
    );
}

fn another_version_is_a_field_fault() {
    let other = ATTRIBUTION_JSON.replace(r#""v":1"#, r#""v":2"#);
    assert_ne!(
        other, ATTRIBUTION_JSON,
        "the control must change the golden"
    );
    assert_eq!(
        decode_frames(&reframe(&other)).map(|read| read.frames.len()),
        Err(FrameFault::Field),
        "a version other than 1"
    );
}

fn donor_proof_is_an_exact_prefix() {
    let (i, r0, r1) = (handed_over(), record_0(), record_1());
    let donor = donor();
    let cases = [
        (
            "a gap",
            file(&[&i, &r1, &torn(&r1, 10)]),
            corrupt(1, Cause::NotAPrefix),
        ),
        (
            "a duplicate",
            file(&[&i, &i, &torn(&r0, 10)]),
            corrupt(1, Cause::NotAPrefix),
        ),
        (
            "a reorder",
            file(&[&r0, &i, &torn(&r1, 10)]),
            corrupt(0, Cause::NotAPrefix),
        ),
        (
            "the exact prefix",
            file(&[&i, &r0, &torn(&r1, 10)]),
            Inspection::RepairableTail {
                start: i.len() + r0.len(),
            },
        ),
    ];
    for (what, bytes, expected) in cases {
        assert_eq!(inspect(&bytes, Some(&donor)), expected, "{what}");
    }
}

fn tail_beyond_the_donor_is_refused() {
    let (i, r0, r1) = (handed_over(), record_0(), record_1());
    let bytes = file(&[&i, &r0, &r1, &torn(&r1, 10)]);
    assert_eq!(
        inspect(&bytes, Some(&donor())),
        corrupt(3, Cause::TailBeyondDonor),
        "a torn frame after the donor's whole sequence is surplus"
    );
}

fn newline_less_final_frame_is_a_tail() {
    let (i, r0, r1) = (handed_over(), record_0(), record_1());
    let without_newline = r1[..r1.len() - 1].to_vec();
    let bytes = file(&[&i, &r0, &without_newline]);
    let start = i.len() + r0.len();
    let read = decode_frames(&bytes).expect("a missing final newline is a torn tail");
    assert_eq!(read.frames.len(), 2, "the two complete frames");
    assert_eq!(
        read.tail,
        Tail::Incomplete { start },
        "the tail starts at the last frame"
    );
    assert_eq!(
        inspect(&bytes, Some(&donor())),
        Inspection::RepairableTail { start },
        "with the matching donor"
    );
    assert_eq!(
        inspect(&bytes, None),
        corrupt(2, Cause::TailWithoutDonor),
        "without a donor"
    );
}

fn every_offset_classifies_consistently() -> Result<(), String> {
    let frames = [handed_over(), record_0(), record_1()];
    let whole = file(&[&frames[0], &frames[1], &frames[2]]);
    let mut bounds = vec![0];
    for frame in &frames {
        bounds.push(bounds.last().copied().unwrap_or(0) + frame.len());
    }
    let donor = donor();
    for cut in 0..=whole.len() {
        let slice = &whole[..cut];
        let whole_frames = bounds.iter().skip(1).filter(|bound| **bound <= cut).count();
        let start = bounds[whole_frames];
        let read = decode_frames(slice).map_err(|fault| format!("offset {cut}: {fault:?}"))?;
        assert_eq!(
            read.frames.len(),
            whole_frames,
            "offset {cut}: complete frames"
        );
        if start == cut {
            assert_eq!(read.tail, Tail::Clean, "offset {cut}: on a boundary");
            assert_eq!(
                inspect(slice, Some(&donor)),
                Inspection::Structural,
                "offset {cut}"
            );
            assert_eq!(inspect(slice, None), Inspection::Structural, "offset {cut}");
        } else {
            assert_eq!(
                read.tail,
                Tail::Incomplete { start },
                "offset {cut}: inside a frame"
            );
            assert_eq!(
                inspect(slice, Some(&donor)),
                Inspection::RepairableTail { start },
                "offset {cut}: with the donor"
            );
            assert_eq!(
                inspect(slice, None),
                corrupt(whole_frames, Cause::TailWithoutDonor),
                "offset {cut}: without a donor"
            );
        }
    }
    Ok(())
}

/// A named case of the row: its name, what it expects, and the check.
type Case = (&'static str, &'static str, fn());

#[test]
fn abandoned_corrupt_without_donor() {
    const ROW: &str = "abandoned_corrupt_without_donor";
    let mut failures = Vec::new();
    let cases: [Case; 12] = [
        (
            "tail_without_donor",
            "a torn tail with no donor is Corrupt",
            tail_without_donor,
        ),
        (
            "complete_corrupt_frames",
            "a corrupt frame is Corrupt with or without a donor",
            complete_corrupt_frames,
        ),
        (
            "altered_frames",
            "a checksum-valid altered frame matches no donor",
            altered_frames_match_no_donor,
        ),
        (
            "unrelated_owner",
            "another owner's handover proves nothing",
            unrelated_owner_proves_nothing,
        ),
        (
            "early_newline",
            "an early newline is a Length fault, never a tail",
            early_newline_is_a_length_fault,
        ),
        (
            "header_newline",
            "a newline inside a header is a Length fault, never a tail",
            newline_in_a_header_field_is_a_length_fault,
        ),
        (
            "over_cap",
            "an over-cap header is refused before allocating",
            over_cap_is_refused_before_allocation,
        ),
        (
            "surplus_bytes",
            "surplus bytes are a Length fault",
            surplus_bytes_are_a_length_fault,
        ),
        (
            "other_version",
            "a version other than 1 is a Field fault",
            another_version_is_a_field_fault,
        ),
        (
            "exact_prefix",
            "only the exact canonical prefix is repairable",
            donor_proof_is_an_exact_prefix,
        ),
        (
            "beyond_the_donor",
            "a tail after the whole sequence is refused",
            tail_beyond_the_donor_is_refused,
        ),
        (
            "newline_less_final_frame",
            "a missing final newline is a tail",
            newline_less_final_frame_is_a_tail,
        ),
    ];
    for (name, expected, run) in cases {
        collect_case(&mut failures, ROW, name, expected, || {
            run();
            Ok(())
        });
    }
    collect_case(
        &mut failures,
        ROW,
        "every_offset",
        "the whole file cut at every byte classifies consistently, never a panic",
        every_offset_classifies_consistently,
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

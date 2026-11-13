// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! File-drain refusal, reporting and redelivery rows: a refused file is kept exactly as found,
//! warned about and counted; an accepted one reaches its own log with its actor.

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use super::super::super::abandoned::{
    AbandonedFrame, MAX_ABANDONED_BYTES, decode_frames, encode_frame, marked,
};
use super::super::DrainError;
use super::super::fixtures::{Live, actor, attributed, runtime};
use super::super::handover::abandoned_path;
use super::drain_abandoned;
use super::tests::{DrainRig, drain_rig, unfrozen};

/// Replace the abandoned file with `bytes`, private to this user as a handover leaves it.
fn plant(rig: &DrainRig, bytes: &[u8]) {
    let path = abandoned_path(&rig.live.path);
    std::fs::write(&path, bytes).expect("planted file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("private mode");
}

/// The rig's own file as frames, for building altered files.
fn frames(rig: &DrainRig) -> Vec<AbandonedFrame> {
    decode_frames(&rig.file().expect("the handed-over file"))
        .expect("the handover wrote whole frames")
        .frames
}

fn encoded(frames: &[AbandonedFrame]) -> Vec<u8> {
    frames
        .iter()
        .map(|frame| encode_frame(frame).expect("a frame fits"))
        .collect::<Vec<_>>()
        .concat()
}

/// Drain once and assert a refusal that leaves the file exactly as planted and appends nothing.
fn refused_unchanged(rig: &mut DrainRig, row: &str, case: &str, want: DrainError) {
    let before = rig.file();
    let records = rig.live.records().len();
    assert_eq!(rig.drain(), Err(want), "{row} {case}: refused");
    assert_eq!(
        rig.file(),
        before,
        "{row} {case}: the file is byte-identical"
    );
    assert_eq!(
        rig.live.records().len(),
        records,
        "{row} {case}: nothing appended"
    );
}

/// The drain half of the closed design's corrupt-file row: a torn tail with no donor, and
/// complete corrupt frames, are refused and never truncated or rewritten.
#[test]
fn abandoned_corrupt_without_donor_drain() {
    const ROW: &str = "abandoned_corrupt_without_donor_drain";
    let mut rig = drain_rig(ROW, |_| {});
    let good = rig.file().expect("the handed-over file");
    let first = encode_frame(&frames(&rig)[0]).expect("a frame fits").len();
    let torn = good[..good.len() - 3].to_vec();
    let mut bad_sum = good.clone();
    let tab = bad_sum
        .iter()
        .position(|b| *b == b'\t')
        .expect("a header tab");
    bad_sum[tab + 1] = if bad_sum[tab + 1] == b'0' { b'1' } else { b'0' };
    let mut bad_length = good.clone();
    bad_length[first] = b'9';
    for (case, bytes) in [
        ("torn tail, no donor", torn),
        ("corrupt first-frame checksum", bad_sum),
        ("corrupt final length", bad_length),
    ] {
        plant(&rig, &bytes);
        refused_unchanged(&mut rig, ROW, case, DrainError::FileRefused);
    }
}

/// F4: a file bound to another log is not delivered to this one; a file naming two logs is
/// refused whole (design D1).
#[test]
fn crash_f4() {
    const ROW: &str = "crash_f4";
    let mut rig = drain_rig(ROW, |_| {});
    let other = Live::new();
    let before = rig.file();
    let other_records = other.records().len();
    let result = runtime(drain_abandoned(
        &mut rig.session,
        Some(Arc::clone(&other.log)),
    ));
    assert_eq!(
        result,
        Err(DrainError::OtherLog),
        "{ROW}: another log is refused"
    );
    assert_eq!(
        other.records().len(),
        other_records,
        "{ROW}: zero appends to the other log"
    );
    assert_eq!(rig.file(), before, "{ROW}: the file is byte-identical");

    let mut mixed = frames(&rig);
    mixed.last_mut().expect("a second frame").log_id = other.log.log_id();
    plant(&rig, &encoded(&mixed));
    refused_unchanged(&mut rig, ROW, "mixed bindings", DrainError::FileRefused);
}

/// Drain once under a WARN capture and, with the metrics feature, a local Prometheus recorder.
fn observed(rig: &mut DrainRig) -> (Result<(), DrainError>, String, String) {
    #[cfg(feature = "metrics")]
    {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (result, warnings) = telemetry_metrics::with_local_recorder(&recorder, || {
            crate::test_log_capture::capture_warnings(|| rig.drain())
        });
        (result, warnings, handle.render())
    }
    #[cfg(not(feature = "metrics"))]
    {
        let (result, warnings) = crate::test_log_capture::capture_warnings(|| rig.drain());
        (result, warnings, String::new())
    }
}

/// Builds the bytes a refusal case plants.
type Build = fn(&DrainRig) -> Vec<u8>;

/// Lead condition on D1/D3: every refusal keeps the file exactly as found, at its path, logs one
/// WARN naming the path and the reason, and counts the reason.
#[test]
fn refused_file_kept_and_reported() {
    const ROW: &str = "refused_file_kept_and_reported";
    let cases: [(&str, DrainError, Build); 7] = [
        ("mixed_binding", DrainError::FileRefused, |rig| {
            let mut mixed = frames(rig);
            mixed.last_mut().expect("a second frame").log_id = Live::new().log.log_id();
            encoded(&mixed)
        }),
        ("torn_tail", DrainError::FileRefused, |rig| {
            let good = rig.file().expect("file");
            good[..good.len() - 3].to_vec()
        }),
        ("wire", DrainError::FileRefused, |rig| {
            let mut bad = rig.file().expect("file");
            let tab = bad.iter().position(|b| *b == b'\t').expect("a header tab");
            bad[tab + 1] = if bad[tab + 1] == b'0' { b'1' } else { b'0' };
            bad
        }),
        ("shape", DrainError::FileRefused, |rig| {
            let mut shaped = frames(rig);
            shaped[0]
                .owner
                .as_mut()
                .expect("intent owner facts")
                .handed_over = false;
            encoded(&shaped)
        }),
        ("over_cap", DrainError::FileRefused, |_| {
            vec![b'0'; MAX_ABANDONED_BYTES + 1]
        }),
        ("unsafe_handle", DrainError::FileRefused, |rig| {
            rig.file().expect("file")
        }),
        ("foreign_donor", DrainError::Journal, |rig| {
            let mut altered = frames(rig);
            altered[0].record.delivered = true;
            encoded(&altered)
        }),
    ];
    for (reason, want, build) in cases {
        let mut rig = drain_rig(ROW, |_| {});
        let bytes = build(&rig);
        plant(&rig, &bytes);
        let path = abandoned_path(&rig.live.path);
        if reason == "unsafe_handle" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect(ROW);
        }
        if reason == "foreign_donor" {
            super::super::super::fixtures::seed(&rig.live.path, &marked(&rig.donor));
            super::super::fixtures::reread(&mut rig.session);
        }
        let journal = rig.journal();
        let (result, warnings, metrics) = observed(&mut rig);
        assert_eq!(result, Err(want), "{ROW} {reason}: refused");
        assert_eq!(
            rig.file().as_deref(),
            Some(bytes.as_slice()),
            "{ROW} {reason}: kept"
        );
        assert_eq!(rig.journal(), journal, "{ROW} {reason}: any donor kept");
        let named = path.display().to_string();
        let lines = warnings
            .lines()
            .filter(|line| line.contains(&named) && line.contains(reason))
            .count();
        assert_eq!(
            lines, 1,
            "{ROW} {reason}: exactly one WARN names the path and the reason: {warnings}"
        );
        #[cfg(feature = "metrics")]
        assert!(
            metrics.lines().any(|line| {
                line.starts_with("mcp_config_abandoned_refused_total")
                    && line.contains(&format!("reason=\"{reason}\""))
                    && line.ends_with(" 1")
            }),
            "{ROW} {reason}: counted once: {metrics}"
        );
        #[cfg(not(feature = "metrics"))]
        assert!(
            metrics.is_empty(),
            "{ROW} {reason}: no recorder without metrics"
        );
    }
}

/// The redelivery hop of the attribution round trip (design D5): an attributed token drained
/// from the file reaches the real log with the complete persisted actor.
#[test]
fn attribution_redelivered() {
    const ROW: &str = "attribution_redelivered";
    let mut rig = drain_rig(ROW, |donor| {
        unfrozen(donor);
        attributed(donor);
    });
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    let token = rig
        .donor
        .writer
        .as_ref()
        .expect("fixture writer")
        .intent_id
        .0
        .clone();
    let records = rig.live.records();
    let owned: Vec<_> = records
        .iter()
        .filter(|r| r["token"] == token.as_str())
        .collect();
    assert!(
        owned.len() >= 2,
        "{ROW}: intent and terminal both delivered"
    );
    for record in owned {
        assert_eq!(
            record["who"],
            serde_json::to_value(actor()).expect(ROW),
            "{ROW}: the complete frozen actor, never the gateway actor"
        );
        assert_eq!(
            record["who"]["principal"], "0123ab45cd67",
            "{ROW}: principal kept"
        );
        assert!(
            record.get("subject").is_none(),
            "{ROW}: no envelope subject"
        );
    }
    rig.live.verify(ROW);
}

/// A record the log refuses as Invalid parks in the file; the next drain refuses with Parked and
/// nothing is removed until the operator's abandon path retires it.
#[test]
fn drain_parks_invalid() {
    const ROW: &str = "drain_parks_invalid";
    let mut rig = drain_rig(ROW, |donor| {
        unfrozen(donor);
        donor
            .writer
            .as_mut()
            .expect("fixture writer")
            .intent
            .payload_json = br#"{"kind":17}"#.to_vec();
    });
    assert_eq!(rig.drain(), Err(DrainError::Parked), "{ROW}: parked");
    let parked = rig.file().expect("the file is kept");
    let frame = &decode_frames(&parked).expect(ROW).frames[0];
    assert!(
        frame.record.parked.is_some(),
        "{ROW}: the park is persisted in the file"
    );
    assert_eq!(rig.drain(), Err(DrainError::Parked), "{ROW}: never resent");
    assert_eq!(rig.file(), Some(parked), "{ROW}: the file is unchanged");
}

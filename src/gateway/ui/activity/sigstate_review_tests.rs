// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The signing-anchor reader rows added by the code review: re-signed and
//! copied sidecars, a closed rebuild, the live catch-up, a live writer, a
//! reload, and two logs sharing chunk coordinates. Helpers are the parent's.

use super::*;

/// R32 (c): a re-signed sidecar whose entry for its own file is shorter than
/// the anchor offset fails coverage (q23).
#[tokio::test]
async fn r32c_own_file_coverage_short_of_p_is_tampering() {
    use crate::security::transparency_log::sigstart::{self, SigStart};
    let fx = turned_on_midway();
    let raw = std::fs::read_to_string(fx.sidecar()).unwrap();
    let mut v: Value = serde_json::from_str(raw.trim_end()).unwrap();
    v.as_object_mut().unwrap().remove("mac");
    let mut body: SigStart = serde_json::from_value(v).unwrap();
    let own = body
        .legacy
        .iter_mut()
        .find(|l| l.seq == body.segment_seq)
        .unwrap();
    own.len -= 1;
    std::fs::write(
        fx.sidecar(),
        sigstart::encode(&body, SECRET.as_bytes()).unwrap(),
    )
    .unwrap();
    let s = seen(&fx, "tool_0").await;
    assert_eq!(s.list["signature"], "invalid");
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "coverage");
}

/// Re-sign a sidecar after `edit`, so only its content, not its MAC, is wrong.
fn resign(
    fx: &Fixture,
    edit: impl FnOnce(&mut crate::security::transparency_log::sigstart::SigStart),
) {
    use crate::security::transparency_log::sigstart::{self, SigStart};
    let raw = std::fs::read_to_string(fx.sidecar()).unwrap();
    let mut v: Value = serde_json::from_str(raw.trim_end()).unwrap();
    v.as_object_mut().unwrap().remove("mac");
    let mut body: SigStart = serde_json::from_value(v).unwrap();
    edit(&mut body);
    std::fs::write(
        fx.sidecar(),
        sigstart::encode(&body, SECRET.as_bytes()).unwrap(),
    )
    .unwrap();
}

/// R39 (kimi code review): after a fail-closed rebuild every unsigned record
/// reads `invalid` in every reader, a legacy one included, and the manifest
/// reports `closed`.
#[tokio::test]
async fn r39_after_a_closed_rebuild_every_unsigned_record_is_invalid() {
    let fx = turned_on_midway();
    std::fs::remove_file(fx.sidecar()).unwrap();
    drop(fx.open(true, 0));
    let s = seen(&fx, "tool_0").await;
    assert_invalid(&s, "sig_missing");
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "closed");
    assert_eq!(s.manifest["anchor_faults"], 1);
    fx.strip("tool_3", |_| {});
    assert_invalid(&seen(&fx, "tool_3").await, "sig_missing");
}

/// R8 (condition 4c) with legacy history: log B's sidecar, valid under the
/// same secret and with its own legacy digests, copied over log A's, and A's
/// open record rewritten to B's id: A's legacy bytes fail B's digests.
/// The row reads `tool_0`: B's anchor falls just after B's `tool_1`, so
/// whether A's `tool_1` ends inside B's frozen range (`legacy_edited`) or
/// past it (`legacy_unlisted`) turns on timestamp lengths; `tool_0` ends a
/// whole record inside it on every clock.
#[tokio::test]
async fn r8_a_copied_sidecar_with_legacy_digests_exempts_nothing() {
    let a = turned_on_midway();
    let b = turned_on_midway();
    std::fs::copy(b.sidecar(), a.sidecar()).unwrap();
    let b_id = b.records()[0].1["log_id"].clone();
    rewrite(&a.path, |v| {
        let hit = v["event"] == "audit_segment_opened";
        if hit {
            v["log_id"] = b_id.clone();
            strip_sig(v);
        }
        hit
    });
    let s = seen(&a, "tool_0").await;
    assert_invalid(&s, "legacy_edited");
}

/// R32 (b), re-signed: a sidecar whose MAC is valid but which leaves out an
/// earlier legacy file fails coverage, and no unsigned record is exempt.
#[tokio::test]
async fn r32b_a_resigned_sidecar_missing_an_earlier_file_fails_coverage() {
    let fx = Fixture::new();
    let plain = fx.open(false, 1024);
    Fixture::calls(&plain, 0, 12);
    drop(plain);
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 12, 2);
    drop(log);
    resign(&fx, |b| {
        assert!(b.legacy.len() >= 2, "more than one legacy file");
        b.legacy.remove(0);
    });
    let s = seen(&fx, "tool_13").await;
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "coverage");
    assert_eq!(s.list_anchor["invocation"], "coverage");
    let legacy = seen(&fx, "tool_11").await;
    assert_invalid(&legacy, "sigstart_coverage");
}

/// R40 (kimi code review): the live stream's catch-up places each record at
/// its own offset: a legacy record stays `unsigned`, a stripped one after
/// signing began reads `invalid` with its reason.
#[test]
fn r40_live_catch_up_judges_each_record_at_its_place() {
    use super::super::forward::{Log, Search, StreamKind, head, rows_after};
    use super::super::reader::Limits;
    let fx = turned_on_midway();
    fx.strip("tool_3", |v| v["response_hash"] = "sha256:ff".into());
    let live = Log {
        path: &fx.path,
        kind: StreamKind::Activity,
        generation: 0,
        secret: Some(SECRET.as_bytes()),
    };
    let stop = head(&live).unwrap();
    let wide = Limits {
        matches: 200,
        bytes: 8 << 20,
    };
    let page = rows_after(
        &live,
        None,
        stop.as_ref(),
        &Access::All,
        wide,
        &mut Search::default(),
    )
    .unwrap();
    let row = |tool: &str| {
        page.rows
            .iter()
            .map(|s| s.row.clone())
            .find(|r| r["tool"] == tool)
            .unwrap_or_else(|| panic!("{tool} not caught up"))
    };
    assert_eq!(row("tool_0")["signature"], "unsigned");
    assert_eq!(row("tool_3")["signature"], "invalid");
    assert_eq!(row("tool_3")["integrity"], "sig_missing");
}

/// R7 (b) (kimi code review): `.sigstart` deleted under a live writer:
/// readers fail closed at once (`missing`), and the writer's next rebuild
/// writes exactly one rebuilt record and a `closed` sidecar.
#[tokio::test]
async fn r7b_a_sidecar_deleted_under_a_live_writer() {
    use crate::security::transparency_log::sigstart_fixture::events;
    let fx = Fixture::new();
    let plain = fx.open(false, 0);
    Fixture::calls(&plain, 0, 2);
    drop(plain);
    let log = fx.open(true, 0);
    Fixture::calls(&log, 2, 2);
    std::fs::remove_file(fx.sidecar()).unwrap();
    let s = seen(&fx, "tool_0").await;
    assert_invalid(&s, "sigstart_missing");
    assert_eq!(s.list_anchor["invocation"], "missing");
    // A synced append re-reads the log, which runs open-time recovery.
    let mut f = serde_json::Map::new();
    f.insert("kind".into(), "control_plane_audit".into());
    f.insert("action".into(), "probe".into());
    log.append_event_synced(f, &crate::security::audit::AuditEnvelope::gateway())
        .unwrap();
    drop(log);
    assert_eq!(events(&fx.path, "audit_segment_sigstart_rebuilt"), 1);
    let raw = std::fs::read_to_string(fx.sidecar()).expect("rebuilt");
    assert!(raw.contains("\"state\":\"closed\""), "{raw}");
}

/// R28 (kimi code review): readers check rows with the secret the running
/// logger opened with, not a reloaded one, so a reload that changes the
/// secret does not turn valid rows invalid.
#[test]
fn r28_readers_keep_the_running_secret_across_a_reload() {
    let mut running = crate::config::Config::default();
    running.security.transparency_log.shared_secret = SECRET.into();
    let live = crate::config_reload::LiveConfig::new(running.clone());
    let mut reloaded = running;
    reloaded.security.transparency_log.shared_secret =
        "a-different-secret-of-32-bytes-or-more!".into();
    live.set(reloaded);
    assert_eq!(
        super::super::verification_secret(&live).as_deref(),
        Some(SECRET.as_bytes())
    );
}

/// Governance records `target_id` = `t_<i>`, unsigned then signed, so the log
/// has legacy history like an invocation log turned on midway.
fn governance_midway(fx: &Fixture) {
    let gov_event = |log: &crate::security::TransparencyLogger, i: usize| {
        let mut f = serde_json::Map::new();
        f.insert("kind".into(), "control_plane_audit".into());
        f.insert("actor_id".into(), "alice".into());
        f.insert("target_id".into(), format!("t_{i}").into());
        f.insert("action".into(), "mutate_grant".into());
        log.append_event(f, &crate::security::audit::AuditEnvelope::gateway())
            .unwrap();
    };
    let plain = fx.open(false, 0);
    (0..2).for_each(|i| gov_event(&plain, i));
    drop(plain);
    let log = fx.open(true, 0);
    (2..4).for_each(|i| gov_event(&log, i));
}

/// R37 (code review C1): two logs whose legacy bytes share segment and chunk
/// coordinates; only the governance log's are edited. One export reads both:
/// the invocation log's verified chunk must not vouch for the governance one.
#[tokio::test]
async fn r37_one_logs_verified_chunk_never_vouches_for_the_other() {
    let inv = turned_on_midway();
    let gov = Fixture::new();
    governance_midway(&gov);
    rewrite(&gov.path, |v| {
        let hit = v["target_id"] == "t_1";
        if hit {
            v["action"] = "read_grant".into();
            strip_sig(v);
        }
        hit
    });
    let logs = Logs {
        invocation: inv.path.clone(),
        governance: Some(gov.path.clone()),
        secret: Some(SECRET.as_bytes().to_vec()),
    };
    let s = signer();
    let nd = json_body(export_response(
        &logs,
        &Access::All,
        &ExportQuery::default(),
        Some(&s),
    ))
    .await;
    let rows: Vec<Value> = String::from_utf8(nd)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let find = |key: &str, val: &str| {
        rows.iter()
            .find(|r| r[key] == val)
            .unwrap_or_else(|| panic!("{val} exported"))
            .clone()
    };
    assert_eq!(find("tool", "tool_0")["signature"], "unsigned");
    assert_eq!(find("target_id", "t_1")["signature"], "invalid");
    assert_eq!(find("target_id", "t_1")["integrity"], "legacy_edited");
}

/// R43 (code review): the live path loads the anchor only when a record
/// needs placing; a valid signed frame reads no sidecar.
#[test]
fn r43_a_valid_live_frame_does_not_load_the_anchor() {
    use super::super::reader::{Line, Which};
    use super::super::rows::Check;
    use crate::security::transparency_log::signature::SignatureState as State;
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 2);
    drop(log);
    let newest = fx.records().last().unwrap().1.clone();
    let line = |entry: Value| Line {
        log: Which::Invocation,
        entry,
        segment: 0,
        span: None,
    };
    let check = Check::one(Some(SECRET.as_bytes()), Which::Invocation, &fx.path);
    assert_eq!(check.judge(&line(newest.clone())).state, State::Valid);
    assert!(!check.anchor_loaded(), "a valid record needs no anchor");
    let mut forged = newest;
    strip_sig(&mut forged);
    assert_ne!(check.judge(&line(forged)).state, State::Valid);
    assert!(check.anchor_loaded(), "an unsigned record is placed");
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The older write paths (the whole-file write and the mutate path) on a
//! gateway whose audit posture requires an audit: refused before any lock,
//! so nothing is recovered unaudited; the posture is fixed for a context's
//! lifetime.

use super::*;
use crate::gateway::test_helpers::ConfigFiles;

/// An audit log in a directory of its own that the log keeps, carried by a
/// context's reporting: the production posture of a gateway with a
/// transparency log.
fn audit_log_reporting() -> super::super::refusals::ReloadReporting {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "posture".to_string(),
                ..Default::default()
            },
        ))
        .expect("log opens"),
    );
    log.keep_test_dir(dir);
    super::super::refusals::ReloadReporting::default().with_audit_log(Some(log))
}

/// A context over `path` whose running config has auth on, with no audit
/// log: a posture that refuses every config write.
fn auth_on_context(path: &Path) -> Arc<super::super::ReloadContext> {
    let mut running = crate::config::Config::load(Some(path)).expect("config loads");
    running.auth.enabled = true;
    Arc::new(
        super::super::ReloadContext::new(
            path.to_path_buf(),
            Arc::new(super::super::LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    )
}

/// The guard's own refusal and nothing else: a crash, a busy lock or an
/// unrelated failure is an error too, and must not pass for the refusal.
fn assert_audited_refusal(err: Option<&super::super::ConfigWriteError>, what: &str) {
    assert_eq!(
        err,
        Some(&super::super::ConfigWriteError::Failed(
            "an audited gateway writes its config only through the audited writer".to_owned()
        )),
        "{what} was not refused by the audit guard"
    );
}

/// The older mutate path with auth on and no audit log: a posture that
/// requires an audit. The write is refused before any lock, so the crashed
/// bytes and the journal stay and nothing is loaded.
#[tokio::test]
async fn the_mutate_path_with_auth_on_and_no_log_recovers_nothing() {
    let (_dir, path, _) = setup();
    let ctx = auth_on_context(&path);
    crashed_after_rename(&path, NEXT);

    let files = ConfigFiles::snapshot(&path);
    let result = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |_: &mut crate::config::Config| {
            Ok::<(), String>(())
        })
        .await;

    assert_audited_refusal(result.as_ref().err(), "the mutate path");
    files.assert_unchanged(&path, "the mutate path");
    assert_eq!(read(&path), NEXT, "the mutate path recovered unaudited");
    assert!(
        journal::journal_path(&path).exists(),
        "the mutate path settled the journal unaudited"
    );
    assert!(!running_has_b(&ctx), "the crashed bytes were loaded");
}

/// The older whole-file write on a gateway with an audit log: its lock
/// never recovers a pending journal unaudited. Refused before any lock, so
/// the crashed bytes and the journal stay and nothing is loaded.
#[tokio::test]
async fn the_whole_file_write_on_an_audited_gateway_recovers_nothing() {
    let (_dir, path, _) = setup();
    let ctx = Arc::new(unshared(&path).with_reporting(audit_log_reporting()));
    crashed_after_rename(&path, NEXT);
    let config = crate::config::Config::load(Some(&path)).expect("config loads");

    let files = ConfigFiles::snapshot(&path);
    let result = ctx
        .write_and_reload_outcome_within(&path, WAIT, &config)
        .await;

    assert_audited_refusal(result.as_ref().err(), "the whole-file write");
    files.assert_unchanged(&path, "the whole-file write");
    assert_eq!(
        read(&path),
        NEXT,
        "the whole-file write recovered unaudited"
    );
    assert!(
        journal::journal_path(&path).exists(),
        "the whole-file write settled the journal unaudited"
    );
    assert!(!running_has_b(&ctx), "the crashed bytes were loaded");
}

/// The old mutate path reads the gateway's audit posture from the context:
/// a context whose reporting carries an audit log is audited even with no
/// recovery sink installed, so the mutate is refused and recovers nothing.
#[tokio::test]
async fn the_mutate_path_reads_the_live_audit_posture() {
    let (_dir, path, _) = setup();
    let ctx = Arc::new(unshared(&path).with_reporting(audit_log_reporting()));
    crashed_after_rename(&path, NEXT);

    let files = ConfigFiles::snapshot(&path);
    let result = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |_: &mut crate::config::Config| {
            Ok::<(), String>(())
        })
        .await;

    assert_audited_refusal(result.as_ref().err(), "the mutate path");
    files.assert_unchanged(&path, "the mutate path");
    assert_eq!(read(&path), NEXT, "the mutate path recovered unaudited");
    assert!(
        journal::journal_path(&path).exists(),
        "the mutate path settled the journal unaudited"
    );
}

/// The old path's posture is fixed for a context's lifetime: auth is
/// restart-only, so a reload whose file turns auth on is accepted while the
/// running auth stays off, and the old path's answer does not change. Fails
/// if auth ever becomes reloadable, or the guard reads the reloaded config.
#[tokio::test]
async fn a_reload_that_turns_auth_on_leaves_the_old_path_posture_as_started() {
    let (_dir, path, ctx) = setup();
    assert!(!ctx.live_config.running().auth.enabled, "premise: auth off");
    let key = crate::config::api_key_digest_spec(b"posture-pin-secret");
    let auth_on = format!(
        "{START}auth:\n  enabled: true\n  single_user: true\n  api_keys:\n    - name: pin\n      key_sha256: \"{key}\"\n      backends: [\"*\"]\n"
    );
    write_owner_only(&path, &auth_on).expect("write");

    ctx.reload_outcome()
        .await
        .expect("the reload accepts auth on");

    assert!(
        ctx.live_config.get().auth.enabled,
        "premise: the reload published auth on"
    );
    assert!(
        !ctx.live_config.running().auth.enabled,
        "the running auth changed without a restart"
    );
    let result = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |_: &mut crate::config::Config| {
            Ok::<(), String>(())
        })
        .await;
    assert!(
        matches!(result, Ok(super::super::ConfigMutation::Applied(..))),
        "a reload changed the old path's posture: {:?}",
        result.as_ref().err()
    );
}

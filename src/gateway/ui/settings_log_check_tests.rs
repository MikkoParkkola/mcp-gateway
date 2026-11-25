// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITE.4: a save that turns auth on is refused, before anything is written
//! or the secret store opens, unless the next start has an audit log it can
//! write; the check asks permissions and nothing else.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::http::StatusCode;
use serde_json::{Map, Value, json};

use super::super::settings_log_check::{Access, Unusable, usable_log};
use super::test_support::*;
use super::{AUDIT_LOG_REQUIRED, NOT_AUDITED, SettingsStoreForTest};
use crate::gateway::ui::admin_audit::AuditDetail;

/// `BASE` with its transparency log section holding `lines`.
fn with_log(lines: &str) -> String {
    format!("{BASE}security:\n  transparency_log:\n{lines}")
}

/// Rewrite the route's config to hold `lines` as its log section, and load
/// it: the check reads the published config, never an unloaded edit.
async fn load_log(route: &Route, lines: &str) {
    route.write(&with_log(lines));
    route.ctx.reload().await.expect("the log section loads");
}

/// The save that turns auth on, with `more` fields: status, answer, detail.
async fn turn_on(route: &Route, more: &[Value]) -> (StatusCode, Value, Map<String, Value>) {
    let mut fields = vec![set("auth.enabled", &json!(true))];
    fields.extend_from_slice(more);
    let body = route.saved_body(&Value::Array(fields));
    let response = route.response(true, &body.to_string(), client(true)).await;
    let detail = response.extensions().get::<AuditDetail>().cloned();
    let AuditDetail(detail) = detail.expect("every save answer carries its detail");
    let (status, answer) = decode(response).await;
    (status, answer, detail)
}

/// A refused save: the 409 with its code, the file as it was, refused.
fn assert_required(
    row: &str,
    route: &Route,
    before: &str,
    answer: (StatusCode, Value, Map<String, Value>),
) {
    let (status, body, detail) = answer;
    assert_eq!(status, StatusCode::CONFLICT, "{row}: {body}");
    assert_eq!(body["error"], AUDIT_LOG_REQUIRED.0, "{row}: {body}");
    assert_eq!(route.text(), before, "{row}: nothing was written");
    assert_eq!(detail["save_outcome"], "refused", "{row}: {detail:?}");
}

fn codes(answer: &Value) -> Vec<String> {
    let notices = answer["notices"].as_array().expect("a notices array");
    notices
        .iter()
        .map(|n| n["code"].as_str().expect("a code").to_owned())
        .collect()
}

/// A directory the runner cannot write; the permission rows need a non-root
/// runner, since root passes `access(2)` whatever the mode bits say.
#[cfg(unix)]
fn locked(at: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    assert!(
        !rustix::process::geteuid().is_root(),
        "W4 needs a non-root runner"
    );
    std::fs::create_dir_all(at).expect("the directory");
    std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o555)).expect("read-only");
    at.to_path_buf()
}

#[test]
fn the_refusal_code_is_its_name() {
    assert_eq!(AUDIT_LOG_REQUIRED.0, "AUDIT_LOG_REQUIRED");
}

/// W4 legs 1 and 2: the log explicitly off, or a blank path.
#[tokio::test]
async fn w4_an_off_or_blank_log_refuses_turning_auth_on() {
    for (row, lines) in [
        ("W4.1", "    enabled: false\n"),
        ("W4.2", "    path: \"  \"\n"),
    ] {
        let route = Route::new(&with_log(lines)).await;
        let before = route.text();
        let answer = turn_on(&route, &[]).await;
        assert!(
            answer.1["message"]
                .as_str()
                .unwrap_or("")
                .contains("security.transparency_log"),
            "{row}: {}",
            answer.1
        );
        assert_required(row, &route, &before, answer);
    }
}

/// W4 leg 3: the default setup, under the process's writable test home.
#[tokio::test]
async fn w4_the_default_log_under_a_writable_home_lets_auth_on() {
    let route = Route::new(BASE).await;
    let (status, answer, detail) = turn_on(&route, &[]).await;
    assert_eq!(status, StatusCode::OK, "W4.3: {answer}");
    assert!(
        codes(&answer).contains(&NOT_AUDITED.0.to_owned()),
        "W4.3: {answer}"
    );
    assert_eq!(detail["save_outcome"], "applied", "W4.3: {detail:?}");
}

/// W4 leg 4: a path whose nearest existing ancestor cannot be written.
#[cfg(unix)]
#[tokio::test]
async fn w4_an_unwritable_directory_refuses_turning_auth_on() {
    let route = Route::new(BASE).await;
    let dir = locked(&route.dir.path().join("locked"));
    let path = dir.join("sub").join("audit.jsonl");
    load_log(&route, &format!("    path: \"{}\"\n", path.display())).await;
    let before = route.text();
    let answer = turn_on(&route, &[]).await;
    let message = answer.1["message"].as_str().unwrap_or("").to_owned();
    assert!(
        message.contains(&path.display().to_string()),
        "W4.4: {message}"
    );
    assert_required("W4.4", &route, &before, answer);
    let listing = std::fs::read_dir(&dir).expect("list").count();
    assert_eq!(listing, 0, "W4.4: the check created nothing");
}

/// W4 legs 5 and 6: an existing read-only log file, and a writable log file
/// in a directory that cannot be written.
#[cfg(unix)]
#[tokio::test]
async fn w4_an_unwritable_existing_log_refuses_turning_auth_on() {
    use std::os::unix::fs::PermissionsExt;
    let route = Route::new(BASE).await;
    let read_only = route.dir.path().join("ro").join("audit.jsonl");
    std::fs::create_dir_all(read_only.parent().expect("a dir")).expect("dir");
    std::fs::write(&read_only, b"").expect("the file");
    let mode = std::fs::Permissions::from_mode(0o444);
    std::fs::set_permissions(&read_only, mode).expect("read-only file");
    let in_locked = route.dir.path().join("held").join("audit.jsonl");
    std::fs::create_dir_all(in_locked.parent().expect("a dir")).expect("dir");
    std::fs::write(&in_locked, b"").expect("the file");
    locked(in_locked.parent().expect("a dir"));
    for (row, path) in [("W4.5", &read_only), ("W4.6", &in_locked)] {
        load_log(&route, &format!("    path: \"{}\"\n", path.display())).await;
        let before = route.text();
        let answer = turn_on(&route, &[]).await;
        assert_required(row, &route, &before, answer);
    }
}

/// W4 leg 7: a relative path is walked from the working directory, and the
/// check creates nothing there.
#[tokio::test]
async fn w4_a_relative_path_is_judged_from_the_working_directory() {
    let absent = Path::new("w4-absent-log-dir");
    assert!(!absent.exists(), "W4.7: premise, the directory is absent");
    let route = Route::new(&with_log("    path: \"w4-absent-log-dir/audit.jsonl\"\n")).await;
    let (status, answer, _) = turn_on(&route, &[]).await;
    assert_eq!(status, StatusCode::OK, "W4.7: {answer}");
    assert!(!absent.exists(), "W4.7: the check created the directory");
}

/// W4 leg 8: the log the gateway holds open is the one the config names.
#[tokio::test]
async fn w4_the_held_log_lets_auth_on_audited() {
    let mut route = Route::new(BASE).await;
    let held = route.audit().path();
    load_log(&route, &format!("    path: \"{}\"\n", held.display())).await;
    let (status, answer, detail) = turn_on(&route, &[]).await;
    assert_eq!(status, StatusCode::OK, "W4.8: {answer}");
    assert!(detail.get("intent_id").is_some(), "W4.8: {detail:?}");
    assert!(
        !codes(&answer).contains(&NOT_AUDITED.0.to_owned()),
        "W4.8: {answer}"
    );
}

/// W4 leg 9: a log held at one path does not pass a config naming another
/// that cannot be written.
#[cfg(unix)]
#[tokio::test]
async fn w4_a_log_held_elsewhere_does_not_pass() {
    let mut route = Route::new(BASE).await;
    route.audit();
    let dir = locked(&route.dir.path().join("locked"));
    let other = dir.join("audit.jsonl");
    load_log(&route, &format!("    path: \"{}\"\n", other.display())).await;
    let before = route.text();
    let answer = turn_on(&route, &[]).await;
    assert_required("W4.9", &route, &before, answer);
}

/// W4 leg 10: the refusal comes before the secret store opens. The store
/// here refuses any open, so an open would answer with its own refusal.
#[cfg(unix)]
#[tokio::test]
async fn w4_the_check_runs_before_the_store_opens() {
    let mut route = Route::new(BASE).await;
    let unopened = super::super::secret_slots::Unopened::Unavailable;
    route.store = Some(SettingsStoreForTest::OpenRefused(unopened));
    let dir = locked(&route.dir.path().join("locked"));
    let path = dir.join("sub").join("audit.jsonl");
    load_log(&route, &format!("    path: \"{}\"\n", path.display())).await;
    let before = route.text();
    let answer = turn_on(&route, &[secret("w4-bearer-value")]).await;
    assert_required("W4.10", &route, &before, answer);
}

/// W4 leg 11: turning auth off is never checked.
#[tokio::test]
async fn w4_turning_auth_off_is_not_checked() {
    let route = Route::new(&with_log("    enabled: false\n")).await;
    let body = route.saved_body(&json!([set("auth.enabled", &json!(false))]));
    let (status, answer) = route.raw(true, &body.to_string(), client(true)).await;
    assert_eq!(status, StatusCode::OK, "W4.11: {answer}");
}

type Calls = Mutex<Vec<(PathBuf, Access)>>;

/// A probe that records each call, refusing the path `refuse` names.
fn record<'a>(
    calls: &'a Calls,
    refuse: Option<&'a Path>,
) -> impl Fn(&Path, Access) -> std::io::Result<()> + 'a {
    move |path, access| {
        calls
            .lock()
            .expect("calls")
            .push((path.to_path_buf(), access));
        if Some(path) == refuse {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

fn config_at(path: &str) -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.security.transparency_log.path = path.to_owned();
    config
}

/// W4b (a): the default path under an injected home: one directory call, on
/// the home, the nearest existing ancestor.
#[test]
fn w4b_the_default_path_asks_its_nearest_existing_directory() {
    let home = tempfile::tempdir().expect("home");
    let calls = Calls::default();
    let probe = record(&calls, None);
    let config = crate::config::Config::default();
    let cwd = Path::new("/");
    assert_eq!(
        usable_log(&config, None, Some(home.path()), cwd, &probe),
        Ok(())
    );
    let want = vec![(home.path().to_path_buf(), Access::Directory)];
    assert_eq!(*calls.lock().expect("calls"), want);
}

/// W4b (b): an existing file: its directory, then the file itself.
#[test]
fn w4b_an_existing_file_asks_its_directory_then_itself() {
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("audit.jsonl");
    std::fs::write(&file, b"").expect("the file");
    let calls = Calls::default();
    let probe = record(&calls, None);
    let config = config_at(&file.display().to_string());
    assert_eq!(
        usable_log(&config, None, None, Path::new("/"), &probe),
        Ok(())
    );
    let want = vec![
        (dir.path().to_path_buf(), Access::Directory),
        (file.clone(), Access::File),
    ];
    assert_eq!(*calls.lock().expect("calls"), want);
}

/// W4b (c): a directory the probe refuses: the path is not writable.
#[test]
fn w4b_a_refused_directory_is_not_writable() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("audit.jsonl");
    let calls = Calls::default();
    let probe = record(&calls, Some(dir.path()));
    let config = config_at(&path.display().to_string());
    let got = usable_log(&config, None, None, Path::new("/"), &probe);
    assert_eq!(got, Err(Unusable::NotWritable(path)));
}

/// W4b (d): a relative path is asked about under the injected working
/// directory, never under an empty one.
#[test]
fn w4b_a_relative_path_is_asked_under_the_working_directory() {
    let cwd = tempfile::tempdir().expect("cwd");
    let calls = Calls::default();
    let probe = record(&calls, None);
    let config = config_at("audit.jsonl");
    assert_eq!(usable_log(&config, None, None, cwd.path(), &probe), Ok(()));
    let want = vec![(cwd.path().to_path_buf(), Access::Directory)];
    assert_eq!(*calls.lock().expect("calls"), want);
}

/// W4b (e): the check's own source opens, creates and locks nothing.
#[test]
fn w4b_the_check_touches_nothing_on_disk() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/ui/settings_log_check.rs");
    let text = std::fs::read_to_string(source).expect("the check's source");
    for call in [
        "File::open",
        "OpenOptions",
        "create_dir",
        "fs::write",
        "lease::acquire",
        "flock",
    ] {
        assert!(!text.contains(call), "the check calls {call}");
    }
}

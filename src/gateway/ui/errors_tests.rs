// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[test]
fn admin_auth_required_shape_is_stable() {
    let (status, body) = admin_auth_required();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.0, json!({ "error": "Admin authentication required" }));
}

#[test]
fn auth_required_preserves_caller_status() {
    let (status, body) = auth_required(StatusCode::UNAUTHORIZED);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.0, json!({ "error": "Authentication required" }));
}

#[test]
fn config_path_unavailable_shape_is_stable() {
    let (status, body) = config_path_unavailable();
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body.0,
        json!({ "error": "Config file path not available; cannot persist changes" })
    );
}

#[test]
fn flat_error_uses_error_field() {
    let (status, body) = flat_error(StatusCode::CONFLICT, "example");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.0, json!({ "error": "example" }));
}

#[test]
fn structured_error_uses_error_and_message_fields() {
    let (status, body) = structured_error(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        "bad capability name",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.0,
        json!({
            "error": "invalid_name",
            "message": "bad capability name",
        })
    );
}

/// C1: every writer error is classified, and exactly as the class rule says
/// (sidecar 1 for `WriterRefused`).
#[test]
fn every_writer_error_is_classified() {
    use crate::config_reload::FileRevision;
    use std::path::PathBuf;
    let s = || "x".to_owned();
    let cases: Vec<(ReplaceError, Option<Retry>)> = vec![
        (ReplaceError::Busy, Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::Busy), Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::ReplayOwed), Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::Restarting), Some(Retry::No)),
        (ReplaceError::Gated(Refusal::Stopping), Some(Retry::No)),
        (
            ReplaceError::Stale {
                current: FileRevision::of(b"x"),
            },
            Some(Retry::No),
        ),
        (ReplaceError::NoAuditLog, Some(Retry::No)),
        (ReplaceError::NoConfigFile, Some(Retry::No)),
        (ReplaceError::ConfigRefused(s()), Some(Retry::No)),
        (
            ReplaceError::WriterRefused {
                code: "foreign-owner",
                text: s(),
            },
            Some(Retry::No),
        ),
        (ReplaceError::AuditRefused(s()), None),
        (ReplaceError::Refused(s()), None),
        (ReplaceError::Unsupported(s()), None),
        (ReplaceError::Stage(s()), None),
        (ReplaceError::Write(s()), None),
        (
            ReplaceError::ReloadRefused {
                class: RefusalClass::Posture,
                reason: s(),
            },
            None,
        ),
        (
            ReplaceError::RollbackFailed {
                journal: PathBuf::new(),
                error: s(),
            },
            None,
        ),
        (
            ReplaceError::Unconfirmed {
                journal: PathBuf::new(),
                error: s(),
            },
            None,
        ),
        (ReplaceError::Failed(s()), None),
        (
            ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut)),
            None,
        ),
    ];
    for (error, expected) in &cases {
        assert_eq!(nothing_attempted(error), *expected, "{error:?}");
    }
}

/// C2: `refusal` sets 409, keeps the body and every other header, and owns
/// `Retry-After` in both directions.
#[tokio::test]
async fn refusal_sets_409_and_owns_retry_after() {
    let incoming = || {
        let mut answer = flat_error(StatusCode::SERVICE_UNAVAILABLE, "busy body").into_response();
        let headers = answer.headers_mut();
        headers.insert("x-probe", HeaderValue::from_static("kept"));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("30"));
        answer
    };
    for (retry, header) in [(Retry::Now, Some("1")), (Retry::No, None)] {
        let answer = refusal(retry, incoming());
        assert_eq!(answer.status(), StatusCode::CONFLICT, "{retry:?}");
        assert_eq!(
            answer.headers().get("x-probe").unwrap(),
            "kept",
            "{retry:?}"
        );
        let after = answer
            .headers()
            .get(RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(after.as_deref(), header, "{retry:?}");
        let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"error":"busy body"}"#, "{retry:?}");
    }
}

/// The status, `Retry-After` and body of one answer.
async fn parts(answer: Response) -> (StatusCode, Option<String>, Value) {
    let status = answer.status();
    let after = answer
        .headers()
        .get(RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, after, serde_json::from_slice(&body).unwrap())
}

/// R1: the shared `refused_write` follows the class rule, for the backend
/// routes and for the config restore route, which both answer through it.
#[tokio::test]
async fn shared_write_refusals_follow_the_class() {
    use crate::config_reload::{FileRevision, NO_AUDIT_LOG, RELOAD_RESTARTING, RELOAD_STOPPING};
    let routes = [
        WriteRoute {
            log: "backend route",
            change: "the backend change",
        },
        WriteRoute {
            log: "config restore route",
            change: "the restore",
        },
    ];
    let one = || Some("1".to_owned());
    for route in routes {
        let busy = json!({"error": ConfigWriteError::Busy.to_string()});
        let gate_busy = json!({"error": "a restart is being prepared; retry"});
        let audit = json!({"error": "audit_log_required", "message": NO_AUDIT_LOG});
        let not_written = json!({"error": format!("{} was not written", route.change)});
        let cases: Vec<(ReplaceError, StatusCode, Option<String>, Value)> = vec![
            (ReplaceError::Busy, StatusCode::CONFLICT, one(), busy),
            (
                ReplaceError::Gated(Refusal::Busy),
                StatusCode::CONFLICT,
                one(),
                gate_busy.clone(),
            ),
            (
                ReplaceError::Gated(Refusal::ReplayOwed),
                StatusCode::CONFLICT,
                one(),
                gate_busy,
            ),
            (
                ReplaceError::Gated(Refusal::Restarting),
                StatusCode::CONFLICT,
                None,
                json!({"error": "restarting", "message": RELOAD_RESTARTING}),
            ),
            (
                ReplaceError::Gated(Refusal::Stopping),
                StatusCode::CONFLICT,
                None,
                json!({"error": "stopping", "message": RELOAD_STOPPING}),
            ),
            (ReplaceError::NoAuditLog, StatusCode::CONFLICT, None, audit),
            // A refused append was started: the route's present answer stays.
            (
                ReplaceError::AuditRefused("a".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                not_written.clone(),
            ),
            (
                ReplaceError::ConfigRefused("c".into()),
                StatusCode::CONFLICT,
                None,
                json!({"error": "gateway.yaml could not be loaded"}),
            ),
            (
                ReplaceError::Stale {
                    current: FileRevision::of(b"x"),
                },
                StatusCode::CONFLICT,
                None,
                json!({"error": "stale", "message": "gateway.yaml changed during the write; retry"}),
            ),
            (
                ReplaceError::NoConfigFile,
                StatusCode::CONFLICT,
                None,
                no_config_file().1.0,
            ),
            (
                ReplaceError::WriterRefused {
                    code: "foreign-owner",
                    text: "w".into(),
                },
                StatusCode::CONFLICT,
                None,
                json!({"error": "foreign-owner", "message": "w"}),
            ),
            // Stays 5xx: a refused reload keeps its fixed 500.
            (
                ReplaceError::ReloadRefused {
                    class: RefusalClass::Internal,
                    reason: "r".into(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                not_written,
            ),
        ];
        for (error, status, after, body) in cases {
            let what = format!("{} {error:?}", route.log);
            let got = parts(refused_write(route, &error)).await;
            assert_eq!(got, (status, after, body), "{what}");
        }
        // Stays 5xx: a timed-out store call may still land an entry.
        let timed_out = ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut));
        let (status, after, body) = parts(refused_write(route, &timed_out)).await;
        assert_eq!(
            (status, after),
            (StatusCode::SERVICE_UNAVAILABLE, None),
            "{}",
            route.log
        );
        let text = body["error"].as_str().unwrap_or_default();
        assert!(
            text.starts_with("the secret store did not answer in time"),
            "{body}"
        );
    }
}

/// The 503 survey: file (under src/gateway/ui) and how many 503 tokens it
/// keeps, each classified READ, STARTED or UNAVAILABLE by the class rule.
const SURVEY: [(&str, usize); 25] = [
    ("activity/counts.rs", 1),
    ("activity/key_lookup.rs", 3),
    ("activity/mod.rs", 1),
    ("admin_audit.rs", 1),
    ("backends/slotting.rs", 1),
    ("config_history.rs", 1),
    ("control_plane.rs", 1),
    ("control_plane/mutations.rs", 1),
    ("decisions.rs", 1),
    ("decisions/resolve.rs", 1),
    ("discovery.rs", 4),
    ("discovery_adopt.rs", 3),
    ("errors.rs", 4),
    ("events.rs", 1),
    ("gateway_health.rs", 1),
    ("history.rs", 1),
    ("keys_create.rs", 2),
    ("keys_revoke.rs", 1),
    ("mod.rs", 1),
    ("preview.rs", 2),
    ("session.rs", 1),
    ("settings.rs", 5),
    ("settings_unused.rs", 2),
    ("stream/mod.rs", 1),
    ("tool_call.rs", 3),
];

/// Test code, by name or by a test directory anywhere in its path.
fn is_test_file(relative: &std::path::Path) -> bool {
    let named = |part: &str| {
        part.ends_with("_tests.rs") || part.ends_with("tests.rs") || part.ends_with("_tests")
    };
    relative
        .iter()
        .filter_map(|part| part.to_str())
        .any(|part| named(part) || part == "tests")
}

/// Every non-test `.rs` file under `dir`, as (path relative to `root`, text).
fn production_files(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(String, String)>,
) {
    for entry in std::fs::read_dir(dir).expect("readable ui dir") {
        let path = entry.expect("dir entry").path();
        let relative = path.strip_prefix(root).expect("under root").to_path_buf();
        if is_test_file(&relative) {
            continue;
        }
        if path.is_dir() {
            production_files(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("readable source");
            out.push((relative.to_string_lossy().replace('\\', "/"), text));
        }
    }
}

/// S1: the 503 sites match the survey, and the two shared 503 helpers for
/// reads are called only by the reads that own them.
#[test]
fn the_503_sites_match_the_survey() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/ui");
    let mut files = Vec::new();
    production_files(&root, &root, &mut files);
    let needle = ["StatusCode::", "SERVICE_UNAVAILABLE"].concat();
    let mut wrong = Vec::new();
    for (file, text) in &files {
        let found = text.matches(needle.as_str()).count();
        let expected = SURVEY
            .iter()
            .find(|(name, _)| name == file)
            .map_or(0, |(_, n)| *n);
        if found != expected {
            wrong.push(format!("{file}: expected {expected}, found {found}"));
        }
    }
    let calls = |helper: &str| -> Vec<(String, usize)> {
        let call = [helper, "()"].concat();
        files
            .iter()
            .map(|(file, text)| {
                let n = text
                    .lines()
                    .filter(|l| l.contains(&call) && !l.contains("fn "))
                    .count();
                (file.clone(), n)
            })
            .filter(|(_, n)| *n > 0)
            .collect()
    };
    let mut readers = calls("no_reload_read");
    readers.sort();
    assert_eq!(
        readers,
        vec![
            ("settings.rs".to_owned(), 1),
            ("settings_unused.rs".to_owned(), 1)
        ],
        "only the settings reads may answer the no-reload 503"
    );
    assert_eq!(
        calls("config_refusal_read"),
        vec![("settings.rs".to_owned(), 1)],
        "only the settings diff may answer the unloadable-file 503"
    );
    assert!(
        wrong.is_empty(),
        "{}\nclassify the new site by the class rule (READ, STARTED, UNAVAILABLE \
         stay 503; a refusal that attempted nothing is 409), then update this table",
        wrong.join("\n")
    );
}

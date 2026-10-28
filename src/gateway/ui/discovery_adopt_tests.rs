// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The adopt route's pieces that need no running gateway: every writer
//! outcome's answer, and the compute's splice and refusals.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::Value;

use super::*;
use crate::config::{BackendConfig, TransportConfig};
use crate::secret_store::StoreError;

const CANARY: &str = "zq-adopt-canary";

async fn body_of(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

/// One row per writer outcome: the result, its status, and the `error` code
/// when the answer names one. Every `Refused` and `Secrets` split has its own
/// row, so the mapping test pins each branch (muse PR4 r3 M1).
fn writer_outcomes() -> Vec<(
    Result<ReplaceOutcome, ReplaceError>,
    StatusCode,
    &'static str,
)> {
    let current = FileRevision::of(b"current");
    vec![
        (
            Err(ReplaceError::Stale { current }),
            StatusCode::CONFLICT,
            "stale",
        ),
        (Err(ReplaceError::Busy), StatusCode::SERVICE_UNAVAILABLE, ""),
        (
            Ok(ReplaceOutcome {
                revision: Some(FileRevision::of(b"new")),
                kept_beside: None,
                reload: crate::config_reload::ReloadOutcome::no_changes(),
            }),
            StatusCode::CREATED,
            "",
        ),
        (
            Ok(ReplaceOutcome {
                revision: None,
                kept_beside: None,
                reload: crate::config_reload::ReloadOutcome::no_changes(),
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Refused(MANAGED.to_owned())),
            StatusCode::CONFLICT,
            "not_adoptable",
        ),
        (
            Err(ReplaceError::Refused(NOT_IN_PLACE.to_owned())),
            StatusCode::CONFLICT,
            "not_in_place",
        ),
        (
            Err(ReplaceError::Refused(REFERENCES.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Refused(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Secrets(SaveError::Refused(
                StoreError::Unavailable(CANARY.to_owned()),
            ))),
            StatusCode::UNPROCESSABLE_ENTITY,
            "",
        ),
        (
            Err(ReplaceError::Secrets(SaveError::Store(StoreError::Failed(
                CANARY.to_owned(),
            )))),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::ReloadRefused(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Unsupported(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Stage(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Write(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::RollbackFailed {
                journal: CANARY.into(),
                error: CANARY.to_owned(),
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Unconfirmed {
                journal: CANARY.into(),
                error: CANARY.to_owned(),
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
        (
            Err(ReplaceError::Failed(CANARY.to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
    ]
}

/// Every writer outcome has one status, and no inner text leaves.
#[test]
fn every_writer_outcome_has_one_answer_and_quotes_nothing() {
    for (written, status, error) in writer_outcomes() {
        let what = format!("{written:?}");
        let ((got, json), logs) = {
            let (response, logs) =
                crate::test_log_capture::capture_warnings(|| answer("tool", written));
            (futures::executor::block_on(body_of(response)), logs)
        };
        assert_eq!(got, status, "{what}");
        if !error.is_empty() {
            assert_eq!(json["error"], error, "{what}");
        }
        let text = json.to_string();
        assert!(!text.contains(CANARY), "{what} answered {text}");
        assert!(!logs.contains(CANARY), "{what} logged {logs}");
    }
}

fn stdio_backend() -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Stdio {
            command: "npx tool".to_owned(),
            cwd: None,
            protocol_version: None,
        },
        enabled: false,
        ..BackendConfig::default()
    }
}

fn run(
    text: &str,
    slots: Slots,
    references: &[String],
    mut backend: BackendConfig,
    env: &[(&str, &str)],
) -> Result<String, String> {
    for (key, value) in env {
        backend.env.insert((*key).to_owned(), (*value).to_owned());
    }
    compute("tool".to_owned(), backend, slots)(text.as_bytes(), references)
        .map(|bytes| String::from_utf8(bytes).expect("utf-8"))
}

/// The compute splices the backend in, disabled, each literal key holding
/// its reference, and leaves every other byte as it was.
#[test]
fn the_compute_splices_a_disabled_backend_with_references() {
    let text = "# kept\nbackends:\n  other:\n    command: other # kept too\n";
    let reference = "file:/secrets/tool-key".to_owned();
    let out = run(
        text,
        vec![(false, "API_KEY".to_owned())],
        std::slice::from_ref(&reference),
        stdio_backend(),
        &[("TOKEN", "${TOKEN}")],
    )
    .expect("spliced");
    assert!(out.starts_with(text), "{out}");
    let config = crate::config::Config::from_file_text(&out).expect("loads");
    let tool = &config.backends["tool"];
    assert!(!tool.enabled);
    assert_eq!(tool.env["API_KEY"], reference);
    assert_eq!(tool.env["TOKEN"], "${TOKEN}");
}

/// An empty flow mapping takes the backend; a populated one cannot be
/// spliced and is refused, never re-serialised.
#[test]
fn a_populated_flow_mapping_is_refused_and_an_empty_one_spliced() {
    assert!(run("backends: {}\n", vec![], &[], stdio_backend(), &[]).is_ok());
    for text in [
        "backends: {other: {command: other}}\n",
        "# note\nbackends: {other: {command: other}}\n",
    ] {
        assert_eq!(
            run(text, vec![], &[], stdio_backend(), &[]),
            Err(NOT_IN_PLACE.to_owned()),
            "{text}"
        );
    }
}

/// The compute's own refusals: a name already a backend, and a reference
/// count that does not match the slots.
#[test]
fn the_compute_refuses_a_managed_name_and_a_short_reference_list() {
    assert_eq!(
        run(
            "backends:\n  tool:\n    command: x\n",
            vec![],
            &[],
            stdio_backend(),
            &[]
        ),
        Err(MANAGED.to_owned())
    );
    assert_eq!(
        run(
            "backends: {}\n",
            vec![(false, "API_KEY".to_owned())],
            &[],
            stdio_backend(),
            &[]
        ),
        Err(REFERENCES.to_owned())
    );
}

/// Every value kind across env and headers: literals (a reference-shaped
/// one included) leave the backend in a fixed order, templates and empty
/// values stay, and the backend is disabled.
#[test]
fn adoption_takes_out_literals_in_a_fixed_order() {
    let mut server = crate::discovery::DiscoveredServer::new(
        "tool".to_owned(),
        String::new(),
        crate::discovery::DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: "npx tool".to_owned(),
            cwd: None,
            protocol_version: None,
        },
        crate::discovery::ServerMetadata::default(),
    );
    server.env = [
        ("Z_KEY", "zq-z"),
        ("A_KEY", "file:/looks/like/a/reference"),
        ("TEMPLATE", "${TOKEN}"),
        ("EMPTY", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    server.headers = [("Authorization", "Bearer zq-h"), ("X-Plain", "${H}")]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let adopted = crate::discovery::adopt::adoption(&server);

    let fields: Vec<String> = adopted
        .literals
        .iter()
        .map(crate::discovery::adopt::Literal::field)
        .collect();
    assert_eq!(fields, ["env.A_KEY", "env.Z_KEY", "headers.Authorization"]);
    assert_eq!(
        adopted.literals[0].value.as_bytes(),
        b"file:/looks/like/a/reference"
    );
    let backend = &adopted.backend;
    assert!(!backend.enabled);
    assert_eq!(backend.env.len(), 2, "{:?}", backend.env.keys());
    assert_eq!(backend.env["TEMPLATE"], "${TOKEN}");
    assert_eq!(backend.env["EMPTY"], "");
    assert_eq!(backend.headers.len(), 1);
    assert_eq!(backend.headers["X-Plain"], "${H}");
}

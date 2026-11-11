// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The adopt route's pieces that need no running gateway: every writer
//! outcome's answer, and the compute's splice and refusals.

use crate::config_reload::RefusalClass;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::Value;

use super::*;
use crate::config::{BackendConfig, TransportConfig};
use crate::config_reload::FileRevision;
use crate::secret_store::StoreError;

const CANARY: &str = "zq-adopt-canary";
/// The guard's refusal text: it goes to the server log, never the answer.
const GUARD_DETAIL: &str = "Refusing to load config file /zq/guard/gateway.yaml: mode 0660";

async fn body_of(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

/// One row per writer outcome: the result, its status, and the `error` code
/// when the answer names one. Every `Refused` and `Secrets` split has its own
/// row, so the mapping test pins each branch.
fn writer_outcomes() -> Vec<(
    Result<ReplaceOutcome, ReplaceError>,
    StatusCode,
    &'static str,
)> {
    let current = FileRevision::of(b"current");
    let failed = |error| (Err(error), StatusCode::INTERNAL_SERVER_ERROR, "");
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
                secrets: Vec::new(),
            }),
            StatusCode::CREATED,
            "",
        ),
        (
            Ok(ReplaceOutcome {
                revision: None,
                kept_beside: None,
                reload: crate::config_reload::ReloadOutcome::no_changes(),
                secrets: Vec::new(),
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
            Err(ReplaceError::NoAuditLog),
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_log_required",
        ),
        failed(ReplaceError::Refused(REFERENCES.to_owned())),
        failed(ReplaceError::Refused(CANARY.to_owned())),
        (
            Err(ReplaceError::Secrets(SaveError::Refused(
                StoreError::Unavailable(CANARY.to_owned()),
            ))),
            StatusCode::UNPROCESSABLE_ENTITY,
            "",
        ),
        failed(ReplaceError::Secrets(SaveError::Store(StoreError::Failed(
            CANARY.to_owned(),
        )))),
        failed(ReplaceError::ReloadRefused {
            class: RefusalClass::Internal,
            reason: CANARY.to_owned(),
        }),
        failed(ReplaceError::Unsupported(CANARY.to_owned())),
        failed(ReplaceError::Stage(CANARY.to_owned())),
        failed(ReplaceError::Write(CANARY.to_owned())),
        failed(ReplaceError::RollbackFailed {
            journal: CANARY.into(),
            error: CANARY.to_owned(),
        }),
        failed(ReplaceError::Unconfirmed {
            journal: CANARY.into(),
            error: CANARY.to_owned(),
        }),
        failed(ReplaceError::Failed(CANARY.to_owned())),
        (
            Err(ReplaceError::NoConfigFile),
            StatusCode::CONFLICT,
            "no_config_file",
        ),
        (
            Err(ReplaceError::ConfigRefused(GUARD_DETAIL.to_owned())),
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway.yaml could not be loaded",
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

/// The guard's refusal is logged with its text, which names the file and the
/// fix, and answered with fixed text naming no path.
#[test]
fn a_guard_refusal_is_logged_in_full_and_answered_without_a_path() {
    let ((status, json), logs) = {
        let (response, logs) = crate::test_log_capture::capture_warnings(|| {
            answer(
                "tool",
                Err(ReplaceError::ConfigRefused(GUARD_DETAIL.to_owned())),
            )
        });
        (futures::executor::block_on(body_of(response)), logs)
    };
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        logs.contains(GUARD_DETAIL),
        "the detail was not logged: {logs}"
    );
    assert!(
        !json.to_string().contains("/zq/"),
        "the answer names a path: {json}"
    );
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
    slots: &[(bool, String)],
    references: &[String],
    mut backend: BackendConfig,
    env: &[(&str, &str)],
) -> Result<String, String> {
    for (key, value) in env {
        backend.env.insert((*key).to_owned(), (*value).to_owned());
    }
    let template = compute("tool".to_owned(), backend, slots.to_vec())(text.as_bytes())?;
    // The writer fills each slot once its entry exists; too few references
    // leave a slot unfilled, which the fill refuses.
    let refs: std::collections::BTreeMap<_, _> = slots
        .iter()
        .zip(references)
        .map(|((header, key), reference)| (adopt_slot("tool", *header, key), reference.clone()))
        .collect();
    template
        .fill(&refs)
        .map(|bytes| String::from_utf8(bytes).expect("utf-8"))
        .map_err(|_| REFERENCES.to_owned())
}

/// The compute splices the backend in, disabled, each literal key holding
/// its reference, and leaves every other byte as it was.
#[test]
fn the_compute_splices_a_disabled_backend_with_references() {
    let text = "# kept\nbackends:\n  other:\n    command: other # kept too\n";
    let reference = "file:/secrets/tool-key".to_owned();
    let out = run(
        text,
        &[(false, "API_KEY".to_owned())],
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
    assert!(run("backends: {}\n", &[], &[], stdio_backend(), &[]).is_ok());
    for text in [
        "backends: {other: {command: other}}\n",
        "# note\nbackends: {other: {command: other}}\n",
    ] {
        assert_eq!(
            run(text, &[], &[], stdio_backend(), &[]),
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
            &[],
            &[],
            stdio_backend(),
            &[]
        ),
        Err(MANAGED.to_owned())
    );
    assert_eq!(
        run(
            "backends: {}\n",
            &[(false, "API_KEY".to_owned())],
            &[],
            stdio_backend(),
            &[]
        ),
        Err(REFERENCES.to_owned())
    );
}

/// Adopt's split of a find, as the route makes it.
fn adopted(server: &crate::discovery::DiscoveredServer) -> crate::discovery::adopt::Adoption {
    crate::discovery::adopt::adoption(server)
}

/// A find carrying ordinary settings and credentials side by side, as a
/// desktop client's config would.
fn find_with_settings() -> crate::discovery::DiscoveredServer {
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
        ("DEBUG", "1"),
        ("LOG_LEVEL", "debug"),
        ("API_KEY", "zq-adopt-a1"),
        ("X_AUTH_TOKEN", "zq-adopt-b2"),
        ("DB_PASSWORD", "zq-adopt-c3"),
        ("SESSION_TIMEOUT", "30"),
        ("CONFIG_PATH", "file:/example"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    server.headers = [("X-Plain", "plain-header")]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    server
}

/// Adopt's side of the shared rule (regression): ordinary settings stay in
/// the backend as text; values under credential-like names, every header, and
/// a reference-shaped value under any name (stored as its bytes, so the
/// gateway never reads it as a reference) leave it for the store.
#[test]
fn adoption_stores_credentials_and_keeps_ordinary_settings() {
    let adopted = adopted(&find_with_settings());
    let fields: Vec<String> = adopted
        .literals
        .iter()
        .map(crate::discovery::adopt::Literal::field)
        .collect();
    assert_eq!(
        fields,
        [
            "env.API_KEY",
            "env.CONFIG_PATH",
            "env.DB_PASSWORD",
            "env.X_AUTH_TOKEN",
            "headers.X-Plain"
        ]
    );
    let env = &adopted.backend.env;
    assert_eq!(env.get("DEBUG").map(String::as_str), Some("1"), "{env:?}");
    assert_eq!(env.get("LOG_LEVEL").map(String::as_str), Some("debug"));
    assert_eq!(env.get("SESSION_TIMEOUT").map(String::as_str), Some("30"));
    assert_eq!(env.len(), 3, "{:?}", env.keys());
    assert!(adopted.backend.headers.is_empty());
}

/// Every value kind across env and headers: credential-named literals (a
/// reference-shaped one included) and header literals leave the backend in a
/// fixed order, templates and empty values stay, and the backend is disabled.
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
        ("Z_API_KEY", "zq-adopt-z9"),
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

    let adopted = adopted(&server);

    let fields: Vec<String> = adopted
        .literals
        .iter()
        .map(crate::discovery::adopt::Literal::field)
        .collect();
    assert_eq!(
        fields,
        ["env.A_KEY", "env.Z_API_KEY", "headers.Authorization"]
    );
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

/// A store that does not answer in time is a retryable 503 naming no store.
#[test]
fn a_store_that_does_not_answer_is_a_retryable_503() {
    let (status, json) = futures::executor::block_on(body_of(store_timed_out()));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert!(json.to_string().contains("retry"), "{json}");
}

/// The two answers the end-to-end test has no cheap
/// fixture for, pinned where the typed error becomes a status. A scan that
/// timed out is a 503, a changed find a 409, and a vault that cannot be
/// opened a 500 whose body never carries the store's own message.
#[test]
fn a_timed_out_scan_and_a_missing_vault_have_fixed_answers() {
    use crate::discovery::listing::ScanTimedOut;
    let timed_out = *found(Err(ScanTimedOut)).expect_err("a timeout is refused");
    let (status, json) = futures::executor::block_on(body_of(timed_out));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    let changed = *found(Ok(None)).expect_err("a changed find is refused");
    let (status, json) = futures::executor::block_on(body_of(changed));
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    assert_eq!(json["error"], "find_changed");

    // Never written: the step is refused before any store is touched.
    let store = std::sync::Arc::new(crate::secret_store::FilesStore::new(std::path::Path::new(
        "/nonexistent-zq-adopt",
    )));
    let refused = secret_step(
        "tool",
        Vec::new(),
        store,
        Err(StoreError::Failed(CANARY.to_owned())),
    )
    .err()
    .expect("no vault is refused");
    let (status, json) = futures::executor::block_on(body_of(*refused));
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{json}");
    assert!(!json.to_string().contains(CANARY), "{json}");
}

/// The store choice's answer: a choice this host cannot meet is the
/// caller's config (422), any other failure a 500; neither repeats the
/// store's message.
#[test]
fn a_store_that_cannot_be_chosen_has_a_fixed_answer() {
    for (error, status) in [
        (
            StoreError::Unavailable(CANARY.to_owned()),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            StoreError::Failed(CANARY.to_owned()),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let refused = *chosen(Err(error)).err().expect("refused");
        let (got, json) = futures::executor::block_on(body_of(refused));
        assert_eq!(got, status, "{json}");
        assert!(!json.to_string().contains(CANARY), "{json}");
    }
}

/// A literal whose key a serializer must quote (here `: `) is adopted with
/// its reference under that key, as before slots.
#[test]
fn a_key_the_serializer_quotes_is_adopted() {
    let reference = "file:/secrets/tool-key".to_owned();
    let out = run(
        "backends: {}\n",
        &[(false, "X: Y".to_owned())],
        std::slice::from_ref(&reference),
        stdio_backend(),
        &[],
    )
    .expect("spliced");
    let config = crate::config::Config::from_file_text(&out).expect("loads");
    assert_eq!(config.backends["tool"].env["X: Y"], reference);
}

/// Keys whose bytes the placeholder escapes (`~`, Unicode, both quotes),
/// and two keys that would collide if `~` itself were not escaped: each
/// reference lands under its own key.
#[test]
fn escaped_keys_each_take_their_own_reference() {
    let keys = ["T~1", "ключ", "say \"hi\"", "it's", "X~3aY", "X:Y"];
    let slots: Vec<(bool, String)> = keys.iter().map(|k| (false, (*k).to_owned())).collect();
    let references: Vec<String> = (0..keys.len())
        .map(|n| format!("file:/secrets/k{n}"))
        .collect();
    let out = run("backends: {}\n", &slots, &references, stdio_backend(), &[]).expect("spliced");
    let config = crate::config::Config::from_file_text(&out).expect("loads");
    for (key, reference) in keys.iter().zip(&references) {
        assert_eq!(&config.backends["tool"].env[*key], reference, "{key}");
    }
}

/// SAVE.6: the audit-log answer follows the refusal's type. A refusal
/// carrying the same words answers exactly as any other refusal.
#[test]
fn the_audit_log_answer_follows_the_type_not_the_words() {
    let answered = |why: &str| {
        futures::executor::block_on(body_of(answer(
            "tool",
            Err(ReplaceError::Refused(why.to_owned())),
        )))
    };
    let look_alike = answered(NO_AUDIT_LOG);
    assert_eq!(look_alike, answered(CANARY), "{look_alike:?}");
    assert_ne!(
        look_alike.1["error"], "audit_log_required",
        "{look_alike:?}"
    );
}

/// Adopt's side of the length bound: a credential-named env value or a header
/// shorter than the redactor's short-value bound stays as written, one at the
/// bound leaves for the store; a reference-shaped value leaves at any length
/// (written as text, the gateway would read it as a reference).
#[test]
fn adoption_stores_nothing_shorter_than_the_bound_but_references() {
    let bound = crate::security::needles::SHORT_VALUE_BYTES;
    let digits = "0123456789abcdef";
    let under: String = digits.chars().take(bound - 1).collect();
    let at: String = digits.chars().take(bound).collect();
    let mut server = find_with_settings();
    server.env = [
        ("API_KEY", under.as_str()),
        ("DB_PASSWORD", at.as_str()),
        ("CONFIG", "file:/x"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    server.headers = [("X-Short", under.as_str()), ("X-Long", at.as_str())]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let adopted = adopted(&server);
    let fields: Vec<String> = adopted
        .literals
        .iter()
        .map(crate::discovery::adopt::Literal::field)
        .collect();
    assert_eq!(fields, ["env.CONFIG", "env.DB_PASSWORD", "headers.X-Long"]);
    assert_eq!(adopted.backend.env.get("API_KEY"), Some(&under));
    assert_eq!(adopted.backend.headers.get("X-Short"), Some(&under));
}

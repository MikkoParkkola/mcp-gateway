// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7721 NEG.1: the revision a stdio backend selects is checked against
//! the revisions this gateway speaks, on the first answer and on the GH #517
//! fallback retry, and the retry's selection is the one adopted.
//!
//! Unix-only: the fake backend is a `sh` script, which Windows does not
//! provide. The Windows build compiles the code under test but runs none of
//! these rows.

use super::*;
use std::collections::HashMap;

/// A revision no gateway release speaks.
const UNSUPPORTED: &str = "1999-01-01";

/// Text shaped like a credential the gateway might have sent, which a
/// diagnostic must never repeat.
const NOT_A_VERSION: &str = "Bearer sk-live-quoted-back";

/// Start a backend that rejects any `initialize` not proposing `accepts`
/// (listing `accepts` as its only supported revision) and answers one that
/// does by selecting `selects`. Each reply carries the id of the request it
/// answers, so the retry is routed like any other response.
async fn start_backend(
    accepts: &str,
    selects: &str,
) -> (tempfile::TempDir, Arc<StdioTransport>, Result<()>) {
    start_backend_with(accepts, selects, "").await
}

/// [`start_backend`], writing the lines in `before_answer` (each ending in
/// `\n`) ahead of the accepted `initialize` answer.
async fn start_backend_with(
    accepts: &str,
    selects: &str,
    before_answer: &str,
) -> (tempfile::TempDir, Arc<StdioTransport>, Result<()>) {
    start_backend_listing(accepts, accepts, selects, before_answer).await
}

/// [`start_backend_with`], whose rejection lists `lists` as the supported
/// revisions while it still accepts only `accepts`.
async fn start_backend_listing(
    lists: &str,
    accepts: &str,
    selects: &str,
    before_answer: &str,
) -> (tempfile::TempDir, Arc<StdioTransport>, Result<()>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"while IFS= read -r request; do
    id=$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    case "$request" in
        *'"method":"initialize"'*'"protocolVersion":"ACCEPTS"'*)
            printf '%s' 'BEFORE'
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"SELECTS","capabilities":{}}}\n' "$id"
            ;;
        *'"method":"initialize"'*)
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"Unsupported protocol version. Supported versions: LISTS"}}\n' "$id"
            ;;
    esac
done
"#
    .replace("LISTS", lists)
    .replace("ACCEPTS", accepts)
    .replace("SELECTS", selects)
    .replace("BEFORE", before_answer);
    std::fs::write(workspace.path().join("server.sh"), script).expect("write server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(10),
        None,
    );
    let outcome = transport.start().await;
    (workspace, transport, outcome)
}

/// Guard against a vacuous row: a backend that accepts the gateway's own
/// proposal exercises no fallback.
fn not_our_proposal(version: &'static str) -> &'static str {
    assert_ne!(
        version, PROTOCOL_VERSION,
        "the backend must reject the first proposal"
    );
    version
}

#[tokio::test]
async fn a_retry_that_selects_an_unsupported_revision_is_refused() {
    let (_workspace, transport, outcome) =
        start_backend(not_our_proposal("2025-06-18"), UNSUPPORTED).await;
    let _ = transport.close().await;

    let error = outcome.expect_err("a revision the gateway does not speak must not be adopted");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(error.to_string().contains(UNSUPPORTED), "{error}");
}

#[tokio::test]
async fn the_retry_selection_is_the_revision_adopted() {
    let proposed_on_retry = not_our_proposal("2025-06-18");
    let selected = not_our_proposal("2024-11-05");
    let (_workspace, transport, outcome) = start_backend(proposed_on_retry, selected).await;
    outcome.expect("a backend that selects a supported revision must start");

    let adopted = transport.protocol_version.read().clone();
    let _ = transport.close().await;
    assert_eq!(
        adopted.as_deref(),
        Some(selected),
        "the backend selects; what the retry proposed is not what was agreed"
    );
}

#[tokio::test]
async fn a_first_answer_that_selects_an_unsupported_revision_is_refused() {
    let (_workspace, transport, outcome) = start_backend(PROTOCOL_VERSION, UNSUPPORTED).await;
    let _ = transport.close().await;

    let error = outcome.expect_err("a revision the gateway does not speak must not be adopted");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(error.to_string().contains(UNSUPPORTED), "{error}");
}

#[tokio::test]
async fn a_selection_that_is_not_a_version_is_refused_without_being_repeated() {
    let (_workspace, transport, outcome) = start_backend(PROTOCOL_VERSION, NOT_A_VERSION).await;
    let _ = transport.close().await;

    let error = outcome.expect_err("a selection that is not a version must not be adopted");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(!error.to_string().contains(NOT_A_VERSION), "{error}");
}

/// Every tracing callsite enabled, so the handshake's log lines evaluate the
/// diagnostic command they name (MIK-8195 W7).
fn verbose() -> tracing::subscriber::DefaultGuard {
    crate::test_log_capture::keep_interest_open();
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .finish(),
    )
}

/// MIK-8195 W7: a rejection that lists no revision this gateway speaks ends
/// the start; nothing is retried and nothing is adopted.
#[tokio::test]
async fn a_rejection_listing_no_spoken_revision_ends_the_start() {
    let _log = verbose();
    let (_workspace, transport, outcome) = start_backend(UNSUPPORTED, UNSUPPORTED).await;
    let adopted = transport.protocol_version.read().clone();
    let _ = transport.close().await;

    let error = outcome.expect_err("no compatible revision means no session");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(
        error.to_string().contains("no compatible version"),
        "{error}"
    );
    assert_eq!(adopted, None, "a failed negotiation adopts nothing");
}

/// MIK-8195 W7: a backend that lists a revision this gateway speaks, then
/// rejects the retry proposing it, ends the start on the retry's error.
#[tokio::test]
async fn a_rejected_negotiated_retry_ends_the_start() {
    let _log = verbose();
    let listed = not_our_proposal("2025-06-18");
    let (_workspace, transport, outcome) =
        start_backend_listing(listed, UNSUPPORTED, UNSUPPORTED, "").await;
    let adopted = transport.protocol_version.read().clone();
    let _ = transport.close().await;

    let error = outcome.expect_err("a retry the backend still rejects is no session");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains(&format!("even with negotiated version {listed}")),
        "{error}"
    );
    assert_eq!(adopted, None, "a rejected retry adopts nothing");
}

/// MIK-8195 W7: the agreed revision is logged and adopted on a negotiated
/// retry the backend accepts.
#[tokio::test]
async fn an_accepted_negotiated_retry_is_logged_and_adopted() {
    let _log = verbose();
    let selected = not_our_proposal("2025-06-18");
    let (_workspace, transport, outcome) = start_backend(selected, selected).await;
    outcome.expect("an accepted retry starts the backend");
    let adopted = transport.protocol_version.read().clone();
    let _ = transport.close().await;
    assert_eq!(adopted.as_deref(), Some(selected));
}

/// MIK-8195 W7: a backend whose `initialize` fails for a reason other than
/// the protocol version ends the start, and the error names only its code:
/// the backend's own text may quote back a credential the gateway sent.
#[test]
fn a_non_version_initialize_error_ends_the_start_by_code_only() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"while IFS= read -r request; do
    id=$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    case "$request" in
        *'"method":"initialize"'*)
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32099,"message":"denied: QUOTED"}}\n' "$id"
            ;;
    esac
done
"#
    .replace("QUOTED", NOT_A_VERSION);
    std::fs::write(workspace.path().join("server.sh"), script).expect("write server");

    let mut ended = None;
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let transport = StdioTransport::new(
                    "sh server.sh",
                    HashMap::new(),
                    Some(workspace.path().to_string_lossy().into_owned()),
                    std::time::Duration::from_secs(10),
                    None,
                );
                let outcome = transport.start().await;
                let adopted = transport.protocol_version.read().clone();
                let _ = transport.close().await;
                ended = Some((outcome, adopted));
            });
    });
    let (outcome, adopted) = ended.expect("the start ran");

    let error = outcome.expect_err("a failed initialize is no session");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(
        error.to_string().contains("backend error code -32099"),
        "{error}"
    );
    assert!(!error.to_string().contains(NOT_A_VERSION), "{error}");
    assert_eq!(adopted, None, "a failed initialize adopts nothing");

    // Logs reach more readers than the caller: the backend's text must not
    // reach a record either.
    assert!(
        !records.is_empty(),
        "the capture must see the transport's records"
    );
    let leaked: Vec<_> = records
        .iter()
        .filter(|r| r.to_string().contains("sk-live"))
        .collect();
    assert!(leaked.is_empty(), "{leaked:#?}");
}

/// Neither a diagnostic nor the log may repeat what the backend sent: a
/// backend can quote a credential back, and logs reach more readers than
/// the caller does.
#[test]
fn a_backend_line_is_never_written_to_the_log() {
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (_workspace, transport, outcome) =
                    start_backend(PROTOCOL_VERSION, NOT_A_VERSION).await;
                let _ = transport.close().await;
                assert!(outcome.is_err(), "the selection must be refused");
            });
    });
    assert!(
        !records.is_empty(),
        "the capture must see the transport's records"
    );
    let leaked: Vec<_> = records
        .iter()
        .filter(|r| r.to_string().contains("sk-live"))
        .collect();
    assert!(leaked.is_empty(), "{leaked:#?}");
}

/// The peer's own fields are text it chose too: the method of a request or
/// notification it sends, and the id of an answer nobody asked for, must not
/// reach the log either.
#[test]
fn peer_methods_and_unmatched_ids_are_never_written_to_the_log() {
    const PEER_LINES: &str = concat!(
        r#"{"jsonrpc":"2.0","id":"sk-live-request-id","method":"sk-live-request"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"sk-live-notification"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":"sk-live-unmatched","result":{}}"#,
        "\n",
    );
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (_workspace, transport, outcome) =
                    start_backend_with(PROTOCOL_VERSION, PROTOCOL_VERSION, PEER_LINES).await;
                let _ = transport.close().await;
                outcome.expect("the peer's extra lines must not stop the start");
            });
    });
    for seen in [
        "Peer sent a request on the response stream",
        "Ignoring peer notification",
        "No pending request found for response",
    ] {
        assert!(
            records.iter().any(|r| r.to_string().contains(seen)),
            "the capture must see each peer line handled ({seen}): {records:#?}"
        );
    }
    let leaked: Vec<_> = records
        .iter()
        .filter(|r| r.to_string().contains("sk-live"))
        .collect();
    assert!(leaked.is_empty(), "{leaked:#?}");
}

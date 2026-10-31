// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON-RPC codes, pre-dispatch classification and the may-have-run
//! note for `Error`.

use super::{Error, MAY_HAVE_RUN, step_failure_text};

/// Every `BackendUnavailable` is raised before the request is
/// sent, so it frees an idempotency key; a lost round does not.
#[test]
fn backend_unavailable_is_pre_dispatch_and_a_lost_round_is_not() {
    assert!(Error::BackendUnavailable("svc".to_string()).is_pre_dispatch());
    assert!(!Error::Transport("reset".to_string()).is_pre_dispatch());
    assert!(!Error::BackendTimeout("slow".to_string()).is_pre_dispatch());
}

/// Case A: the gateway-sealed transient is pre-dispatch (it is
/// built only before a send); a look-alike with the same code, text and
/// data but no seal, as a backend could answer, is not. The seal decides,
/// never the text.
#[test]
fn only_the_sealed_transient_is_pre_dispatch() {
    let sealed = crate::personal_accounts::refusal::transient_retry_error(None);
    let Error::JsonRpc { code, message, .. } = &sealed else {
        panic!("premise: the transient is a JSON-RPC error: {sealed}");
    };
    let look_alike = Error::JsonRpc {
        code: *code,
        message: message.clone(),
        data: crate::personal_accounts::refusal::transient_data(&sealed),
    };
    assert!(sealed.is_pre_dispatch(), "{sealed}");
    assert!(!look_alike.is_pre_dispatch(), "{look_alike}");
}

/// `outcome_undetermined` is exactly "not pre-dispatch", so a
/// backend's answer at any status, a plain JSON-RPC error, a refusal and a
/// local error all read as "may have run"; a lost round always does, and
/// only the pre-dispatch allowlist reads as never sent.
#[test]
fn only_an_error_raised_before_the_send_is_a_determined_outcome() {
    let retryable = |status| Error::JsonRpcRetryable {
        code: -32000,
        message: "x".into(),
        status,
        data: None,
    };
    let undetermined = vec![
        Error::Transport("x".into()),
        Error::BackendTimeout("x".into()),
        Error::Io(std::io::Error::other("x")),
        Error::Config("x".into()),
        Error::Internal("x".into()),
        Error::Protocol("x".into()),
        Error::ResponseFirewallRefused,
        Error::JsonRpc {
            code: -32602,
            message: "x".into(),
            data: None,
        },
        retryable(408),
        retryable(429),
        retryable(500),
        retryable(502),
        retryable(503),
        retryable(504),
    ];
    for error in &undetermined {
        assert!(error.outcome_undetermined(), "{error:?}");
    }
    let determined = [
        Error::Forbidden {
            code: -32003,
            status: 403,
            message: "x".into(),
        },
        Error::gateway_refused(-32000, "x"),
        Error::TransportConnect("x".into()),
        Error::BackendUnavailable("x".into()),
        Error::BackendNotFound("x".into()),
        Error::ToolNotFound("x".into()),
        Error::RateLimited("x".into()),
    ];
    for error in &determined {
        assert!(!error.outcome_undetermined(), "{error:?}");
    }
    for lost in [
        Error::Transport("x".into()),
        Error::BackendTimeout("x".into()),
    ] {
        assert!(
            lost.is_lost_round() && lost.outcome_undetermined(),
            "{lost:?}"
        );
    }
    for status in [400, 500] {
        let response = axum::http::Response::builder()
            .status(status)
            .body(String::new())
            .expect("fixture response builds");
        let http = Error::Http(
            reqwest::Response::from(response)
                .error_for_status()
                .expect_err("a fixture status is non-2xx"),
        );
        assert!(http.outcome_undetermined(), "Http {status}");
    }
}

/// A step's text says it may have run, except a gateway refusal's, which
/// keeps its neutral reason (A3) and reads as raised before the send.
#[test]
fn only_a_refusal_keeps_its_step_text_unmarked() {
    let lost = Error::BackendTimeout("no answer".into());
    assert!(step_failure_text(&lost, lost.to_string()).ends_with(MAY_HAVE_RUN));
    let refused = Error::Forbidden {
        code: -32003,
        status: 403,
        message: "step not permitted for this caller".into(),
    };
    assert!(refused.is_pre_dispatch());
    assert_eq!(
        step_failure_text(&refused, refused.to_string()),
        "step not permitted for this caller"
    );
    let gated = Error::gateway_refused(-32000, "Server 'mail' is currently disabled");
    assert!(gated.is_pre_dispatch());
    assert_eq!(
        step_failure_text(&gated, gated.to_string()),
        gated.to_string(),
        "a gateway decision's refusal stays unmarked"
    );
    let offer = crate::personal_accounts::refusal::offer_error(
        -32042,
        "Connect your work account to continue.".into(),
        serde_json::json!({"schema_version": "accounts.v1", "account_id": "work"}),
    );
    assert_eq!(
        step_failure_text(&offer, "Connect your work account to continue.".into()),
        "Connect your work account to continue.",
        "a sealed offer's text is kept as written"
    );
    let unsent = Error::TransportConnect("refused".into());
    assert_eq!(
        step_failure_text(&unsent, unsent.to_string()),
        unsent.to_string()
    );
}

#[test]
fn a_permanent_transport_failure_reports_as_a_backend_error() {
    // Omitting the variant here reported a missing backend command as an
    // INTERNAL error, blaming the gateway for the operator's typo.
    assert_eq!(
        Error::TransportPermanent("Failed to spawn: no such file".to_string()).to_rpc_code(),
        -32000,
    );
    assert_eq!(
        Error::Transport("connection refused".to_string()).to_rpc_code(),
        -32000,
        "the two transport variants must look the same to a JSON-RPC caller"
    );
}

#[test]
fn a_refusal_keeps_the_peers_code_whichever_carriage_brings_it() {
    // A peer code recovered from a 429/503 body is the peer's answer, not a
    // gateway fault: omitting the retryable variant here reported an
    // exhausted backend refusal as INTERNAL and sent operators after the
    // wrong process.
    assert_eq!(
        Error::JsonRpcRetryable {
            code: -32601,
            message: "method not found".to_string(),
            status: 503,
            data: None,
        }
        .to_rpc_code(),
        -32601,
    );
}

/// The five standard JSON-RPC 2.0 codes keep their spec values
/// (written as literals here on purpose; every site migrated to these
/// names relies on them).
#[test]
fn the_standard_codes_keep_their_spec_values() {
    use super::rpc_codes::{
        INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR,
    };
    assert_eq!(
        [
            PARSE_ERROR,
            INVALID_REQUEST,
            METHOD_NOT_FOUND,
            INVALID_PARAMS,
            INTERNAL_ERROR
        ],
        [-32700, -32600, -32601, -32602, -32603]
    );
}

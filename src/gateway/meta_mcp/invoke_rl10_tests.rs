// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH475.RL.10: real executor errors through private dispatch consumers.

use super::{BudgetOutcome, MetaMcp, classify_dispatch_error};
use crate::backend::BackendRegistry;
use crate::capability::CapabilityExecutor;
use crate::gateway::recovery::{ErrorCategory, RecoveryContext, recovery_for};
use crate::{Error, Result};
use serde_json::Value;
use std::sync::Arc;

fn assert_budget_effect(error: Error, expected: BudgetOutcome, counts: (usize, usize)) {
    let result: Result<Value> = Err(error);
    let outcome = BudgetOutcome::of(&result);
    assert_eq!(outcome, expected);
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.record_error_budget("rl10", "fixture", outcome);
    assert_eq!(meta.kill_switch.window_counts("rl10"), counts);
    assert_eq!(
        meta.kill_switch.capability_window_counts("rl10", "fixture"),
        counts
    );
}

fn assert_typed_429(error: &Error, protocol: &str) {
    assert!(
        matches!(error, Error::Http(inner) if inner.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS)),
        "{protocol}: the consumer fixture must carry an actual typed429 error, got {error:?}"
    );
}

async fn assert_429_budget(protocol: &str) {
    let error = CapabilityExecutor::rl10_test_error(protocol, 429, "synthetic").await;
    assert_typed_429(&error, protocol);
    assert_budget_effect(error, BudgetOutcome::IgnoredRateLimit, (0, 0));
}

#[tokio::test]
async fn rl10_actual_429_changes_neither_budget_window_rest() {
    assert_429_budget("rest").await;
}

#[tokio::test]
async fn rl10_actual_429_changes_neither_budget_window_jsonrpc() {
    assert_429_budget("jsonrpc").await;
}

#[tokio::test]
async fn rl10_actual_429_changes_neither_budget_window_graphql() {
    assert_429_budget("graphql").await;
}

async fn assert_500_budget(protocol: &str) {
    let error = CapabilityExecutor::rl10_test_error(protocol, 500, "synthetic").await;
    assert!(matches!(&error, Error::Protocol(_)));
    assert_budget_effect(error, BudgetOutcome::Failure, (0, 1));
}

#[tokio::test]
async fn rl10_actual_500_records_failure_in_both_budget_windows_rest() {
    assert_500_budget("rest").await;
}

#[tokio::test]
async fn rl10_actual_500_records_failure_in_both_budget_windows_jsonrpc() {
    assert_500_budget("jsonrpc").await;
}

#[tokio::test]
async fn rl10_actual_500_records_failure_in_both_budget_windows_graphql() {
    assert_500_budget("graphql").await;
}

async fn assert_429_recovery(protocol: &str) {
    let body_secret = "RL10_RECOVERY_BODY_SECRET_27d691";
    let query_secret = "RL10_QUERY_SECRET_5e8d2c";
    let body =
        format!("{body_secret}: http://localhost/rl10-private-endpoint?api_key={query_secret}");
    let error = CapabilityExecutor::rl10_test_error(protocol, 429, &body).await;
    assert_typed_429(&error, protocol);
    let (category, detail) = classify_dispatch_error(&error);
    assert_eq!(category, ErrorCategory::RateLimited, "{protocol}");
    let hint = recovery_for(
        category,
        RecoveryContext {
            backend: Some("rl10"),
            tool: Some("fixture"),
            detail: Some(&detail),
            ..Default::default()
        },
    );
    assert_eq!(hint.error_code, "RATE_LIMITED", "{protocol}");
    assert!(
        hint.retry,
        "{protocol}: throttling must allow delayed retry"
    );
    for secret in [
        body_secret,
        query_secret,
        "localhost",
        "/rl10-private-endpoint",
        "api_key",
    ] {
        assert!(
            !detail.contains(secret),
            "{protocol}: recovery detail leaked {secret}"
        );
        assert!(
            !hint.message.contains(secret),
            "{protocol}: recovery hint leaked {secret}"
        );
    }
}

#[tokio::test]
async fn rl10_actual_429_has_rate_limited_retry_guidance_rest() {
    assert_429_recovery("rest").await;
}

#[tokio::test]
async fn rl10_actual_429_has_rate_limited_retry_guidance_jsonrpc() {
    assert_429_recovery("jsonrpc").await;
}

#[tokio::test]
async fn rl10_actual_429_has_rate_limited_retry_guidance_graphql() {
    assert_429_recovery("graphql").await;
}

async fn assert_non_429_recovery(protocol: &str) {
    for (status, category) in [
        (500, ErrorCategory::BackendError),
        (504, ErrorCategory::Timeout),
    ] {
        let error = CapabilityExecutor::rl10_test_error(protocol, status, "synthetic").await;
        assert_eq!(
            classify_dispatch_error(&error).0,
            category,
            "{protocol} {status}"
        );
    }
}

#[tokio::test]
async fn rl10_non_429_protocol_recovery_keeps_failure_and_timeout_categories_rest() {
    assert_non_429_recovery("rest").await;
}

#[tokio::test]
async fn rl10_non_429_protocol_recovery_keeps_failure_and_timeout_categories_jsonrpc() {
    assert_non_429_recovery("jsonrpc").await;
}

#[tokio::test]
async fn rl10_non_429_protocol_recovery_keeps_failure_and_timeout_categories_graphql() {
    assert_non_429_recovery("graphql").await;
}

#[tokio::test]
async fn rl10_other_typed_http_errors_are_failures_in_both_consumers() {
    for status in [403, 500] {
        let error = CapabilityExecutor::rl10_test_http_error(status).await;
        assert!(
            matches!(&error, Error::Http(inner) if inner.status().map(|s| s.as_u16()) == Some(status))
        );
        assert_eq!(
            classify_dispatch_error(&error).0,
            ErrorCategory::BackendError,
            "typed {status}"
        );
        assert_budget_effect(error, BudgetOutcome::Failure, (0, 1));
    }
}

#[tokio::test]
async fn rl10_statusless_transport_error_keeps_generic_classification() {
    let error = CapabilityExecutor::rl10_test_transport_error().await;
    assert!(matches!(&error, Error::Http(inner) if inner.status().is_none()));
    assert_eq!(
        classify_dispatch_error(&error).0,
        ErrorCategory::BackendError
    );
    assert_budget_effect(error, BudgetOutcome::Failure, (0, 1));
}

async fn assert_pending_reason_is_private(protocol: &str) {
    // GH475.RL10.C13/C14: all three protocols share the raw status-line fixture
    // with C12, including its never-completed body and bounded execute deadline.
    let raw = CapabilityExecutor::rl10_test_pending_reason_error(protocol).await;
    let error = raw.error;
    assert_typed_429(&error, protocol);
    let Error::Http(inner) = &error else {
        unreachable!()
    };
    assert!(inner.url().is_none(), "{protocol}: remove the URL field");
    assert_eq!(error.to_rpc_code(), -32000, "{protocol}");
    let (category, detail) = classify_dispatch_error(&error);
    assert_eq!(category, ErrorCategory::RateLimited, "{protocol}");
    let hint = recovery_for(
        category,
        RecoveryContext {
            backend: Some("rl10"),
            tool: Some("fixture"),
            detail: Some(&detail),
            ..Default::default()
        },
    );
    assert_eq!(hint.error_code, "RATE_LIMITED", "{protocol}");
    assert!(hint.retry, "{protocol}: preserve delayed retry");
    for secret in [
        raw.reflected_url.as_str(),
        raw.query_secret,
        "localhost",
        "/rl10-private-endpoint",
        "api_key",
    ] {
        assert!(
            !raw.warn_fields.contains(secret),
            "{protocol}: WARN leaked {secret}"
        );
        assert!(
            !error.to_string().contains(secret),
            "{protocol}: error leaked {secret}"
        );
        assert!(
            !detail.contains(secret),
            "{protocol}: detail leaked {secret}"
        );
        assert!(
            !hint.message.contains(secret),
            "{protocol}: hint leaked {secret}"
        );
    }
    assert_budget_effect(error, BudgetOutcome::IgnoredRateLimit, (0, 0));
}

#[tokio::test]
async fn rl10_pending_reason_429_stays_private_rest() {
    assert_pending_reason_is_private("rest").await;
}

#[tokio::test]
async fn rl10_pending_reason_429_stays_private_jsonrpc() {
    assert_pending_reason_is_private("jsonrpc").await;
}

#[tokio::test]
async fn rl10_pending_reason_429_stays_private_graphql() {
    assert_pending_reason_is_private("graphql").await;
}

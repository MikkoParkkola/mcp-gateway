// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787: a caller's argument is data, never a secret reference. A value
//! such as `{env.NAME}` in a query argument must reach the provider as that
//! text, not as the gateway's own secret.

use std::sync::Arc;

use serde_json::json;

use super::super::CapabilityExecutor;
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn executor_holding(vars: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, vars).expect("write env file");
    let overlay = EnvOverlay::from_paths(&[path]);
    let env = Arc::new(LiveEnv::new(Arc::new(overlay), ResolvedEnvFiles::default()));
    (dir, CapabilityExecutor::new().with_env(env))
}

#[test]
fn a_secret_reference_in_a_caller_value_is_not_expanded() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "{env.MIK7787_TEST_SECRET}" });
    let value = executor.substitute_string("{q}", &params).unwrap();
    assert_eq!(value, "{env.MIK7787_TEST_SECRET}");
    assert!(!value.contains("gateway-owned"));
}

#[test]
fn a_secret_reference_in_the_template_still_resolves() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "cats" });
    let value = executor
        .substitute_string("{q}:{env.MIK7787_TEST_SECRET}", &params)
        .unwrap();
    assert_eq!(value, "cats:gateway-owned");
}

#[test]
fn the_query_path_sends_a_caller_reference_as_text() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "see {env.MIK7787_TEST_SECRET}" });
    let template = std::collections::HashMap::from([("q".to_string(), "{q}".to_string())]);
    let pairs = executor.substitute_params(&template, &params).unwrap();
    assert_eq!(
        pairs,
        [("q".to_string(), "see {env.MIK7787_TEST_SECRET}".to_string())]
    );
}

#[test]
fn the_typed_body_path_sends_a_caller_reference_as_text() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "see {env.MIK7787_TEST_SECRET}" });
    let body = json!({ "query": "{q}", "note": "x {q}" });
    let out = executor.substitute_value(&body, &params).unwrap();
    assert_eq!(
        out,
        json!({ "query": "see {env.MIK7787_TEST_SECRET}", "note": "x see {env.MIK7787_TEST_SECRET}" })
    );
}

// MIK-7888: one pass over the template. A value that was substituted is data
// and is never scanned for placeholders again.

#[test]
fn a_secret_containing_a_placeholder_reaches_the_provider_byte_for_byte() {
    let (_dir, executor) = executor_holding("MIK7888_TOKEN=abc{q}xyz\n");
    let params = json!({ "q": "caller-text" });
    let value = executor
        .substitute_string("Bearer {env.MIK7888_TOKEN}", &params)
        .unwrap();
    assert_eq!(value, "Bearer abc{q}xyz");
}

#[test]
fn a_caller_value_that_looks_like_another_placeholder_is_not_expanded() {
    let (_dir, executor) = executor_holding("MIK7888_UNUSED=1\n");
    // Whichever key a map visits first, neither value is re-scanned.
    let params = json!({ "a": "{b}", "b": "B-VALUE" });
    let value = executor.substitute_string("{a}|{b}", &params).unwrap();
    assert_eq!(value, "{b}|B-VALUE");
}

#[test]
fn a_secret_containing_another_secret_reference_is_not_chained() {
    let (_dir, executor) = executor_holding("MIK7888_A=x{env.MIK7888_B}y\nMIK7888_B=second\n");
    let value = executor
        .substitute_string("{env.MIK7888_A}-{env.MIK7888_B}", &json!({}))
        .unwrap();
    assert_eq!(value, "x{env.MIK7888_B}y-second");
}

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
fn the_typed_and_query_paths_do_not_expand_a_caller_reference_either() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "{env.MIK7787_TEST_SECRET}" });
    let template = std::collections::HashMap::from([("q".to_string(), "{q}".to_string())]);
    let pairs = executor.substitute_params(&template, &params).unwrap();
    assert!(pairs.iter().all(|(_, v)| !v.contains("gateway-owned")));
}

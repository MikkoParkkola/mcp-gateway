// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4 / SECRET.1: a capability credential whose variable is set but empty is
//! refused, as `SecretRef::resolve` refuses one, instead of being sent as
//! `Authorization: Bearer ` with nothing after it.

use std::sync::Arc;

use super::super::CapabilityExecutor;
use crate::capability::{AuthConfig, CapabilityExecutionContext};
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn executor_with_blank_var() -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("c4.env");
    crate::gateway::test_helpers::write_owner_only(&path, "MCP_GW_C4_CAP_BLANK=\n")
        .expect("write env file");
    let overlay = EnvOverlay::from_paths(&[path]);
    let env = Arc::new(LiveEnv::new(Arc::new(overlay), ResolvedEnvFiles::default()));
    (dir, CapabilityExecutor::new().with_env(env))
}

#[tokio::test]
async fn empty_capability_credential_refused_in_every_env_form() {
    let (_dir, executor) = executor_with_blank_var();
    for key in [
        "env:MCP_GW_C4_CAP_BLANK",
        "{env.MCP_GW_C4_CAP_BLANK}",
        "MCP_GW_C4_CAP_BLANK",
    ] {
        let auth = AuthConfig {
            key: key.to_string(),
            ..AuthConfig::default()
        };
        let err = executor
            .fetch_credential(&auth, &CapabilityExecutionContext::default())
            .await
            .expect_err("an empty capability credential must be refused");
        assert!(
            err.to_string().contains("MCP_GW_C4_CAP_BLANK"),
            "{key}: the error must name the variable: {err}"
        );
    }
}

/// C9 leaves capability YAMLs out of the `file:` secret grammar: a third-party
/// capability must not read an arbitrary gateway-owned file and send it
/// upstream. The capability `file:` keeps its own `path.json:field` meaning.
#[tokio::test]
async fn capability_file_ref_stays_literal() {
    let (dir, executor) = executor_with_blank_var();
    let json = dir.path().join("cred.json");
    crate::gateway::test_helpers::write_owner_only(&json, r#"{"token":"c9-field"}"#)
        .expect("write json");
    let fetch = |key: String| {
        let auth = AuthConfig {
            key,
            ..AuthConfig::default()
        };
        let executor = &executor;
        async move {
            executor
                .fetch_credential(&auth, &CapabilityExecutionContext::default())
                .await
        }
    };
    assert_eq!(
        fetch(format!("file:{}:token", json.display()))
            .await
            .unwrap(),
        "c9-field",
        "the capability grammar extracts a JSON field"
    );
    let whole = fetch("file:/etc/passwd".to_string())
        .await
        .expect_err("a whole-file secret is not a capability credential");
    assert!(
        whole.to_string().contains("Invalid file credential format"),
        "{whole}"
    );
}

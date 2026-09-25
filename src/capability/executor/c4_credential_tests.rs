// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4 / SECRET.1: a capability credential whose variable is set but empty is
//! refused, as `SecretRef::resolve` refuses one, instead of being sent as
//! `Authorization: Bearer ` with nothing after it.

use std::sync::Arc;

use super::CapabilityExecutor;
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

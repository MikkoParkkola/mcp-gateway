// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's secret-injection rules apply on the direct route
//! `/mcp/{name}` as they do through `gateway_invoke`: an `argument` rule's
//! secret reaches the backend in the tool call's arguments.

use serde_json::json;

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::{Answer, fixture_built};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget, SecretInjector};

/// The secret the rule injects: a literal, so no environment is read.
const SECRET: &str = "direct-route-secret-4c1e";

/// One `argument` rule on `backend`, injecting [`SECRET`] as `api_key`.
fn injector(backend: &str) -> SecretInjector {
    SecretInjector::new(std::collections::HashMap::from([(
        backend.to_string(),
        vec![CredentialRule {
            name: "api".to_string(),
            credential_type: CredentialType::ApiKey,
            value: SECRET.to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]))
}

/// The direct route applies an `argument` rule, on a gated and a passthrough
/// backend.
#[tokio::test]
async fn the_direct_route_applies_an_argument_rule() {
    for backend in ["alpha", "alpha-pt"] {
        let fx = fixture_built(Answer::Ok, |meta| {
            meta.with_secret_injector(injector(backend))
        })
        .await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: premise: {body}");
        let seen = fx.seen.lock().expect("recorder").clone();
        assert!(
            seen.iter()
                .any(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET))),
            "{backend}: the argument rule's secret never reached the backend: {seen:?}"
        );
    }
}

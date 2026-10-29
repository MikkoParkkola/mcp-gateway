// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What `DirectRouteGuards::run` records on the delivery: the session
//! profile's refusal raises `refused` there, where the direct route delivers
//! it; a sealed refusal (a disabled capability) passes through unraised and
//! raises where it is framed.

use super::direct_guards::DirectRouteGuards;
use super::direct_guards_fixture::{Answer, Fx, fixture, fixture_built};
use crate::gateway::delivery_facts;
use crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall;
use crate::gateway::meta_mcp::signing::SigningScope;

/// `alpha`'s `read` as key `k-std`.
fn read_call() -> BackendCall<'static> {
    BackendCall {
        server: "alpha",
        tool: "read",
        session_id: None,
        api_key_name: Some("k-std"),
        cost_key: Some("k-std"),
        trace_id: "",
        caller_key: None,
    }
}

/// The guards' result for [`read_call`], and whether its cell holds a refusal.
async fn guarded(fx: &Fx) -> (crate::Result<()>, bool) {
    let call = read_call();
    delivery_facts::scope(async {
        let guarded =
            DirectRouteGuards::run(&fx.state.meta_mcp, &call, SigningScope::EveryToolCall);
        let refused = delivery_facts::snapshot().expect("a cell").refused();
        (guarded, refused)
    })
    .await
}

/// A tool the session profile excludes is refused, and the guards raise it.
#[tokio::test]
async fn a_session_profile_refusal_is_raised_by_the_guards() {
    let fx = fixture_built(Answer::Ok, |meta| {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "restricted".to_string(),
            crate::routing_profile::RoutingProfileConfig {
                description: "a profile that excludes alpha's read".to_string(),
                deny_tools: Some(vec!["read".to_string()]),
                ..Default::default()
            },
        );
        meta.with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles,
            "restricted",
        ))
    })
    .await;
    let (guarded, refused) = guarded(&fx).await;
    let error = guarded.expect_err("the profile excludes the tool");
    assert!(
        matches!(error, crate::Error::Protocol(_)),
        "the profile's refusal: {error:?}"
    );
    assert!(refused, "not raised by the guards");
}

/// The guards pass a sealed admission refusal (a disabled capability)
/// through unchanged and raise nothing for it: it raises where it is framed.
#[tokio::test]
async fn a_sealed_admission_refusal_passes_through_the_guards_unraised() {
    let fx = fixture(Answer::Ok, |meta| {
        let cfg = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();
        for _ in 0..cfg.min_samples.max(cfg.window_size) {
            meta.kill_switch()
                .record_capability_failure("alpha", "read", &cfg);
        }
    })
    .await;
    let (guarded, refused) = guarded(&fx).await;
    let error = guarded.expect_err("a disabled capability is refused");
    assert!(
        !matches!(error, crate::Error::Protocol(_)),
        "the capability refusal, not a profile one: {error:?}"
    );
    assert!(!refused, "raised by the guards");
}

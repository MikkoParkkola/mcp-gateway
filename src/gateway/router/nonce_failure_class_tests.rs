// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8379 D4 (lead ruling, parity per failure class): for every class
//! `Error::is_pre_dispatch` admits, a signed call whose dispatch fails with it
//! keeps its nonce on `/mcp` and on the direct route alike. On `/mcp` the send
//! spends the witness first (`invoke.rs`, before `mark_dispatched`) and no
//! refund site handles these classes; the direct route copies that answer at
//! its failure site (`answer_failure`). Each row warms the schema first, so the
//! KEEP comes from the send and not from a tool-list fill, and runs both
//! direct backends plus the `/mcp` twin.
//!
//! The error is raised by the scripted transport, the point where a real
//! start or send failure surfaces; every class reaches the same answer arm.
//! `ToolNotFound` never arises at the send on either route: only capability
//! grant evaluation raises it, before the send, where `/mcp` refunds it at the
//! chokepoint with the witness. Its row pins the mechanism, not a real path.

use serde_json::json;

use super::direct_continuation_tests::{BACKENDS, dispatched};
use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed};

fn refused_as_replay(body: &serde_json::Value) -> bool {
    body.to_string().to_lowercase().contains("replay")
}

/// Warm `backend`'s shared tool list, so the failing call fills nothing.
async fn warm(fx: &Fx, backend: &str) -> std::sync::Arc<crate::backend::Backend> {
    let registered = fx.state.backends.get(backend).expect("fixture backend");
    registered
        .get_tools_shared()
        .await
        .expect("warm the tool list");
    registered
}

/// The direct route and `/mcp`, each on a fresh fixture whose sends fail with
/// `make`: the failing call keeps its nonce, so the same nonce re-sent is a
/// replay and the backend is not tried again.
async fn keeps_on_both_routes(class: &str, make: fn() -> crate::Error) {
    assert!(
        make().is_pre_dispatch(),
        "{class}: premise: a pre-dispatch class"
    );
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::FailsWith(make), true).await;
        let target = warm(&fx, backend).await;
        let fills = target.list_fills();
        let who = ("k-std", backend);
        let (_, failed) =
            super::direct_continuation_tests::signed_call(&fx, who, "d1", json!({})).await;
        assert!(
            failed.get("error").is_some() || failed["result"]["isError"] == true,
            "{class} direct {backend}: {failed}"
        );
        assert_eq!(
            target.list_fills(),
            fills,
            "{class} direct {backend}: premise: no fill"
        );
        assert_eq!(
            dispatched(&fx),
            1,
            "{class} direct {backend}: the send was attempted"
        );
        let (_, again) =
            super::direct_continuation_tests::signed_call(&fx, who, "d1", json!({})).await;
        assert!(
            refused_as_replay(&again),
            "{class} direct {backend}: the nonce was given back: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{class} direct {backend}: tried again");
    }
    let fx = fixture_hardened_signed(Answer::FailsWith(make), true).await;
    let target = warm(&fx, "alpha").await;
    let fills = target.list_fills();
    let who = ("k-std", "alpha");
    let (_, failed) = super::mcp_nonce_witness_tests::signed_call(&fx, who, "m1", json!({})).await;
    assert!(
        failed.get("error").is_some() || failed["result"]["isError"] == true,
        "{class} /mcp: {failed}"
    );
    assert_eq!(target.list_fills(), fills, "{class} /mcp: premise: no fill");
    assert_eq!(dispatched(&fx), 1, "{class} /mcp: the send was attempted");
    let (_, again) = super::mcp_nonce_witness_tests::signed_call(&fx, who, "m1", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "{class} /mcp: the nonce was given back: {again}"
    );
    assert_eq!(dispatched(&fx), 1, "{class} /mcp: tried again");
}

macro_rules! class_row {
    ($name:ident, $class:literal, $make:expr) => {
        #[tokio::test]
        async fn $name() {
            keeps_on_both_routes($class, $make).await;
        }
    };
}

class_row!(
    a_circuit_open_dispatch_keeps_the_nonce_on_both_routes,
    "CircuitOpen",
    || {
        crate::Error::CircuitOpen {
            backend: "b".into(),
            last_failure: None,
        }
    }
);
class_row!(
    a_rate_limited_dispatch_keeps_the_nonce_on_both_routes,
    "RateLimited",
    || { crate::Error::RateLimited("b".into()) }
);
class_row!(
    a_slots_exhausted_dispatch_keeps_the_nonce_on_both_routes,
    "IdentitySlotsExhausted",
    || {
        crate::Error::IdentitySlotsExhausted {
            backend: "b".into(),
            limit: "per-backend",
        }
    }
);
class_row!(
    a_backend_not_found_dispatch_keeps_the_nonce_on_both_routes,
    "BackendNotFound",
    || { crate::Error::BackendNotFound("b".into()) }
);
class_row!(
    a_tool_not_found_dispatch_keeps_the_nonce_on_both_routes,
    "ToolNotFound",
    || { crate::Error::ToolNotFound("read".into()) }
);
class_row!(
    an_unreachable_backend_keeps_the_nonce_on_both_routes,
    "TransportConnect",
    || { crate::Error::TransportConnect("no route".into()) }
);
class_row!(
    an_unavailable_backend_keeps_the_nonce_on_both_routes,
    "BackendUnavailable",
    || { crate::Error::BackendUnavailable("b".into()) }
);
class_row!(
    an_incomplete_login_keeps_the_nonce_on_both_routes,
    "AuthorizationIncomplete",
    || {
        crate::Error::AuthorizationIncomplete {
            backend: "b".into(),
            window_secs: 60,
        }
    }
);
class_row!(
    a_cancelled_login_keeps_the_nonce_on_both_routes,
    "AuthorizationCancelled",
    || {
        crate::Error::AuthorizationCancelled {
            backend: "b".into(),
        }
    }
);
class_row!(
    a_required_login_keeps_the_nonce_on_both_routes,
    "AuthorizationRequired",
    || {
        crate::Error::AuthorizationRequired {
            backend: "b".into(),
        }
    }
);
class_row!(
    a_pending_login_keeps_the_nonce_on_both_routes,
    "AuthorizationPending",
    || {
        crate::Error::AuthorizationPending {
            backend: "b".into(),
        }
    }
);

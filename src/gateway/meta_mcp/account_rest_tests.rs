// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! REST capabilities dispatching through the ONE account credential boundary.
//!
//! THE CLAIM UNDER TEST. A REST capability whose `auth.account` names an
//! `accounts.descriptors` map key executes as the VERIFIED caller, using the
//! same `IdentityPropagation` strategy instance the shared installer built for
//! that descriptor — the same custody, the same five-field account key, the same
//! mandatory release recheck an MCP backend gets. Not a second store, not a
//! second auth enum, not a managed-token branch beside the resolver.
//!
//! THE REFUSALS ARE PROVED BY ABSENCE. Every negative case asserts ZERO requests
//! at the real capture endpoint. That is what "before HTTP and before the legacy
//! operator OAuth lookup" means operationally: the endpoint would have recorded
//! a call, and the legacy path would have produced the gateway-held token, so a
//! recorded count of zero and an error that does not carry a token is the only
//! outcome that can pass.
//!
//! THE POSITIVE CONTROL IS FIRST. If the endpoint were unreachable every
//! refusal test would pass vacuously, so the Alice/Bob case establishes that the
//! very same capability, arguments and backend DO reach the wire.

mod dispatch_and_refusals;
mod multi_user;
mod warm_cache;

use std::sync::Arc;

use serde_json::json;

use crate::capability::CapabilityExecutor;
use crate::identity_propagation::AccountStrategyRegistry;
use crate::personal_accounts::AccountCustody;

use super::account_resolver_fixture::{
    ALICE_PERSONAL_TOKEN, ALICE_WORK_TOKEN, BOB_WORK_TOKEN, PERSONAL, ROTATED_TOKEN,
    STATIC_FALLBACK, WORK, account_key, custody_with, grant, identity, reconnect_from,
    revoke_and_reconnect,
};
use super::account_rest_fixture::{
    Captured, EXPIRED_EXTERNAL_TOKEN, TOOL, backend_with, cacheable_base_url, cacheable_capability,
    caching_context, caching_executor, call, capability, capability_requiring_argument,
    capture_endpoint, context, declared_only, external, installed_expired_external,
    installed_gateway, managed, meta_execute, multi_user_caching_backend, prepared_caching_context,
    shared,
};

/// The gateway-held login a fallback would reach for. Seeded in the caching
/// cases as a TRAP: it is a perfectly valid legacy `oauth:google` token, so a
/// refusal that leaves it unused is a refusal that chose to fail closed with a
/// working alternative in hand.
const LEGACY_TRAP_TOKEN: &str = "synthetic-operator-legacy-trap-token-3d0a";

/// Never-expiring, so no case takes the refresh path by accident.
const FRESH: u64 = u64::MAX;

fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// A host that cannot resolve. Used where the assertion is that resolution
/// refused BEFORE the wire; if a refusal ever regressed into a dispatch, the
/// failure would be a transport error, not a silent pass.
const UNROUTABLE: &str = "https://rest-account-control.invalid";

fn assert_no_credential_leaked(error: &crate::Error, captured: &Captured) {
    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN)
            && !text.contains(BOB_WORK_TOKEN)
            && !text.contains(STATIC_FALLBACK),
        "a refusal must carry neither an account token nor a static credential: {text}"
    );
    assert_eq!(
        captured.count(),
        0,
        "the refusal must happen before any HTTP request reaches the backend"
    );
}

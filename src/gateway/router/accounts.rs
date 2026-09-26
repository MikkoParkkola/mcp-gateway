// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The hosted `/accounts/v1` surface (MIK-6745 design §4.3, §6.4).
//!
//! `DELETE /accounts/v1/connections/{account_id}` (§8.2, §8.3) is mounted
//! once and names its principal by exactly one credential: the adapter's
//! `VerifiedIdentity` or the bridge-verified Open `WebUI` session. The account
//! key is built from that principal and the configured descriptor, so a caller
//! can only ever name their own account; nothing in the path or body can
//! select another principal's entry.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use super::AppState;
use crate::config::{Config, account_bindings};
use crate::identity_propagation::audit_identity_propagation;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::identity::{Principal, account_key};
use crate::personal_accounts::{
    AccountHandles, AccountKey, AccountRevocation, GatewayCustody, JourneyService, ProviderOutcome,
};

#[path = "accounts/bridge.rs"]
mod bridge;
#[path = "accounts/callback.rs"]
mod callback;
#[path = "accounts/complete.rs"]
mod complete;
#[path = "accounts/connections.rs"]
mod connections;
#[path = "accounts/envelope.rs"]
mod envelope;
#[path = "accounts/hosted.rs"]
mod hosted;
#[path = "accounts/journeys.rs"]
mod journeys;
#[path = "accounts/start.rs"]
mod start;

pub(crate) use hosted::CALLBACK;
pub(crate) use journeys::ConnectOffers;

const ROUTE: &str = "/accounts/v1/connections/{account_id}";

/// The gateway's custody as the handles the router holds.
pub(crate) fn account_handles_of(custody: Option<&Arc<GatewayCustody>>) -> Option<AccountHandles> {
    custody.map(|custody| AccountHandles {
        revocation: Arc::clone(custody) as Arc<dyn AccountRevocation>,
        journeys: Arc::clone(custody) as Arc<dyn JourneyService>,
    })
}

/// The whole `/accounts/v1` router, or `None` unless `accounts.hosted` is
/// configured and custody is up; then the prefix is the ordinary 404.
/// `authenticate` applies the main chain's auth layers to the owner routes
/// and, separately, to the API half of `DELETE` (§6.4: mounted once).
pub(super) fn router(
    handles: Option<AccountHandles>,
    config: &Config,
    authenticate: impl Fn(Router<Arc<AppState>>) -> Router<Arc<AppState>>,
) -> Option<Router<Arc<AppState>>> {
    let hosted = config
        .accounts
        .as_ref()
        .is_some_and(|accounts| accounts.hosted.is_some());
    let AccountHandles {
        revocation,
        journeys,
    } = handles.filter(|_| hosted)?;
    let create = Arc::clone(&journeys);
    let reading = Arc::clone(&journeys);
    let owner = Router::new()
        .route(
            "/accounts/v1/journeys",
            post(move |state, identity, body| journeys::create(create, state, identity, body)),
        )
        .route(
            "/accounts/v1/journeys/{id}",
            get(move |state, identity, id| journeys::status(reading, state, identity, id)),
        );
    let api_delete = authenticate(connections::api_route(Arc::clone(&revocation)));
    let browser = browser_routes(journeys, revocation, api_delete);
    Some(hosted::shell(authenticate(owner).merge(browser)))
}

/// Routes a browser reaches with its Open `WebUI` session; merged AFTER
/// `authenticate`, so no auth layer wraps them. `DELETE` stays mounted for
/// API callers, and the callback (which needs no bridge), even when the
/// bridge client cannot be built.
fn browser_routes(
    journeys: Arc<dyn JourneyService>,
    revocation: Arc<dyn AccountRevocation>,
    api_delete: Router<Arc<AppState>>,
) -> Router<Arc<AppState>> {
    let bridge = bridge::OwuiSessionBridge::new()
        .inspect_err(|error| {
            tracing::error!(%error, "Open WebUI session bridge client unavailable");
        })
        .ok()
        .map(Arc::new);
    let disconnect = connections::route(api_delete, Arc::clone(&revocation), bridge.clone());
    let completing = Arc::clone(&journeys);
    let routes = Router::new().route(ROUTE, disconnect).route(
        CALLBACK,
        get(move |state, uri, headers| callback::callback(completing, state, uri, headers)),
    );
    let Some(bridge) = bridge else {
        return routes;
    };
    let starting = Arc::clone(&bridge);
    routes
        .route(
            start::START,
            get(move |state, id, headers| start::start(journeys, starting, state, id, headers)),
        )
        .merge(complete::routes(revocation, bridge))
}

/// Revoke `identity`'s own `account_id` (§8.2): tombstone, evict, audit, then
/// the provider. Whoever authenticated the caller, the key is theirs alone.
async fn revoke_for(
    state: &AppState,
    revocation: &dyn AccountRevocation,
    identity: &VerifiedIdentity,
    account_id: String,
) -> Response {
    let config = state.live_config.get();
    let key = match own_key(&config, identity, &account_id) {
        Ok(key) => key,
        Err(NoKey::NotFound) => return envelope::refusal(StatusCode::NOT_FOUND, "not_found", None),
        Err(NoKey::Unavailable) => {
            tracing::error!("account descriptors do not compile; revoke refused");
            return envelope::refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None);
        }
    };
    let Ok(material) = revocation.invalidate(&key).await else {
        return envelope::refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None);
    };
    evict_slots(state, &config, &key, &account_id).await;
    let audited = audit_identity_propagation(
        state.transparency_log.as_ref(),
        "account_revoke",
        &identity.stable_actor_id(),
        &account_id,
        None,
        None,
    )
    .await;
    // The provider call runs even without an audit row: the tokens were
    // captured once and are wiped on drop, so withholding them would leave
    // the grant live at the provider with no later chance to revoke it.
    let outcome = revocation.revoke_at_provider(&account_id, material).await;
    if outcome == ProviderOutcome::Failed {
        tracing::warn!(%account_id, "provider revocation failed; the grant may stay live upstream");
    }
    revoked_response(&account_id, outcome, &audited)
}

/// The DELETE answer once the tombstone is durable: 200, or 503
/// `audit_unavailable` that still reports what the provider said.
fn revoked_response<E>(
    account_id: &str,
    outcome: ProviderOutcome,
    audited: &Result<(), E>,
) -> Response {
    if audited.is_err() {
        let mut body = envelope::body("audit_unavailable", true);
        body["local_status"] = json!("revoked");
        body["provider_revocation"] = json!(outcome.as_str());
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response();
    }
    let body = json!({"schema_version": envelope::SCHEMA, "account_id": account_id,
                      "status": "revoked", "provider_revocation": outcome.as_str()});
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// Why no key: the id names no managed descriptor (404), or the live
/// descriptor set does not compile, so no id can be judged at all (503).
enum NoKey {
    NotFound,
    Unavailable,
}

/// The caller's own key for a configured `personal_managed` descriptor.
fn own_key(
    config: &Config,
    identity: &VerifiedIdentity,
    account_id: &str,
) -> Result<AccountKey, NoKey> {
    let descriptors =
        account_bindings::compile_descriptors(config).map_err(|_| NoKey::Unavailable)?;
    let descriptor = descriptors
        .into_iter()
        .find(|compiled| compiled.descriptor_id == account_id)
        .and_then(|compiled| compiled.account)
        .ok_or(NoKey::NotFound)?;
    account_key(Some(Principal::Verified(identity)), &descriptor).map_err(|_| NoKey::NotFound)
}

/// Drop upstream sessions minted under any generation of this account. The
/// prefix is the stable head of `cache_binding`; response caches need no sweep
/// because their bindings carry a generation no lease can be issued for again.
/// Every skipped eviction is logged under an 8-character digest prefix only.
async fn evict_slots(state: &AppState, config: &Config, key: &AccountKey, account_id: &str) {
    let Ok(digest) = key.digest() else {
        tracing::warn!(%account_id, "revoke evicted no sessions: account key has no digest");
        return;
    };
    let tag = digest.get(..8).unwrap_or_default();
    let Ok(bound) = account_bindings::compile(config) else {
        tracing::warn!(
            %account_id,
            account = tag,
            "revoke evicted no sessions: bindings do not compile"
        );
        return;
    };
    let prefix = format!("acct:v1:{digest}:");
    for (name, binding) in &bound {
        if binding.descriptor_id != account_id {
            continue;
        }
        let Some(backend) = state.backends.get(name) else {
            tracing::warn!(
                %account_id,
                account = tag,
                backend = %name,
                "revoke evicted no sessions: bound backend not registered"
            );
            continue;
        };
        backend.evict_identity_slots(&prefix).await;
    }
}

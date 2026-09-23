// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The hosted `/accounts/v1` surface (MIK-6745 design §4.3, §6.4).
//!
//! `DELETE /accounts/v1/connections/{account_id}` (§8.2) is API credential
//! only: it sits behind `auth_middleware` and the `OpenWebUI` adapter, and the
//! principal is the `VerifiedIdentity` the adapter inserted. The account key is
//! built from that principal and the configured descriptor, so a caller can
//! only ever name their own account; nothing in the path or body can select
//! another principal's entry.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::json;

use super::AppState;
use crate::config::{Config, account_bindings};
use crate::identity_propagation::audit_identity_propagation;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::identity::{Principal, account_key};
use crate::personal_accounts::{
    AccountHandles, AccountKey, AccountRevocation, GatewayCustody, JourneyService,
};

#[path = "accounts/hosted.rs"]
mod hosted;
#[path = "accounts/journeys.rs"]
mod journeys;

pub(crate) use hosted::CALLBACK;

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
/// `authenticate` applies the main chain's auth layers to the owner routes.
pub(super) fn router(
    handles: Option<AccountHandles>,
    config: &Config,
    authenticate: impl FnOnce(Router<Arc<AppState>>) -> Router<Arc<AppState>>,
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
    let owner = Router::new()
        .route(
            "/accounts/v1/journeys",
            post(move |state, identity, body| journeys::create(create, state, identity, body)),
        )
        .route(
            "/accounts/v1/journeys/{id}",
            get(move |state, identity, id| journeys::status(journeys, state, identity, id)),
        )
        .route(
            ROUTE,
            delete(
                move |State(state): State<Arc<AppState>>,
                      Path(account_id): Path<String>,
                      request| {
                    let revocation = Arc::clone(&revocation);
                    async move { delete_connection(state, revocation, account_id, request).await }
                },
            ),
        );
    Some(hosted::shell(authenticate(owner)))
}

async fn delete_connection(
    state: Arc<AppState>,
    revocation: Arc<dyn AccountRevocation>,
    account_id: String,
    request: Request,
) -> Response {
    // Only the adapter's verified identity names a principal here; a bare API
    // key or a path segment never does.
    let Some(identity) = request.extensions().get::<VerifiedIdentity>().cloned() else {
        return refusal(StatusCode::UNAUTHORIZED, "unauthenticated");
    };
    let config = state.live_config.get();
    let Some(key) = own_key(&config, &identity, &account_id) else {
        return refusal(StatusCode::NOT_FOUND, "not_found");
    };
    let Ok(material) = revocation.invalidate(&key).await else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");
    };
    evict_slots(&state, &config, &key, &account_id).await;
    let audited = audit_identity_propagation(
        state.transparency_log.as_deref(),
        "account_revoke",
        &identity.stable_actor_id(),
        &account_id,
        None,
        None,
    );
    if audited.is_err() {
        // The tombstone stands; only the provider call is withheld.
        let body = json!({"schema_version": 1, "error": "audit_unavailable",
                          "local_status": "revoked"});
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response();
    }
    let outcome = revocation.revoke_at_provider(&account_id, material).await;
    let body = json!({"schema_version": 1, "account_id": account_id, "status": "revoked",
                      "provider_revocation": outcome.as_str()});
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// The caller's own key for a managed descriptor, or `None` for an id that is
/// not a configured `personal_managed` descriptor.
fn own_key(config: &Config, identity: &VerifiedIdentity, account_id: &str) -> Option<AccountKey> {
    let descriptors = account_bindings::compile_descriptors(config).ok()?;
    let descriptor = descriptors
        .into_iter()
        .find(|compiled| compiled.descriptor_id == account_id)?
        .account?;
    account_key(Some(Principal::Verified(identity)), &descriptor).ok()
}

/// Drop upstream sessions minted under any generation of this account. The
/// prefix is the stable head of `cache_binding`; response caches need no sweep
/// because their bindings carry a generation no lease can be issued for again.
async fn evict_slots(state: &AppState, config: &Config, key: &AccountKey, account_id: &str) {
    let (Ok(digest), Ok(bound)) = (key.digest(), account_bindings::compile(config)) else {
        return;
    };
    let prefix = format!("acct:v1:{digest}:");
    for (name, binding) in &bound {
        if binding.descriptor_id != account_id {
            continue;
        }
        if let Some(backend) = state.backends.get(name) {
            backend.evict_identity_slots(&prefix).await;
        }
    }
}

fn refusal(status: StatusCode, error: &str) -> Response {
    (
        status,
        axum::Json(json!({ "schema_version": 1, "error": error })),
    )
        .into_response()
}

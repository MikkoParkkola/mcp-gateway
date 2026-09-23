// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /accounts/v1/connections/{account_id}` (MIK-6745 design §8.2).
//!
//! API credential only: the route sits behind `auth_middleware` and the
//! `OpenWebUI` adapter, and the principal is the `VerifiedIdentity` the adapter
//! inserted. The account key is built from that principal and the configured
//! descriptor, so a caller can only ever name their own account; nothing in
//! the path or body can select another principal's entry.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::delete;
use serde_json::json;

use super::AppState;
use crate::config::Config;
use crate::personal_accounts::{AccountRevocation, GatewayCustody};

const ROUTE: &str = "/accounts/v1/connections/{account_id}";

/// The gateway's custody as the revoke handle the router holds.
pub(crate) fn revocation_of(
    custody: Option<&Arc<GatewayCustody>>,
) -> Option<Arc<dyn AccountRevocation>> {
    custody.map(|custody| Arc::clone(custody) as Arc<dyn AccountRevocation>)
}

/// Mount the route only when `accounts.hosted` is configured and custody is
/// up. Otherwise the router is unchanged and the path is the ordinary 404.
pub(super) fn mount(
    routes: Router<Arc<AppState>>,
    revocation: Option<Arc<dyn AccountRevocation>>,
    config: &Config,
) -> Router<Arc<AppState>> {
    let hosted = config
        .accounts
        .as_ref()
        .is_some_and(|accounts| accounts.hosted.is_some());
    let Some(revocation) = revocation.filter(|_| hosted) else {
        return routes;
    };
    routes.route(
        ROUTE,
        delete(
            move |State(state): State<Arc<AppState>>, Path(account_id): Path<String>, request| {
                let revocation = Arc::clone(&revocation);
                async move { delete_connection(state, revocation, account_id, request).await }
            },
        ),
    )
}

async fn delete_connection(
    _state: Arc<AppState>,
    _revocation: Arc<dyn AccountRevocation>,
    _account_id: String,
    _request: Request,
) -> Response {
    refusal(StatusCode::NOT_IMPLEMENTED, "not_implemented")
}

fn refusal(status: StatusCode, error: &str) -> Response {
    (status, axum::Json(json!({ "schema_version": 1, "error": error }))).into_response()
}

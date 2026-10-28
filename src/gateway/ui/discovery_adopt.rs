// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/discovery/adopt`: one find from another client's config
//! file becomes a disabled backend in gateway.yaml (ADR-021, ADR-024).
//!
//! The caller names a find and the gateway.yaml revision it was listed
//! against; it never supplies a command, URL or value. The find is read
//! again from its client file, judged by the shared adopt rule, its literal
//! values go to the secret store, and the one locked writer splices the
//! backend in place or refuses. No answer or log line holds a value, URL,
//! argument or file text.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::super::errors::{admin_auth_required, config_path_unavailable, flat_error};
use super::super::is_admin;
use super::{Gateway, name_refusal, read_gateway};
use crate::config::SecretStoreChoice;
use crate::config_persistence::{NOT_IN_PLACE, edit_text};
use crate::config_reload::{
    Expected, FileRevision, RELOAD_LOCK_WAIT, Replace, ReplaceError, ReplaceOutcome, Replaced,
    SecretStep, replace_detached,
};
use crate::discovery::DiscoveredServer;
use crate::discovery::adopt::{AdoptRefusal, Adoption, Literal, adoption, refusals};
use crate::discovery::listing::{DiscoveryCache, ScanTimedOut};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::secret_store::{
    NewSecretOwned, SaveError, SecretStore, StoreError, Vault, choose_store,
};

/// The compute's refusal when the name is already a backend in the bytes
/// it was handed.
const MANAGED: &str = "managed";
/// The compute's refusal when the store returned a different number of
/// references than there are literals: a bug, never the caller's.
const REFERENCES: &str = "references";

/// The adopt body: a find and the revision it was listed against.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdoptBody {
    find_id: String,
    revision: String,
}

/// One refused find: every reason with its field, never a value.
fn not_adoptable(reasons: &[(&'static str, String)]) -> Response {
    let gateway_side = reasons
        .iter()
        .any(|(code, _)| matches!(*code, "managed" | "capabilities_name"));
    let status = if gateway_side {
        StatusCode::CONFLICT
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let refusals: Vec<_> = reasons
        .iter()
        .map(|(reason, field)| json!({"reason": reason, "field": field}))
        .collect();
    (
        status,
        Json(json!({"error": "not_adoptable", "refusals": refusals})),
    )
        .into_response()
}

fn stale(current: &FileRevision) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({"error": "stale", "current": current.as_str()})),
    )
        .into_response()
}

fn fixed(status: StatusCode, message: &'static str) -> Response {
    flat_error(status, message).into_response()
}

const FAILED: &str = "the adopt did not complete";
const STORE_UNAVAILABLE: &str = "secrets.store cannot take the discovered values";

/// The writer's result as one answer. Only fixed text leaves: an inner
/// error string is never returned, and only the variant name is logged.
pub(super) fn answer(name: &str, written: Result<ReplaceOutcome, ReplaceError>) -> Response {
    let failed = |variant: &'static str| {
        tracing::warn!(variant, "discovery adopt: the config write failed");
        fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED)
    };
    match written {
        Ok(ReplaceOutcome {
            revision: Some(revision),
            ..
        }) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "adopted",
                "name": name,
                "enabled": false,
                "revision": revision.as_str(),
                "args_copied_verbatim": true,
            })),
        )
            .into_response(),
        // An add always changes the bytes; unchanged ones mean nothing was added.
        Ok(ReplaceOutcome { revision: None, .. }) => failed("unchanged"),
        Err(ReplaceError::Stale { current }) => stale(&current),
        Err(ReplaceError::Busy) => fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the config is being written; retry",
        ),
        Err(ReplaceError::Refused(why)) if why == MANAGED => {
            not_adoptable(&[("managed", "name".to_owned())])
        }
        Err(ReplaceError::Refused(why)) if why == NOT_IN_PLACE => (
            StatusCode::CONFLICT,
            Json(json!({"error": "not_in_place", "message": NOT_IN_PLACE})),
        )
            .into_response(),
        Err(ReplaceError::Refused(_)) => failed("refused"),
        Err(ReplaceError::Secrets(SaveError::Refused(StoreError::Unavailable(_)))) => {
            fixed(StatusCode::UNPROCESSABLE_ENTITY, STORE_UNAVAILABLE)
        }
        Err(ReplaceError::Secrets(_)) => failed("secrets"),
        Err(ReplaceError::ReloadRefused(_)) => failed("reload_refused"),
        Err(ReplaceError::Unsupported(_)) => failed("unsupported"),
        Err(ReplaceError::Stage(_)) => failed("stage"),
        Err(ReplaceError::Write(_)) => failed("write"),
        Err(ReplaceError::RollbackFailed { .. }) => failed("rollback_failed"),
        Err(ReplaceError::Unconfirmed { .. }) => failed("unconfirmed"),
        Err(ReplaceError::Failed(_)) => failed("failed"),
    }
}

/// Where each store reference goes: `(header?, key)`, in the order the
/// literals were saved.
type Slots = Vec<(bool, String)>;

/// The writer's compute: inserts `backend` under `name`, each literal slot
/// filled with its store reference, as a splice of the current bytes. Its
/// refusals are fixed strings ([`MANAGED`], [`REFERENCES`], or
/// [`edit_text`]'s), never anything read from the file.
pub(super) fn compute(
    name: String,
    backend: crate::config::BackendConfig,
    slots: Slots,
) -> impl FnOnce(&[u8], &[String]) -> Result<Vec<u8>, String> + Send {
    move |bytes, references| {
        if references.len() != slots.len() {
            return Err(REFERENCES.to_owned());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
        let mut backend = backend;
        for ((header, key), reference) in slots.iter().zip(references) {
            let map = if *header {
                &mut backend.headers
            } else {
                &mut backend.env
            };
            map.insert(key.clone(), reference.clone());
        }
        edit_text(text, |config| {
            if config.backends.contains_key(&name) {
                return Err(MANAGED);
            }
            config.backends.insert(name, backend);
            Ok(())
        })
        .map(String::into_bytes)
        .map_err(str::to_owned)
    }
}

/// The store a find's literal values go to, with a `value_too_large` reason
/// added for each value it cannot hold. `None` when there is no literal; an
/// `Err` is the answer when no store can be chosen.
fn store_for(
    adoption: &Adoption,
    configured: SecretStoreChoice,
    dir: &std::path::Path,
    reasons: &mut Vec<(&'static str, String)>,
) -> Result<Option<Arc<dyn SecretStore + Send + Sync>>, Response> {
    if adoption.literals.is_empty() {
        return Ok(None);
    }
    let chosen = match choose_store(configured, dir) {
        Ok(chosen) => chosen,
        Err(StoreError::Unavailable(_)) => {
            return Err(fixed(StatusCode::UNPROCESSABLE_ENTITY, STORE_UNAVAILABLE));
        }
        Err(_) => return Err(fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED)),
    };
    let limit = chosen.store.limit();
    for literal in &adoption.literals {
        if literal.value.as_bytes().len() > limit {
            reasons.push(("value_too_large", literal.field()));
        }
    }
    Ok(Some(chosen.store))
}

/// The writer's secret step: each literal saved under its backend field.
/// A vault that cannot be opened (no home for its lock) is a 500 with fixed
/// text; the store's own message is never returned.
pub(super) fn secret_step(
    name: &str,
    literals: Vec<Literal>,
    store: Arc<dyn SecretStore + Send + Sync>,
    vault: Result<Vault, StoreError>,
) -> Result<SecretStep, Response> {
    let Ok(vault) = vault else {
        return Err(fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED));
    };
    let values = literals
        .into_iter()
        .map(|literal| NewSecretOwned {
            field: format!("backends.{name}.{}", literal.field()),
            value: literal.value,
        })
        .collect();
    Ok(SecretStep {
        vault,
        store,
        values,
    })
}

/// The find a fresh scan resolved, or the answer when it did not: changed
/// since the listing (409), or the scan timed out (503).
pub(super) fn found(
    resolved: Result<Option<DiscoveredServer>, ScanTimedOut>,
) -> Result<DiscoveredServer, Response> {
    match resolved {
        Ok(Some(server)) => Ok(server),
        Ok(None) => {
            Err((StatusCode::CONFLICT, Json(json!({"error": "find_changed"}))).into_response())
        }
        Err(ScanTimedOut) => Err(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "discovery scan timed out",
        )),
    }
}

/// `POST /ui/api/discovery/adopt`.
pub(super) async fn adopt_discovery(
    State(state): State<Arc<AppState>>,
    Extension(cache): Extension<Arc<DiscoveryCache>>,
    client: Option<Extension<AuthenticatedClient>>,
    body: Result<Json<AdoptBody>, JsonRejection>,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    // Every rejection gets the same fixed text: axum's own would quote the
    // body back.
    let Ok(Json(body)) = body else {
        return fixed(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the body must be {\"find_id\", \"revision\"} and nothing else",
        );
    };
    let Some(path) = state.config_path.clone() else {
        return config_path_unavailable().into_response();
    };
    let read = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || read_gateway(Some(&path))).await
    };
    let Ok(Ok(gateway)) = read else {
        return fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway.yaml could not be loaded",
        );
    };
    let Gateway::File { revision, config } = &gateway else {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "no_config_file"})),
        )
            .into_response();
    };
    if revision.as_str() != body.revision {
        return stale(revision);
    }
    let Some(context) = state.meta_mcp.reload_context() else {
        return fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "Config reload is not enabled on this gateway",
        );
    };
    let server = match found(cache.resolve(&body.find_id).await) {
        Ok(server) => server,
        Err(refused) => return refused,
    };

    let mut reasons: Vec<(&'static str, String)> = refusals(&server)
        .into_iter()
        .map(|(refusal, field): (AdoptRefusal, String)| (refusal.code(), field))
        .collect();
    if let Some(code) = name_refusal(&gateway, &server.name) {
        reasons.push((code, "name".to_owned()));
    }
    let adoption = adoption(&server);
    let dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let store = match store_for(&adoption, config.secrets.store, &dir, &mut reasons) {
        Ok(store) => store,
        Err(refused) => return refused,
    };
    if !reasons.is_empty() {
        reasons.sort_by(|a, b| a.1.cmp(&b.1));
        return not_adoptable(&reasons);
    }

    let name = server.name.clone();
    let slots: Slots = adoption
        .literals
        .iter()
        .map(|literal| (literal.header, literal.key.clone()))
        .collect();
    let secrets = match store {
        None => None,
        Some(store) => {
            let vault = Vault::for_config_dir(&dir);
            match secret_step(&name, adoption.literals, store, vault) {
                Ok(step) => Some(step),
                Err(refused) => return refused,
            }
        }
    };
    let replace = Replace {
        expected: Expected::Revision(revision.clone()),
        compute: Box::new(compute(name.clone(), adoption.backend, slots)),
        replaced: Replaced::Discard,
        secrets,
    };
    answer(
        &name,
        replace_detached(context, replace, RELOAD_LOCK_WAIT).await,
    )
}

#[cfg(test)]
#[path = "discovery_adopt_tests.rs"]
mod tests;

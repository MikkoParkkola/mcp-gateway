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

use super::super::errors::{
    admin_auth_required, config_path_unavailable, flat_error, structured_error,
};
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
    Chosen, NewSecretOwned, SaveError, SecretStore, StoreError, Vault, choose_store,
};

/// A secret store the writer can save into.
type Store = Arc<dyn SecretStore + Send + Sync>;

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

/// The store the configured choice resolves to, or the answer when none can
/// take the values: 422 when the choice cannot be met on this host, 500
/// otherwise. The store's own message is never returned.
pub(super) fn chosen(choice: Result<Chosen, StoreError>) -> Result<Store, Box<Response>> {
    match choice {
        Ok(chosen) => Ok(chosen.store),
        Err(StoreError::Unavailable(_)) => Err(Box::new(fixed(
            StatusCode::UNPROCESSABLE_ENTITY,
            STORE_UNAVAILABLE,
        ))),
        Err(_) => Err(Box::new(fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED))),
    }
}

/// The store choice and the vault beside gateway.yaml, opened off the async
/// workers: `auto` probes the OS keychain (Secret Service over D-Bus, the
/// macOS keychain, Credential Manager), a blocking call that may stall on a
/// locked or slow keychain. Bounded by the writer's own wait; a keychain that
/// does not answer by then is a 503, and its thread finishes on its own.
async fn open_store(
    configured: SecretStoreChoice,
    dir: std::path::PathBuf,
) -> Result<(Store, Result<Vault, StoreError>), Box<Response>> {
    let open = tokio::task::spawn_blocking(move || {
        (choose_store(configured, &dir), Vault::for_config_dir(&dir))
    });
    match tokio::time::timeout(RELOAD_LOCK_WAIT, open).await {
        Ok(Ok((choice, vault))) => Ok((chosen(choice)?, vault)),
        Ok(Err(_)) => Err(Box::new(fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED))),
        Err(_) => Err(Box::new(store_timed_out())),
    }
}

/// The answer when the store choice or the vault did not answer within the
/// writer's wait: retryable, and naming no store.
pub(super) fn store_timed_out() -> Response {
    fixed(
        StatusCode::SERVICE_UNAVAILABLE,
        "the secret store did not answer; retry",
    )
}

/// A `value_too_large` reason, by client field, for each literal `store`
/// cannot hold.
fn over_limit(adoption: &Adoption, store: &Store) -> Vec<(&'static str, String)> {
    let limit = store.limit();
    adoption
        .literals
        .iter()
        .filter(|literal| literal.value.as_bytes().len() > limit)
        .map(|literal| ("value_too_large", literal.field()))
        .collect()
}

/// The writer's secret step: each literal saved under its backend field.
/// A vault that cannot be opened (no home for its lock) is a 500 with fixed
/// text; the store's own message is never returned.
pub(super) fn secret_step(
    name: &str,
    literals: Vec<Literal>,
    store: Store,
    vault: Result<Vault, StoreError>,
) -> Result<SecretStep, Box<Response>> {
    let Ok(vault) = vault else {
        return Err(Box::new(fixed(StatusCode::INTERNAL_SERVER_ERROR, FAILED)));
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
) -> Result<DiscoveredServer, Box<Response>> {
    match resolved {
        Ok(Some(server)) => Ok(server),
        Ok(None) => Err(Box::new(
            (StatusCode::CONFLICT, Json(json!({"error": "find_changed"}))).into_response(),
        )),
        Err(ScanTimedOut) => Err(Box::new(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "discovery scan timed out",
        ))),
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
        return structured_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
            "the body must be {\"find_id\", \"revision\"} and nothing else",
        )
        .into_response();
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
        Err(refused) => return *refused,
    };

    let mut reasons: Vec<(&'static str, String)> = refusals(&server)
        .into_iter()
        .map(|(refusal, field): (AdoptRefusal, String)| (refusal.code(), field))
        .collect();
    if let Some(code) = name_refusal(&gateway, &server.name) {
        reasons.push((code, "name".to_owned()));
    }
    // Judged before any store is touched: a find the adopt rule or its name
    // refuses never probes the keychain, and a store failure never hides why
    // it was refused. Only `value_too_large` needs the store, for its limit.
    if !reasons.is_empty() {
        reasons.sort_by(|a, b| a.1.cmp(&b.1));
        return not_adoptable(&reasons);
    }
    let adoption = adoption(&server);
    let dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let opened = if adoption.literals.is_empty() {
        None
    } else {
        match open_store(config.secrets.store, dir).await {
            Ok(opened) => Some(opened),
            Err(refused) => return *refused,
        }
    };
    if let Some((store, _)) = &opened {
        let over = over_limit(&adoption, store);
        if !over.is_empty() {
            return not_adoptable(&over);
        }
    }

    let name = server.name.clone();
    let slots: Slots = adoption
        .literals
        .iter()
        .map(|literal| (literal.header, literal.key.clone()))
        .collect();
    let secrets = match opened {
        None => None,
        Some((store, vault)) => match secret_step(&name, adoption.literals, store, vault) {
            Ok(step) => Some(step),
            Err(refused) => return *refused,
        },
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

#[cfg(test)]
#[path = "discovery_adopt_route_tests.rs"]
mod route_tests;

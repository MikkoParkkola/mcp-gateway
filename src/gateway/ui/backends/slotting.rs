// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a backend write does before the store opens: the shared value rule
//! (refusals first, with field names only), the literals it stores, and the
//! store and its secret step. Every refusal here answers before any store is
//! touched, so a refused save probes no keychain and leaves no entry.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::super::errors::flat_error;
#[cfg(test)]
use super::super::secret_slots::Store;
use super::super::secret_slots::{self, Unopened};
use super::write::{STORE_UNAVAILABLE, Slotted};
use crate::config::Config;
use crate::config::secret_values::Syntax;
use crate::gateway::ui::backend_ops::{ValueClass, classify, literal_refusals};
use crate::wiped_bytes::WipedBytes;
#[cfg(test)]
use std::sync::Arc;

/// Test-only, as a request extension: the store a backend write saves into
/// instead of the configured one, and a hook run between the pre-check and
/// the locked write (where another writer can change gateway.yaml). Absent
/// from every non-test build.
#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct BackendStoreForTest {
    pub(super) store: Option<Store>,
    pub(super) after_precheck: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// One literal a write stores: its map, key and value (wiped on drop).
pub(super) struct Literal {
    pub(super) header: bool,
    pub(super) key: String,
    pub(super) value: WipedBytes,
}

impl Literal {
    /// `env.KEY` or `headers.KEY`.
    fn field(&self) -> String {
        format!(
            "{}.{}",
            if self.header { "headers" } else { "env" },
            self.key
        )
    }
}

/// Each refused value in `env` (and `headers`) as `(code, field)`.
pub(super) fn refusals(
    env: &std::collections::HashMap<String, String>,
    headers: &std::collections::HashMap<String, String>,
) -> Vec<(&'static str, String)> {
    let probe = crate::config::BackendConfig {
        env: env.clone(),
        headers: headers.clone(),
        ..Default::default()
    };
    literal_refusals(&probe)
}

/// The values to store among `env` (and `headers`, when given), sorted by
/// field so every run stores them in one order: each value
/// [`classify`] stores, from each header value that
/// [`secret_slots::stores_header_value`] and each env value that
/// [`secret_slots::stores_env_value`]. Every other value is written as typed.
/// Call after [`refuse_values`].
pub(super) fn literals<'a>(
    env: impl Iterator<Item = (&'a String, &'a String)>,
    headers: impl Iterator<Item = (&'a String, &'a String)>,
) -> Vec<Literal> {
    let mut found: Vec<Literal> = env
        .map(|kv| (false, kv))
        .chain(headers.map(|kv| (true, kv)))
        .filter(|(header, (key, value))| {
            classify(value, &Syntax::Dollar) == Ok(ValueClass::Stored)
                && if *header {
                    secret_slots::stores_header_value(value)
                } else {
                    secret_slots::stores_env_value(key, value)
                }
        })
        .map(|(header, (key, value))| Literal {
            header,
            key: key.clone(),
            value: WipedBytes::new(value.as_bytes().to_vec()),
        })
        .collect();
    found.sort_by_key(Literal::field);
    found
}

/// What the write expects of backend `name` in gateway.yaml before it stores
/// anything: an add needs it absent, an update needs it present. Checked here
/// so a duplicate add or a missing backend opens no store; the writer's edit
/// checks again under its lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Expect {
    Absent,
    Present,
}

/// gateway.yaml as it stands, once `name` is as `expect` says: else the
/// 409 or 404 the write would give, before any value is judged or stored.
pub(super) async fn read_expecting(
    path: &std::path::Path,
    name: &str,
    expect: Expect,
) -> Result<Config, Box<Response>> {
    let read = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Config::load_literal_with_text(&path)).await
    };
    let Ok(Ok((config, _))) = read else {
        return Err(Box::new(
            super::super::errors::config_refusal().into_response(),
        ));
    };
    match (expect, config.backends.contains_key(name)) {
        (Expect::Absent, true) => {
            return Err(Box::new(
                flat_error(
                    StatusCode::CONFLICT,
                    format!("Backend '{name}' already exists"),
                )
                .into_response(),
            ));
        }
        (Expect::Present, false) => {
            return Err(Box::new(
                flat_error(StatusCode::NOT_FOUND, format!("Backend '{name}' not found"))
                    .into_response(),
            ));
        }
        _ => {}
    }
    Ok(config)
}

/// The slots and secret step for `literals` on backend `name`, or the answer
/// that stops the write first. `None` when there is nothing to store: no
/// store is opened then.
pub(super) async fn prepare(
    path: &std::path::Path,
    config: &Config,
    name: &str,
    literals: Vec<Literal>,
    #[cfg(test)] store_for_test: Option<Store>,
) -> Result<Option<Slotted>, Box<Response>> {
    if literals.is_empty() {
        return Ok(None);
    }
    let dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let (store, vault) = secret_slots::open_store(config.secrets.store, dir)
        .await
        .map_err(|why| Box::new(unopened(why)))?;
    #[cfg(test)]
    let store = store_for_test.unwrap_or(store);
    let limit = store.limit();
    let over: Vec<(&'static str, String)> = literals
        .iter()
        .filter(|literal| literal.value.as_bytes().len() > limit)
        .map(|literal| ("value_too_large", literal.field()))
        .collect();
    if !over.is_empty() {
        return Err(Box::new(secret_slots::refused_values(&over)));
    }
    let slots = literals.iter().map(|l| (l.header, l.key.clone())).collect();
    let values = literals.into_iter().map(|l| (l.field(), l.value)).collect();
    let step = secret_slots::secret_step(name, values, store, vault)
        .map_err(|why| Box::new(unopened(why)))?;
    Ok(Some(Slotted { slots, step }))
}

/// A store that could not be opened, answered with fixed text only.
fn unopened(why: Unopened) -> Response {
    match why {
        Unopened::Unavailable => {
            flat_error(StatusCode::UNPROCESSABLE_ENTITY, STORE_UNAVAILABLE).into_response()
        }
        Unopened::Failed => flat_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the backend change was not written",
        )
        .into_response(),
        Unopened::TimedOut => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the secret store did not answer; nothing was written; retry",
        )
        .into_response(),
    }
}

/// The answer's `secrets_stored`: each stored field (`env.KEY`) and the
/// reference gateway.yaml now holds for it, from the write itself.
pub(super) fn stored(name: &str, secrets: &[(String, String)]) -> serde_json::Value {
    let prefix = format!("backends.{name}.");
    serde_json::Value::Array(
        secrets
            .iter()
            .map(|(field, reference)| {
                json!({"field": field.strip_prefix(&prefix).unwrap_or(field), "reference": reference})
            })
            .collect(),
    )
}

/// One write's whole step before the store: when any value is refused or
/// stored, gateway.yaml is read and `name` checked (`expect`) first, then a
/// refused value is answered by field and code, then the store and its step
/// are made for the literals. `None`: nothing to store, no store opened.
pub(super) async fn before_store(
    path: &std::path::Path,
    name: &str,
    expect: Expect,
    env: &std::collections::HashMap<String, String>,
    headers: &std::collections::HashMap<String, String>,
    #[cfg(test)] seam: Option<BackendStoreForTest>,
) -> Result<Option<Slotted>, Box<Response>> {
    let reasons = refusals(env, headers);
    let found = literals(env.iter(), headers.iter());
    if reasons.is_empty() && found.is_empty() {
        return Ok(None);
    }
    let config = read_expecting(path, name, expect).await?;
    #[cfg(test)]
    if let Some(hook) = seam.as_ref().and_then(|s| s.after_precheck.clone()) {
        hook();
    }
    if !reasons.is_empty() {
        return Err(Box::new(secret_slots::refused_values(&reasons)));
    }
    prepare(
        path,
        &config,
        name,
        found,
        #[cfg(test)]
        seam.and_then(|s| s.store),
    )
    .await
}

/// An update's step before the store: only the env values the request sets
/// are judged and stored; values already in gateway.yaml are carried as they are.
pub(super) async fn for_update(
    state: &crate::gateway::router::AppState,
    name: &str,
    env: Option<&std::collections::HashMap<String, String>>,
    #[cfg(test)] seam: Option<BackendStoreForTest>,
) -> Result<Option<Slotted>, Box<Response>> {
    let Some(values) = env else {
        return Ok(None);
    };
    let Some(config_file) = state.config_path.as_deref() else {
        return Err(Box::new(
            super::super::errors::config_path_unavailable().into_response(),
        ));
    };
    before_store(
        config_file,
        name,
        Expect::Present,
        values,
        &std::collections::HashMap::new(),
        #[cfg(test)]
        seam,
    )
    .await
}

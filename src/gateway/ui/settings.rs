// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settings wire contract. Admitted requests deliberately remain unimplemented.

use crate::{
    gateway::{router::AppState, ui::guard::Guard},
    wiped_bytes::WipedBytes,
};
#[cfg(test)]
use axum::extract::Extension;
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::sync::Arc;

#[cfg(test)]
#[derive(Clone)]
pub(super) enum SettingsStoreForTest {
    Store(super::secret_slots::Store),
    // Inject the opener outcome without probing the host keychain or waiting.
    OpenRefused(super::secret_slots::Unopened),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiffBody {
    fields: Vec<FieldBody<ValueBody>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SaveBody {
    base_revision: String,
    fields: Vec<FieldBody<SaveValueBody>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldBody<S> {
    field: String,
    backend: Option<String>,
    index: Option<usize>,
    value: S,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ValueBody {
    Set(serde_json::Value),
    Remove(bool),
    Secret(bool),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum SaveValueBody {
    Set(serde_json::Value),
    Remove(bool),
    Secret(#[serde(deserialize_with = "secret")] WipedBytes),
}

/// Move the parser's owned string allocation directly into the wiping owner.
fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<WipedBytes, D::Error> {
    String::deserialize(deserializer).map(|s| WipedBytes::new(s.into_bytes()))
}

fn not_implemented() -> Response {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not_implemented"})),
    )
        .into_response()
}

pub(super) async fn settings_diff(
    State(_state): State<Arc<AppState>>,
    #[cfg(test)] _store: Option<Extension<SettingsStoreForTest>>,
    guard: Guard,
    _body: Result<Json<DiffBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    not_implemented()
}

pub(super) async fn settings_save(
    State(_state): State<Arc<AppState>>,
    #[cfg(test)] _store: Option<Extension<SettingsStoreForTest>>,
    guard: Guard,
    _body: Result<Json<SaveBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    not_implemented()
}

// The result and constructor boundaries stay stubbed with the routes.
fn answer(_refusal: crate::config_reload::ui_diff::UiRefused) -> Response {
    not_implemented()
}

fn restart_fields(_fields: &[&str], _reload: &crate::config_reload::ReloadOutcome) -> Vec<String> {
    Vec::new()
}

fn secret_target(
    _opened: Result<
        (
            super::secret_slots::Store,
            Result<crate::secret_store::Vault, crate::secret_store::StoreError>,
        ),
        super::secret_slots::Unopened,
    >,
) -> Result<crate::config_reload::ui_save::SecretTarget, Response> {
    Err(not_implemented())
}

#[cfg(test)]
#[path = "settings_answer_tests.rs"]
mod answer_tests;
#[cfg(test)]
#[path = "settings_route_secret_tests.rs"]
mod route_secret_tests;
#[cfg(test)]
#[path = "settings_route_tests.rs"]
mod route_tests;
#[cfg(test)]
#[path = "settings_test_support.rs"]
mod test_support;

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/refusals`: what this gateway refused to apply, and the fix.
//!
//! Admin only. Startup refusals (a backend its runtime policy denies) are read
//! from the registry; reload and admin-write refusals come from the reload
//! context's ledger. Every cause is rebuilt from fixed text by the ledger, so
//! nothing here can echo a configured value.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use super::AppState;
use super::guard::Guard;
use crate::config::Config;
use crate::config_reload::refusals::{RefusalKind, RefusalLedger, startup_refusals};

/// The handler.
pub(super) async fn refusals(
    State(state): State<Arc<AppState>>,
    guard: Guard,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let mut list = startup_refusals(&state.backends);
    if let Some(context) = state.meta_mcp.reload_context() {
        list.extend(context.refusals().list());
    }
    Json(json!({ "refusals": list })).into_response()
}

/// One admin write's place in the refusal ledger (when the gateway has one):
/// taken inside the write's lock, stamped once the write has committed, so a
/// write that fails resolves nothing and an older success cannot resolve a
/// newer refusal.
#[derive(Clone, Default)]
pub(super) struct WriteTicket {
    ledger: Option<Arc<RefusalLedger>>,
    ticket: Arc<parking_lot::Mutex<Option<u64>>>,
}

impl WriteTicket {
    pub(super) fn new(state: &AppState) -> Self {
        Self {
            ledger: state
                .meta_mcp
                .reload_context()
                .map(|context| Arc::clone(context.refusals())),
            ticket: Arc::default(),
        }
    }

    /// Inside the lock: record that the edited `config` will not validate
    /// (the write's own validation then refuses it, answer unchanged), or
    /// reserve this write's place if it will.
    pub(super) fn note(&self, kind: RefusalKind, name: &str, config: &Config) {
        match config.validate_with_env(&config.env_overlay()) {
            Err(error) => self.record(kind, name, &error.to_string()),
            Ok(()) => self.reserve(),
        }
    }

    /// Inside the lock: reserve this write's place.
    pub(super) fn reserve(&self) {
        if let Some(ledger) = &self.ledger {
            *self.ticket.lock() = Some(ledger.reserve());
        }
    }

    pub(super) fn record(&self, kind: RefusalKind, name: &str, error: &str) {
        if let Some(ledger) = &self.ledger {
            ledger.record(kind, Some(name), error);
        }
    }

    /// An edit refused with `code`: recorded unless the backend was not
    /// found (nothing to fix there); `code` is returned unchanged.
    pub(super) fn refused_edit(&self, name: &str, error: &str, code: StatusCode) -> StatusCode {
        if code != StatusCode::NOT_FOUND {
            self.record(RefusalKind::Edit, name, error);
        }
        code
    }

    /// After the write committed: resolve `name`'s earlier refusals.
    pub(super) fn committed(&self, name: &str) {
        if let (Some(ledger), Some(ticket)) = (&self.ledger, self.ticket.lock().take()) {
            ledger.write_applied_at(name, ticket);
        }
    }
}

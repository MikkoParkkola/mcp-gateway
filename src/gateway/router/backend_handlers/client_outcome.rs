// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A direct call's outcome, recorded as a success or a failure on the
//! calling client's circuit breaker in the live key table, when that client
//! has one. A caller with no client identity records nothing.

use super::super::AppState;
use crate::gateway::auth::AuthenticatedClient;

pub(super) fn record_client_success(state: &AppState, client: Option<&AuthenticatedClient>) {
    if let Some(client) = client {
        state
            .live_config
            .generation()
            .auth()
            .record_client_success(client);
    }
}

pub(super) fn record_client_failure(state: &AppState, client: Option<&AuthenticatedClient>) {
    if let Some(client) = client {
        state
            .live_config
            .generation()
            .auth()
            .record_client_failure(client);
    }
}

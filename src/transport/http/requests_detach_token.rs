// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The interactive caller's token step, run in a task of its own.

use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;

use crate::oauth::OAuthClient;
use crate::{Error, Result};

/// Run an interactive caller's token step in a task of its own (MIK-8339):
/// the login it may lead belongs to the task, so a caller whose deadline
/// fires drops only its wait, and a person who approves later still stores a
/// token. The caller's scopes are carried in, so the task's marks land on the
/// caller's own Provenance. Before it holds the client, the task observes a
/// restart or stop and ends at the authorization window; no timeout ever
/// wraps a live Lead (the Lead stage bounds itself, in `authorize_until`).
pub(super) async fn detach_token_step(
    oauth: Arc<TokioMutex<OAuthClient>>,
    gate: Arc<crate::oauth::login_gate::LoginGate>,
    set_out: crate::oauth::login_gate::SetOut,
    backend: String,
) -> Result<String> {
    let crate::oauth::login_gate::SetOut {
        since,
        cohort,
        deadline,
    } = set_out;
    #[cfg(test)]
    gate.note_detached();
    let carried = crate::oauth::login_gate::carry_scopes();
    let task = tokio::spawn(carried.run(async move {
        let mut client = gate
            .bounded(since, &cohort, &backend, deadline, oauth.lock_owned())
            .await?;
        // Bounded as the wait for the client is: a re-discovery is a fetch.
        let rediscover = client.rediscover_if_moved();
        gate.bounded(since, &cohort, &backend, deadline, rediscover)
            .await??;
        client
            .get_token_detached(true, since, &cohort, deadline)
            .await
    }));
    let token = task
        .await
        .map_err(|e| Error::OAuth(format!("the detached token step failed: {e}")))?;
    // The refresh ran in its own task, outside this call's delivery cell: a
    // destination refusal it returns is recorded here, in the caller's task.
    token.inspect_err(|e| {
        if crate::security::ssrf::is_ssrf_refusal(e) {
            crate::gateway::delivery_facts::refused_while_vouched();
        }
    })
}

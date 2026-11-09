// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection for catalogue reads (`prompts/get`, `resources/read`):
//! the forwarded params are an egress, the answer a delivery.

use serde_json::Value;

#[cfg(feature = "firewall")]
use super::RelayKey;
use crate::gateway::meta_mcp::MetaMcp;

/// Who a catalogue read (`prompts/get`, `resources/read`) runs for, keyed as
/// `tools/call` keys the same caller (COLLUDE.1 x MIK-7765).
#[derive(Clone)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct CatalogueCaller {
    /// The relay key: the HTTP caller key, the stdio operator, or a session.
    pub(crate) key: String,
    /// Whether `key` is a real identity (an unkeyed key is refused under block).
    pub(crate) keyed: bool,
    /// The caller's display name, for the audit record.
    pub(crate) name: String,
    /// The session the read arrived on, for the audit record's session
    /// fingerprint (MIK-7832).
    pub(crate) session: String,
    /// The generation the read is judged under.
    pub(crate) generation: CatalogueGeneration,
}

/// The generation a catalogue read is judged under. Production builds only
/// [`Self::Pinned`]: every route pins one on arrival, so no read can fall
/// back to the config published later.
#[derive(Clone)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) enum CatalogueGeneration {
    /// The generation the read's request pinned on arrival (an HTTP
    /// request's, a stdio line's).
    Pinned(std::sync::Arc<crate::config_reload::Generation>),
    /// Judged under the generation published now, else refused unpublished:
    /// a test's own caller, which carries no request.
    #[cfg(test)]
    PublishedAtCheck,
}

tokio::task_local! {
    /// The caller of the catalogue read in flight; absent outside a route.
    static CATALOGUE_CALLER: CatalogueCaller;
}

/// Run `read`, a catalogue handler, for `who`.
/// A plain function, not an `async fn`: an `async fn` would hold `read` twice
/// (the argument beside the task-local future that owns it).
pub(crate) fn as_caller<F: std::future::Future>(
    who: CatalogueCaller,
    read: F,
) -> impl std::future::Future<Output = F::Output> {
    CATALOGUE_CALLER.scope(who, read)
}

impl MetaMcp {
    /// Forward a catalogue read to `backend` under `credential`, inside relay
    /// detection: the forwarded params are an egress (`-32002` under `block`
    /// when they carry what another caller was delivered), and the answer is
    /// staged as a delivery from `backend:method`.
    pub(in crate::gateway::meta_mcp) async fn forward_catalogue(
        &self,
        id: crate::protocol::RequestId,
        backend: &crate::backend::Backend,
        (method, params): (&str, Value),
        credential: super::super::super::caller_forward::ForwardCredential,
        empty: Value,
    ) -> crate::protocol::JsonRpcResponse {
        #[cfg(feature = "firewall")]
        let caller = CATALOGUE_CALLER.try_with(Clone::clone).ok();
        #[cfg(feature = "firewall")]
        {
            // Test builds: the witness hook runs before the first generation read on this route.
            #[cfg(test)]
            crate::security::firewall::relay_witness_hook::run();
            if let Some(refusal) =
                self.catalogue_refusal(caller.as_ref(), &backend.name, method, &params, &id)
            {
                return crate::gateway::delivery_facts::refused(refusal);
            }
        }
        let response =
            Self::forward_for_caller(id, backend, method, params, credential, empty).await;
        #[cfg(feature = "firewall")]
        {
            self.stage_catalogue_result(caller, (&backend.name, method), &response);
        }
        response
    }
}

#[cfg(feature = "firewall")]
impl MetaMcp {
    /// The `-32002` answer when a catalogue read's forwarded `params` carry
    /// what another caller was delivered, under `block`; `None` otherwise.
    fn catalogue_refusal(
        &self,
        caller: Option<&CatalogueCaller>,
        backend: &str,
        method: &str,
        params: &Value,
        id: &crate::protocol::RequestId,
    ) -> Option<crate::protocol::JsonRpcResponse> {
        use crate::security::firewall::RelayCaller;
        let (caller, fw) = (
            caller?,
            self.firewall.as_ref().filter(|fw| fw.relay_active())?,
        );
        let who = RelayCaller::new(&caller.key, caller.keyed);
        // The request's pinned generation; a test's own caller reads the one
        // published now, and with none it fails closed (`unpublished_refusal`).
        #[cfg(test)]
        let published = matches!(caller.generation, CatalogueGeneration::PublishedAtCheck)
            .then(|| self.current_generation())
            .flatten();
        let generation = match &caller.generation {
            CatalogueGeneration::Pinned(generation) => Some(&**generation),
            #[cfg(test)]
            CatalogueGeneration::PublishedAtCheck => published.as_deref(),
        };
        let message = match generation {
            Some(generation) => fw.relay_block_message(
                generation.collusion_view(),
                who,
                (backend, method),
                params,
                (&caller.session, &caller.name),
            )?,
            None => super::staging::unpublished_refusal("catalogue witness"),
        };
        // The same error `tools/call` refuses with, so the route stamps the
        // same HTTP status (MIK-7832).
        let refusal = crate::Error::Forbidden {
            code: -32002,
            status: 403,
            message,
        };
        Some(
            super::super::super::response_security::error_response_preserving_status(
                id.clone(),
                &refusal,
            ),
        )
    }

    /// Stage a delivered catalogue result as a delivery from `backend:method`.
    fn stage_catalogue_result(
        &self,
        caller: Option<CatalogueCaller>,
        target: (&str, &str),
        response: &crate::protocol::JsonRpcResponse,
    ) {
        let (Some(caller), Some(result)) = (caller, response.result.as_ref()) else {
            return;
        };
        if response.error.is_some() || !self.relay_active() {
            return;
        }
        let recorded = self.recorded_prompt(target, Some(&caller.name), "catalogue", result);
        self.stage_relay_receipt(RelayKey::new(&caller.key, caller.keyed), target, &recorded);
    }
}

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_catalogue_unpublished_tests.rs"]
mod unpublished_tests;

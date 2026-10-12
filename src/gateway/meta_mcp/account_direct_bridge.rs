// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The managed-account gateway, handed to the direct-route tests (#2190).
//!
//! Those tests live in `router`, where this fixture's `pub(super)` items are
//! out of reach. This is their one door, and it exposes only owned values and
//! counts, so none of the fixture's types leak out through a signature. The
//! gateway itself is [`gateway_in`], unchanged: production compilation,
//! production install, real custody.

use super::*;

/// The backend every direct-route case calls.
pub(crate) const BACKEND: &str = "work-mail";

/// The access token of the sole operator's seeded grant.
pub(crate) const OPERATOR_TOKEN: &str = ALICE_WORK_TOKEN;

/// How `BACKEND` is configured.
pub(crate) enum Binding {
    /// `account: work-gmail`, a managed account, with empty custody.
    Unconnected,
    /// [`Self::Unconnected`] with a connected grant for the sole operator.
    Connected,
    /// A backend-level signed-assertion `identity_propagation` block: minted
    /// per caller, never by the sole-operator assertion.
    Propagation,
}

/// A compiled and installed gateway serving `BACKEND`.
pub(crate) struct DirectAccountGateway {
    meta: Option<MetaMcp>,
    backends: Arc<BackendRegistry>,
    dispatches: Arc<Dispatches>,
    /// Kept alive: its store directory lives as long as the gateway.
    custody: Custody,
}

impl DirectAccountGateway {
    /// Served over HTTP under `auth`. A seeded grant's per-user slot is
    /// seeded too, so a dispatch under it stays in process.
    pub(crate) fn new(auth: crate::config::AuthConfig, binding: &Binding) -> Self {
        Self::new_in(ServeMode::Http, auth, binding)
    }

    /// [`Self::new`] for a chosen transport; stdio catalogue tests (#2231).
    pub(crate) fn new_in(
        mode: ServeMode,
        auth: crate::config::AuthConfig,
        binding: &Binding,
    ) -> Self {
        Self::new_with(mode, auth, binding, None)
    }

    /// [`Self::new_in`], with `BACKEND`'s argument-key enforcement set when
    /// `enforcement` names one (MIK-8356 C10 runs the stdio twin at Off).
    pub(crate) fn new_with(
        mode: ServeMode,
        auth: crate::config::AuthConfig,
        binding: &Binding,
        enforcement: Option<crate::config::InputSchemaEnforcement>,
    ) -> Self {
        let operator_grant = matches!(binding, Binding::Connected);
        let bind = match binding {
            Binding::Unconnected | Binding::Connected => Bind::Account(WORK),
            Binding::Propagation => Bind::Propagation(external_cfg()),
        };
        let seed = if operator_grant {
            vec![(operator_key(), grant(ALICE_WORK_TOKEN, u64::MAX))]
        } else {
            Vec::new()
        };
        let slots = if operator_grant {
            vec![Self::operator_binding()]
        } else {
            Vec::new()
        };
        let custody = custody_with(&seed);
        let (meta, dispatches) = gateway_in_with(
            &[(BACKEND, bind)],
            &Descriptors::same(&[WORK]),
            &custody.installed(),
            &slots,
            (mode, auth),
            |config| {
                if let Some(mode) = enforcement {
                    config.input_schema_enforcement = mode;
                }
            },
        );
        Self {
            backends: Arc::clone(&meta.backends),
            meta: Some(meta),
            dispatches,
            custody,
        }
    }

    /// The Meta-MCP to install in the router state. Once only.
    pub(crate) fn take_meta(&mut self) -> MetaMcp {
        self.meta.take().expect("the Meta-MCP is taken once")
    }

    /// The registry the Meta-MCP resolves against, which the direct route
    /// must look `BACKEND` up in too.
    pub(crate) fn backends(&self) -> Arc<BackendRegistry> {
        Arc::clone(&self.backends)
    }

    /// Requests that reached the fixture's capturing transport.
    pub(crate) fn dispatched(&self) -> usize {
        self.dispatches.count()
    }

    /// The `tools/call` requests that reached the backend, each as its
    /// `Authorization` header and the identity key that selected its slot.
    /// Probe only: revoke the sole operator's grant through live custody,
    /// with no reconnect.
    pub(crate) async fn revoke_operator_grant_for_probe(&self) {
        self.custody
            .handle
            .invalidate(&operator_key())
            .await
            .expect("the seeded grant must revoke through real custody");
    }

    pub(crate) fn tool_calls(&self) -> Vec<(Option<String>, Option<String>)> {
        self.dispatches
            .calls()
            .into_iter()
            .map(|call| (call.authorization(), call.identity_key))
            .collect()
    }

    /// Every request that reached the backend, as its method, `Authorization`
    /// header and slot identity key (#2231: listings, not only `tools/call`).
    pub(crate) fn requests(&self) -> Vec<(String, Option<String>, Option<String>)> {
        self.dispatches
            .all()
            .into_iter()
            .map(|call| (call.method.clone(), call.authorization(), call.identity_key))
            .collect()
    }

    /// Answer the next non-`tools/list` request with `result`.
    pub(crate) fn answer_next(&self, result: serde_json::Value) {
        self.dispatches.script(&[Answer::Result(result)]);
    }

    /// Answer the next requests, `tools/list` included, with these HTTP
    /// statuses (MIK-8356 C9: a cold slot's first list gets a 401).
    pub(crate) fn answer_lists_with(&self, statuses: &[u16]) {
        self.dispatches.script_lists();
        self.dispatches.answer_with(statuses);
    }

    /// Forced refreshes custody ran: one per `after_upstream_401`.
    pub(crate) fn refreshes(&self) -> usize {
        self.custody.refreshes()
    }

    /// Credential releases custody made: one per `prepare` (MIK-8356 F5: a
    /// refused call resolves nothing).
    pub(crate) fn releases(&self) -> usize {
        self.custody.releases()
    }

    /// Revoke the sole operator's seeded grant and reconnect it under a new
    /// generation, through live custody (MIK-8356: the old slot stays warm and
    /// indexed, but no longer belongs to the current grant).
    pub(crate) async fn rotate_operator_grant(&self) {
        revoke_and_reconnect(
            &self.custody,
            &operator_key(),
            &grant(ALICE_WORK_TOKEN, u64::MAX),
            ROTATED_TOKEN,
        )
        .await;
    }

    /// The per-user slot the sole operator's seeded grant selects.
    pub(crate) fn operator_binding() -> String {
        expected_identity_key_for(&operator_key(), SEEDED_REVISION)
    }

    /// The audit subject the sole operator is recorded under.
    pub(crate) fn operator_subject() -> String {
        crate::personal_accounts::identity::Principal::SoleOperator.stable_actor_id()
    }
}

/// The sole operator's key for [`WORK`], built the way custody builds it.
pub(super) fn operator_key() -> AccountKey {
    crate::personal_accounts::identity::account_key(
        Some(crate::personal_accounts::identity::Principal::SoleOperator),
        &key_descriptor(WORK),
    )
    .expect("fixture principal and descriptor must bind")
}

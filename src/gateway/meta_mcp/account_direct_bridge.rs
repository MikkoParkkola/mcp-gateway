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
    _custody: Custody,
}

impl DirectAccountGateway {
    /// Served over HTTP under `auth`. A seeded grant's per-user slot is
    /// seeded too, so a dispatch under it stays in process.
    pub(crate) fn new(auth: crate::config::AuthConfig, binding: &Binding) -> Self {
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
        let (meta, dispatches) = gateway_in(
            &[(BACKEND, bind)],
            &Descriptors::same(&[WORK]),
            &custody.installed(),
            &slots,
            ServeMode::Http,
            auth,
        );
        Self {
            backends: Arc::clone(&meta.backends),
            meta: Some(meta),
            dispatches,
            _custody: custody,
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
    pub(crate) fn tool_calls(&self) -> Vec<(Option<String>, Option<String>)> {
        self.dispatches
            .calls()
            .into_iter()
            .map(|call| (call.authorization(), call.identity_key))
            .collect()
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
fn operator_key() -> AccountKey {
    crate::personal_accounts::identity::account_key(
        Some(crate::personal_accounts::identity::Principal::SoleOperator),
        &key_descriptor(WORK),
    )
    .expect("fixture principal and descriptor must bind")
}

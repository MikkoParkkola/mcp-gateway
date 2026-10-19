// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one strategy instance an installed account descriptor mints through.

use std::sync::Arc;

use crate::identity_propagation::IdentityPropagation;

/// The one strategy instance an installed descriptor mints through.
///
/// ONE FIELD, NOT TWO. A managed descriptor's vault is kept typed because
/// durable custody is not expressible through [`IdentityPropagation`]:
/// `propagate` mints, and a recheck must NOT mint. Holding it as its own variant
/// (rather than a trait object plus an optional typed copy) makes "a vault
/// strategy with no custody handle" or "a custody handle for some other
/// strategy" unrepresentable: one descriptor has one key, one resolver and one
/// store no matter which consumer reaches it.
pub(crate) enum Minter {
    /// `personal_managed`: the vault the installer built.
    Managed(Arc<crate::personal_accounts::VaultStrategy>),
    /// `external`: the strategy's published expiry and behaviour, unchanged.
    External(Arc<dyn IdentityPropagation>),
}

impl Minter {
    /// The trait object the per-backend MCP map holds: for a managed
    /// descriptor the vault itself, coerced, so it is the same allocation.
    pub(crate) fn strategy(&self) -> Arc<dyn IdentityPropagation> {
        match self {
            Self::Managed(vault) => Arc::clone(vault) as Arc<dyn IdentityPropagation>,
            Self::External(strategy) => Arc::clone(strategy),
        }
    }

    /// The managed vault, when this descriptor is `personal_managed`.
    pub(crate) fn managed(&self) -> Option<&Arc<crate::personal_accounts::VaultStrategy>> {
        match self {
            Self::Managed(vault) => Some(vault),
            Self::External(_) => None,
        }
    }
}

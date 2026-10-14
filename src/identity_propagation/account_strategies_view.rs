// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The registry's mint-free view read and its busy-custody audit record
//! (MIK-8392 Busy parity), kept beside the registry to hold its file under
//! the size ceiling.

use std::sync::Arc;

use super::{
    AccountStrategyRegistry, Principal, PropagationError, TransparencyLogger, audit_subject,
};
use crate::identity_propagation::CallerProof;

impl AccountStrategyRegistry {
    /// The caller's current view of descriptor `descriptor_id`, read without
    /// refreshing or minting (MIK-8392), keeping a busy custody distinct
    /// (Busy parity): `None` when the descriptor has no managed custody to
    /// read (an external or token-exchange account, or none installed), so
    /// no mint-free judgement exists. A caller with no principal for it has
    /// no view, reported as not connected.
    pub(crate) async fn view_binding_classified(
        &self,
        descriptor_id: &str,
        caller: CallerProof<'_>,
    ) -> Option<crate::personal_accounts::ViewBinding> {
        use crate::personal_accounts::ViewBinding;
        let installed = self.installed(descriptor_id)?;
        let vault = installed.minter.managed()?;
        let Some(principal) = Self::principal(installed.as_ref(), caller) else {
            return Some(ViewBinding::NoView(PropagationError::AccountNotConnected(
                "the request carries no principal for this account".to_owned(),
            )));
        };
        Some(vault.view_binding_classified(principal).await)
    }

    /// The one `idp_refuse` record for a transient busy custody (MIK-8392
    /// Busy parity), shared by the live call and the stored read: the real
    /// subject, descriptor and audience, with the busy reason. The caller
    /// passes its own transparency logger, as the mint path passes its.
    pub(crate) async fn audit_transient_refusal(
        &self,
        logger: Option<&Arc<TransparencyLogger>>,
        descriptor_id: &str,
        caller: CallerProof<'_>,
        reason: &str,
    ) {
        let Some(installed) = self.installed(descriptor_id) else {
            return;
        };
        let subject_id = Self::principal(installed.as_ref(), caller).map_or_else(
            || audit_subject(caller.verified()),
            Principal::stable_actor_id,
        );
        Self::audit_refusal(
            logger,
            &subject_id,
            descriptor_id,
            installed.audience.as_str(),
            reason,
        )
        .await;
    }
}

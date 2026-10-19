// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407: re-binding a target to another account, as production can.
//! A managed backend's `account:` changes only across a restart (a reload
//! refuses it, `config::account_bindings::reload_binding_refusal`), which the
//! backend swap below stands in for. A capability's `auth.account` changes
//! live: its hot reload checks only that the account resolves.

use super::*;

impl DirectAccountGateway {
    /// Re-bind [`BACKEND`] from `work-gmail` to `personal-gmail`: a
    /// replacement instance under the same name, built by the production
    /// compilation, as the restart that applies such a change builds it.
    /// Built by [`Self::with_second`]`(.., Second::PersonalAccount)`, which
    /// installs both accounts' strategies; the operator's slot on each
    /// account is seeded, so a dispatch stays in process. Its catalogue
    /// starts empty.
    pub(crate) fn rebind_backend_to_personal_for_test(&self) {
        let slots: Vec<String> = [WORK, PERSONAL]
            .iter()
            .map(|id| expected_identity_key_for(&operator_key_for(id), SEEDED_REVISION))
            .collect();
        let replacement = super::super::gateway::rebound_backend(
            (BACKEND, PERSONAL),
            &[WORK, PERSONAL],
            &self.dispatches,
            &slots,
        );
        assert!(
            self.backends.register(replacement),
            "the re-bound backend must register"
        );
    }
}

impl CapabilityAccount {
    /// A managed capability on `WORK`, with `PERSONAL` installed beside it
    /// and alice holding a live grant on both.
    pub(crate) async fn start_two_accounts() -> Self {
        let mut account = Self::start(false).await;
        account.custody = custody_with(&[
            (
                account_key("alice", WORK),
                grant(ALICE_WORK_TOKEN, u64::MAX),
            ),
            (
                account_key("alice", PERSONAL),
                grant(ALICE_PERSONAL_TOKEN, u64::MAX),
            ),
        ]);
        account.second = true;
        account
    }

    /// Hot-reload the capability onto `PERSONAL`: the same definition
    /// registered again under the other `auth.account`, as a reload of its
    /// file registers it. Needs [`Self::start_two_accounts`].
    pub(crate) fn rebind_to_personal(&self, meta: &MetaMcp) {
        let capabilities = meta.get_capabilities().expect("the capability backend");
        capabilities
            .register_capability(crate::gateway::meta_mcp::account_rest_fixture::capability(
                &format!("http://127.0.0.1:{}", self.port),
                "oauth:google",
                Some(PERSONAL),
            ))
            .expect("the re-bound capability registers");
    }
}

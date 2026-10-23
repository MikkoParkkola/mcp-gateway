// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only constructors for [`SigningInvocationContext`] and a direct
//! admission driver, moved out of `signing.rs` (MIK-8668). A child module keeps
//! access to the private fields and to `MetaMcp::admit_meta_sync`.

use super::*;

impl SigningInvocationContext {
    pub(crate) fn internal_for_test() -> Self {
        Self {
            origin: Origin::Unsigned,
            scope: SigningScope::InvokeOnly,
            nonce: CapturedNonce::Missing,
            request_id: None,
            prepared_target: None,
            admitted: false,
            nonce_stamp: None,
            refund: NonceRefund::default(),
        }
    }

    /// An external `gateway_invoke` context that has passed admission.
    pub(crate) fn external_for_test(nonce: Option<&str>) -> Self {
        Self {
            origin: Origin::GatewayInvoke,
            scope: SigningScope::InvokeOnly,
            nonce: captured(nonce.map(|value| Value::String(value.to_owned()))),
            request_id: None,
            prepared_target: None,
            admitted: true,
            nonce_stamp: None,
            refund: NonceRefund::default(),
        }
    }

    /// [`Self::external_for_test`] that signing already prepared for
    /// `server`'s `tool`, as `prepare_signing_invocation` leaves it.
    pub(crate) fn prepared_for_test(server: &str, tool: &str) -> Self {
        Self {
            prepared_target: Some((server.to_owned(), tool.to_owned())),
            ..Self::external_for_test(None)
        }
    }

    pub(crate) fn invalid_for_test() -> Self {
        Self {
            origin: Origin::GatewayInvoke,
            scope: SigningScope::InvokeOnly,
            nonce: CapturedNonce::Invalid,
            request_id: None,
            prepared_target: None,
            admitted: true,
            nonce_stamp: None,
            refund: NonceRefund::default(),
        }
    }
}

impl super::super::MetaMcp {
    /// [`Self::admit_meta_sync`] for a test that drives admission directly,
    /// with nothing having acted before it.
    pub(crate) fn admit_meta_sync_for_test(
        &self,
        owner: super::super::AdmissionOwner<'_>,
        caller: &super::super::MetaMcpCallerContext<'_>,
        tool_name: &str,
        arguments: &Value,
        session: Option<&str>,
        id: &crate::protocol::RequestId,
    ) -> crate::Result<super::super::admission::SyncAdmission> {
        let witness = Some(RefundWitness::at_capture());
        Self::admit_meta_sync(
            self, owner, caller, tool_name, arguments, session, id, witness,
        )
    }
}

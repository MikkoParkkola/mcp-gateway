// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The principal a continuation binds a stdio caller to (MIK-7570.STDIO.1).
//!
//! A stdio process serves exactly the one client that spawned it, so a value
//! unique to the process names that client completely. Unique, not constant:
//! continuations share a keyring across processes (`protocol::continuation`),
//! and a constant would be one shared non-identity held by every stdio process
//! on a config, which `mrtr::principal_fingerprint` exists to refuse.
//!
//! The control is who can obtain one. The field is private and so is the
//! constructor, and [`StdioNonce::process`] is visible to the stdio transport
//! module alone, so only its two caller-context builders can bind a caller as
//! stdio. An HTTP caller has no path to the value, whatever text it presents.

use std::sync::OnceLock;

/// 32 bytes from the OS RNG, drawn once per process. Never persisted, never
/// logged: no `Debug`, no `Display`, no serialisation.
pub(crate) struct StdioNonce([u8; 32]);

impl StdioNonce {
    fn generate() -> Self {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("the OS RNG must yield 32 bytes");
        Self(bytes)
    }

    /// This process's nonce. The serve loop forces it at start so the RNG is
    /// read before the first request rather than inside one.
    pub(super) fn process() -> &'static Self {
        static NONCE: OnceLock<StdioNonce> = OnceLock::new();
        NONCE.get_or_init(Self::generate)
    }

    /// The bytes the fingerprint is derived from.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::StdioNonce;
    use crate::protocol::continuation::ContinuationState;
    use crate::protocol::mrtr::{PrincipalSource, original_request_digest, source_fingerprint};

    fn fingerprint(nonce: &StdioNonce) -> String {
        source_fingerprint(PrincipalSource::Stdio {
            nonce: nonce.bytes(),
        })
        .expect("a stdio caller always has a fingerprint")
    }

    /// R5-T5: an envelope minted for one stdio process is not redeemable by
    /// another process that shares its keyring. Red against a constant nonce.
    #[tokio::test]
    async fn a_stdio_envelope_is_not_redeemable_by_another_stdio_process() {
        let (first, second) = (StdioNonce::generate(), StdioNonce::generate());
        let digest = original_request_digest("fixture", "needs_input", &serde_json::json!({}));
        let payload = ContinuationState::new()
            .begin_exchange(
                "fixture".to_owned(),
                None,
                fingerprint(&first),
                digest.clone(),
                crate::protocol::continuation::now_unix_secs(),
            )
            .await
            .expect("a fresh state has a slot");

        assert!(payload.redeemable_by(&fingerprint(&first), &digest).is_ok());
        assert!(
            payload
                .redeemable_by(&fingerprint(&second), &digest)
                .is_err(),
            "a second stdio process must not redeem the first one's envelope"
        );
    }

    /// A context rebuilt for a chain step keeps the stdio binding: the copy in
    /// `with_retry` is by hand, and a dropped field would unbind the step.
    #[test]
    fn a_rebuilt_stdio_context_keeps_its_binding() {
        let policy =
            crate::security::ToolPolicy::from_config(&crate::security::ToolPolicyConfig::default());
        let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
            tool_policy: &policy,
        };
        let caller =
            super::super::stdio_caller_context(&authorizer, crate::protocol::meta::Era::Modern);
        let rebuilt = caller.with_retry(&crate::protocol::mrtr::NO_RETRY);
        let expected = fingerprint(StdioNonce::process());
        assert_eq!(
            source_fingerprint(rebuilt.principal_source()).as_deref(),
            Some(expected.as_str())
        );
    }
}

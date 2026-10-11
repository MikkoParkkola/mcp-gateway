// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who an open continuation slot is charged to (MIK-8293).
//!
//! The in-flight table is one pool per replica. Each caller may hold at most
//! [`PRINCIPAL_SLOTS`] of it, so no caller can fill the pool and refuse every
//! other caller's questions and confirmations until its holds expire.
//!
//! The caller is named by a [`QuotaKey`], and a `QuotaKey` can only be built
//! from a [`QuotaSource`]: who the caller is, never a string. That is what
//! keeps "one caller, one cap" true at every site that takes a slot. In
//! particular, the fingerprint sealed into an envelope cannot be passed as a
//! quota key: it is finer than the caller on purpose (one per propagated
//! binding), and it would give one caller a cap per backend.

/// The most slots one caller may hold at once, per replica: 1/64 of the pool.
///
/// Fixed, not configured: filling the pool takes 64 distinct credentials. It
/// leaves room for the busiest legitimate caller: a principal at its cap of
/// 32 live tasks, each with one round open, still has 32 slots for other
/// questions and confirmations.
pub const PRINCIPAL_SLOTS: usize = super::ledger::IN_FLIGHT_CAPACITY / 64;

/// Who a caller is, for the slot cap. One credential gives one source
/// whatever route it calls through.
// Public for the integration soak test only; hidden, not part of the API.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub enum QuotaSource<'a> {
    /// A stdio process: every call it makes, and every task worker it hosts,
    /// carries the process's nonce.
    Stdio(&'a [u8; 32]),
    /// A caller with a verified identity, by its stable actor id.
    Identity(&'a crate::key_server::oidc::VerifiedIdentity),
    /// A caller a trusted proxy, Cloudflare Access, a client certificate or an
    /// OAuth agent names (an operator-configured trust root).
    Subject(&'a crate::identity_grants::GrantSubject),
    /// An authenticated credential's principal. The bare digest a live caller
    /// carries and the `credential:`-prefixed owner a task worker carries are
    /// one credential, so both name one caller.
    Credential(&'a str),
    /// An API key known only by its name. Names are unique at load.
    KeyName(&'a str),
}

/// The caller a slot is charged to. Opaque; built only from a
/// [`QuotaSource`].
// Public for the integration soak test only (it holds slots through
// `InFlight::hold`); hidden, not part of the API.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuotaKey(String);

impl QuotaKey {
    /// The key for `source`. Each source has its own scheme, so two kinds of
    /// caller can never collide, and the text is hashed so the table holds no
    /// identity in the clear.
    // Public for the integration soak test only; hidden, not part of the API.
    #[doc(hidden)]
    #[must_use]
    pub fn new(source: QuotaSource<'_>) -> Self {
        let prefix = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX;
        let named = match source {
            QuotaSource::Stdio(nonce) => {
                return Self(crate::hashing::sha256_hex_chunks([
                    b"quota:stdio:".as_slice(),
                    nonce.as_slice(),
                ]));
            }
            QuotaSource::Identity(identity) => format!("agent:{}", identity.stable_actor_id()),
            QuotaSource::Subject(subject) => format!(
                "subject:{}:{}:{}:{}",
                subject.authority.len(),
                subject.authority,
                subject.subject.len(),
                subject.subject
            ),
            QuotaSource::Credential(principal) => {
                format!(
                    "credential:{}",
                    principal.strip_prefix(prefix).unwrap_or(principal)
                )
            }
            QuotaSource::KeyName(name) => format!("key-name:{name}"),
        };
        Self(crate::hashing::sha256_hex(
            format!("quota:{named}").as_bytes(),
        ))
    }

    /// Test-only: a key for a named test caller.
    #[cfg(test)]
    pub(crate) fn for_test(label: &str) -> Self {
        Self::new(QuotaSource::KeyName(label))
    }
}

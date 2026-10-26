// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller a continuation binds to, and the fingerprints that bind it.

use serde_json::Value;

/// What a continuation binds a caller to.
///
/// A distinct input rather than a sentinel in a credential string: an HTTP
/// `client.principal` is caller-influenced text, and a variant cannot be
/// spelled by any text. The variant being public is not the control, though —
/// the control is the caller-context field that selects it, which only the two
/// stdio context builders set (`gateway::server`).
#[derive(Clone)]
pub enum PrincipalSource<'a> {
    /// A caller bound by its verified identity, when it has one.
    Credential(Option<&'a crate::key_server::oidc::VerifiedIdentity>),
    /// A caller with no verified identity, bound by the validated credential
    /// it presented: the principal text the idempotency guard already keys
    /// that caller's calls on (`caller_cache_principal`), built by the gateway,
    /// never read from a request. One key is one principal, so
    /// everyone holding a shared key is one caller here too.
    Key(String),
    /// The one client of this stdio process, named by a nonce drawn once per
    /// process from the OS RNG. Never persisted, never logged.
    Stdio {
        /// The per-process nonce.
        nonce: &'a [u8; 32],
    },
}

/// Redacted: the stdio nonce is never printed.
impl std::fmt::Debug for PrincipalSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credential(identity) => f.debug_tuple("Credential").field(identity).finish(),
            Self::Key(_) => f.write_str("Key(<principal>)"),
            Self::Stdio { .. } => f.write_str("Stdio { nonce: <redacted> }"),
        }
    }
}

/// The caller binding sealed into a continuation, or `None` when this caller
/// cannot be bound at full strength.
///
/// `None` is a refusal, not a fallback. A continuation names who may redeem it,
/// and the only honest answer for a caller the gateway cannot name is that it
/// has none: an anonymous caller shares its non-identity with every other
/// anonymous caller, so a fingerprint standing in for one would satisfy
/// [`Payload::redeemable_by`](crate::protocol::continuation::Payload::redeemable_by)
/// while binding nothing. An under-binding nobody can see is worse than a
/// refusal everybody can.
///
/// Two schemes are constructible. A verified agent binds by
/// `VerifiedIdentity::stable_actor_id`. A stdio caller binds by its process
/// nonce: the process serves exactly the one client that spawned it, so a
/// principal unique to the process is a complete binding. A nonce rather than
/// a constant, because continuations share a keyring across processes and a
/// constant would be the one shared non-identity every stdio process on a
/// config holds. An API-key caller binds on the principal the gateway already
/// owns its sessions, grants, journals and tasks by:
/// the truncated 48-bit digest of its key. Short, but it is not a credential
/// and is never chosen by a caller: a redeemer must present a validated key,
/// and two configured keys can never share a principal
/// (`refuse_shared_principals`). So one key cannot redeem another's
/// continuation, and every holder of one shared key is one caller. The
/// client-certificate scheme is not yet reachable at the mint site (its DER is
/// read and dropped before the caller context is built); its callers are
/// refused rather than bound weakly.
///
/// Scheme-tagged (`agent:`, `key:`, `stdio:`) so two schemes can never collide on one
/// value, and derived from `VerifiedIdentity::stable_actor_id` rather than a
/// second length-prefixed encoding of the same pair: a second spelling of an
/// unambiguous encoding is how one caller acquires two fingerprints.
#[must_use]
pub fn source_fingerprint(source: PrincipalSource<'_>) -> Option<String> {
    match source {
        PrincipalSource::Credential(identity) => Some(crate::hashing::sha256_hex(
            format!("agent:{}", identity?.stable_actor_id()).as_bytes(),
        )),
        PrincipalSource::Key(principal) => Some(crate::hashing::sha256_hex(
            format!("key:{principal}").as_bytes(),
        )),
        PrincipalSource::Stdio { nonce } => Some(crate::hashing::sha256_hex_chunks([
            b"stdio:".as_slice(),
            nonce.as_slice(),
        ])),
    }
}

/// [`source_fingerprint`] for a caller bound by its verified identity alone.
///
/// Not a caller binding: every gateway site binds through
/// `MetaMcpCallerContext::principal_source`, which also binds a key-only
/// caller. Its one production caller is the direct route's A2A
/// round, whose caller cannot reach `principal_source` yet. It is
/// the same derivation as the `Credential` arm, not a second one.
#[must_use]
pub fn principal_fingerprint(
    identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
) -> Option<String> {
    source_fingerprint(PrincipalSource::Credential(identity))
}

/// Which request a continuation continues.
///
/// Computed over the original call and nothing else. The retry's own
/// `inputResponses` and `requestState` are excluded because they do not exist
/// on the first call, so including them would produce a digest that could never
/// match the one sealed at mint.
///
/// Delegates to the idempotency key derivation rather than repeating its shape:
/// both hash a tool name and a canonical rendering of the same arguments, and
/// two spellings of one canonical form is how a digest silently stops matching.
/// Qualified by server because a bare tool name is ambiguous across backends.
#[must_use]
pub fn original_request_digest(server: &str, tool: &str, arguments: &Value) -> String {
    crate::idempotency::derive_key(&format!("{server}:{tool}"), arguments)
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The verified assertion a token's verification leaves, and the refusal for
//! a token whose identity names no one. `VerifiedIdentity` and its checked
//! constructor live in `oidc/verified.rs`.

use super::OidcError;

/// A token this verifier has fully verified, kept as the exact string that
/// was verified together with the window that verification judged: the two
/// cannot be split or recomposed, and no other module can mint one.
#[derive(Clone)]
pub(crate) struct VerifiedAssertion {
    assertion: String,
    exp: u64,
    leeway: u64,
}

impl VerifiedAssertion {
    pub(super) fn verified(assertion: String, exp: u64, leeway: u64) -> Self {
        Self {
            assertion,
            exp,
            leeway,
        }
    }

    /// The verified string, for the re-verification that needs it.
    pub(crate) fn expose(&self) -> &str {
        &self.assertion
    }

    /// Whether the verified window is still live, judged exactly as
    /// verification judged it: `exp` with the same leeway, no `nbf`.
    pub(crate) fn live(&self) -> bool {
        crate::clock::jwt_window(
            crate::clock::JwtClaimTime::At(self.exp),
            crate::clock::JwtClaimTime::Absent,
            self.leeway,
        ) == crate::clock::Validity::Live
    }

    #[cfg(test)]
    pub(crate) fn for_test(assertion: &str) -> Self {
        Self {
            assertion: assertion.to_owned(),
            exp: u64::MAX,
            leeway: 0,
        }
    }
}

impl std::fmt::Debug for VerifiedAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAssertion(<redacted>)")
    }
}

/// The refusal for a token whose identity names no one: an existing variant,
/// so the public error type is unchanged (MIK-8287).
pub(super) fn missing_subject() -> OidcError {
    OidcError::JwtError(jsonwebtoken::errors::Error::from(
        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("sub".to_owned()),
    ))
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::net::SocketAddr;

use super::{DeadReason, LiveCtx, ViewSubject};

/// How many transient Cloudflare failures a stream survives.
const CF_MAX_TRANSIENT: u32 = 3;

/// The header identity a stream was admitted under, when one was admitted
/// and selected: the verified Cloudflare assertion, or the trusted
/// proxy's peer. `Debug` is safe only because the receipt's own `Debug`
/// is redacted.
#[derive(Clone, Debug, Default)]
pub(crate) enum HeldSource {
    #[default]
    None,
    Cloudflare(crate::key_server::oidc::VerifiedAssertion),
    TrustedProxy {
        peer: SocketAddr,
    },
}

/// Per-stream Cloudflare grace: transient failures stay this decision.
#[derive(Debug, Default)]
pub(crate) struct CfGrace {
    consecutive: u32,
    last_good: Option<u64>,
}

/// What a Cloudflare re-verification means for the stream.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::gateway::streaming) enum CfVerdict {
    Good,
    Transient,
    Dead,
}

// `Ok` is `Good`; unreachable-provider errors are `Transient`; the rest is `Dead`.
pub(in crate::gateway::streaming) fn cf_verdict(
    result: &Result<crate::key_server::oidc::VerifiedIdentity, crate::key_server::oidc::OidcError>,
) -> CfVerdict {
    match result {
        Ok(_) => CfVerdict::Good,
        Err(
            crate::key_server::oidc::OidcError::HttpError(_)
            | crate::key_server::oidc::OidcError::DiscoveryStatus(_)
            | crate::key_server::oidc::OidcError::ClientUnavailable,
        ) => CfVerdict::Transient,
        Err(_) => CfVerdict::Dead,
    }
}

impl ViewSubject {
    /// Re-verify the held Cloudflare Access assertion against the verifier's
    /// current keys, as admission did, so a rotated or revoked key ends the
    /// stream. Nothing to check for a stream that holds no assertion; a
    /// missing verifier refuses, as admission does.
    pub(crate) async fn verify_held_cf(&self, ctx: &LiveCtx<'_>) -> Result<(), DeadReason> {
        let HeldSource::Cloudflare(held) = &self.identity_source else {
            return Ok(());
        };
        if !held.live() {
            return Err(DeadReason::Cf);
        }
        let Some(verifier) = ctx.cf_verifier else {
            return Err(DeadReason::Cf);
        };
        let age = crate::config::KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::ExpOnly,
        };
        let outcome = verifier.verify(held.expose(), &age).await;
        match cf_verdict(&outcome) {
            CfVerdict::Good => {
                let mut grace = self.cf_grace.lock();
                grace.consecutive = 0;
                if let Ok(now) = crate::clock::unix_secs() {
                    grace.last_good = Some(now);
                }
                Ok(())
            }
            CfVerdict::Dead => Err(DeadReason::Cf),
            CfVerdict::Transient => {
                if !held.live() {
                    return Err(DeadReason::Cf);
                }
                let Ok(now) = crate::clock::unix_secs() else {
                    return Err(DeadReason::Cf);
                };
                let mut grace = self.cf_grace.lock();
                if grace.last_good.is_none() {
                    grace.last_good = Some(now);
                }
                grace.consecutive = grace.consecutive.saturating_add(1);
                if grace.consecutive >= CF_MAX_TRANSIENT {
                    return Err(DeadReason::Cf);
                }
                let ttl = verifier.jwks_ttl().as_secs();
                let since = grace.last_good.map_or(0, |last| now.saturating_sub(last));
                if since > ttl {
                    return Err(DeadReason::Cf);
                }
                Ok(())
            }
        }
    }
}

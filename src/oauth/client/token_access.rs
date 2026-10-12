// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Getting a usable access token: cached, refreshed, or a fresh login.

use super::{OAuthClient, grants, refresh_buffer};
use crate::security::ssrf::is_ssrf_refusal;
use crate::{Error, Result};

impl OAuthClient {
    /// Get a valid access token, refreshing or re-authorizing as needed
    ///
    /// # Errors
    ///
    /// Returns an error if token refresh and re-authorization both fail.
    pub async fn get_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let token = self.current_token.read();
            if let Some(ref t) = *token
                && !t.is_expired()
            {
                return Ok(t.access_token.clone());
            }
        }

        // Try to refresh if we have a refresh token
        // A refresh sends the stored refresh token (MIK-8018); a cached one
        // only says this client has a grant to refresh.
        let has_refresh_token = self
            .current_token
            .read()
            .as_ref()
            .is_some_and(|t| t.refresh_token.is_some());

        if has_refresh_token {
            match self.refresh_token().await {
                Ok(new_token) => return Ok(new_token),
                // A policy refusal is not an expired grant: re-authorizing
                // would only walk past it (MIK-7701).
                Err(e) if is_ssrf_refusal(&e) => return Err(e),
                Err(_) => {}
            }
        }

        // Need to authorize from scratch
        let token = self
            .authorize_shared(super::super::login_gate::interactive(), None)
            .await?;
        Ok(token)
    }

    /// The cached access token, if it is unexpired: one read of the cell, so
    /// no expiry can land between the check and the copy (MIK-8339).
    pub(crate) fn live_token(&self) -> Option<String> {
        self.current_token
            .read()
            .as_ref()
            .filter(|token| !token.is_expired())
            .map(|token| token.access_token.clone())
    }

    /// The token step a detached request-time task runs (MIK-8339), for a
    /// caller that captured `since` (its cancel epoch) and `cohort` before
    /// it queued. Before a login is led or joined, the refresh observes a
    /// restart or stop (`AuthorizationCancelled`) and ends at
    /// [`grants::OAUTH_AUTHORIZATION_WINDOW`] through
    /// [`LoginGate::classify`](super::super::login_gate::LoginGate::classify),
    /// never falling into a login after its bound. A refresh that succeeds
    /// after a revocation is not handed back.
    pub(crate) async fn get_token_detached(
        &self,
        interactive: bool,
        since: u64,
        cohort: &std::sync::Arc<super::super::login_gate::Cohort>,
        deadline: tokio::time::Instant,
    ) -> Result<String> {
        if let Some(access) = self.live_token() {
            return Ok(access);
        }
        let cancelled = || Error::AuthorizationCancelled {
            backend: self.backend_name.clone(),
        };
        let has_refresh_token = self
            .current_token
            .read()
            .as_ref()
            .is_some_and(|t| t.refresh_token.is_some());
        if has_refresh_token {
            let refreshed = match &self.login_gate {
                Some(gate) => tokio::select! {
                    biased;
                    () = gate.revoked_since(since) => return Err(cancelled()),
                    () = tokio::time::sleep_until(super::super::login_gate::stage_end(
                        grants::OAUTH_AUTHORIZATION_WINDOW,
                        deadline,
                    )) => {
                        return Err(gate.classify(
                            cohort,
                            &self.backend_name,
                            Error::BackendTimeout(self.backend_name.clone()),
                        ));
                    }
                    refreshed = self.refresh_token() => refreshed,
                },
                None => self.refresh_token().await,
            };
            match refreshed {
                Ok(token) => {
                    if self
                        .login_gate
                        .as_ref()
                        .is_some_and(|gate| gate.is_revoked(since))
                    {
                        return Err(cancelled());
                    }
                    return Ok(token);
                }
                Err(e) if is_ssrf_refusal(&e) => return Err(e),
                Err(_) => {}
            }
        }
        self.authorize_shared_with(interactive, Some(since), Some(cohort), Some(deadline))
            .await
    }

    /// Return the backend name (used by the background refresh task for logging).
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// Check if the client has a valid token
    pub fn has_valid_token(&self) -> bool {
        let token = self.current_token.read();
        token.as_ref().is_some_and(|t| !t.is_expired())
    }

    /// Return true if the token should be proactively refreshed.
    ///
    /// Triggers when the remaining lifetime is below [`refresh_buffer`]: a set
    /// buffer, else max(300 s, 10 % of the token lifetime).
    #[must_use]
    pub fn needs_proactive_refresh(&self) -> bool {
        let token = self.current_token.read();
        let Some(ref t) = *token else { return false };

        // Tokens with no expiry never need proactive refresh
        let Some(expires_at) = t.expires_at else {
            return false;
        };

        // A scheduler: on a clock that cannot be read the proactive pass is
        // skipped; `is_expired` still guards every use (MIK-8202).
        let Ok(now) = crate::clock::unix_secs() else {
            return false;
        };

        let remaining = expires_at.saturating_sub(now);

        remaining < refresh_buffer(self.token_refresh_buffer_secs, t.lifetime_secs)
    }
}

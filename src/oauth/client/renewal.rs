// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Background token renewal: the headless grants tried before a token
//! expires, and the task that tries them.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, warn};

use super::OAuthClient;
use crate::security::ssrf::is_ssrf_refusal;

/// What one background renewal attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Renewal {
    /// A headless grant issued a new token.
    Renewed,
    /// The destination policy refused a grant's endpoint. Every later attempt
    /// meets the same policy, and re-authorizing is not the remedy (MIK-7701).
    Refused,
    /// Every headless grant failed: the person must authorize again.
    Exhausted,
}

impl OAuthClient {
    /// Try the headless renewal strategies (`refresh_token`, then
    /// `client_credentials`), stopping at a policy refusal.
    pub(super) async fn attempt_background_renewal(&self) -> Renewal {
        let refresh_token_opt = {
            let token = self.current_token.read();
            token.as_ref().and_then(|t| t.refresh_token.clone())
        };

        if let Some(refresh_token) = refresh_token_opt {
            match self.refresh_token(&refresh_token).await {
                Ok(_) => return Renewal::Renewed,
                Err(e) if is_ssrf_refusal(&e) => return self.refused(&e),
                Err(e) => {
                    debug!(
                        backend = %self.backend_name,
                        error = %e,
                        "Token refresh failed, trying client_credentials"
                    );
                }
            }
        }

        // Headless, for Beeper-style tokens.
        match self.try_client_credentials().await {
            Ok(_) => Renewal::Renewed,
            Err(e) if is_ssrf_refusal(&e) => self.refused(&e),
            Err(e) => {
                debug!(
                    backend = %self.backend_name,
                    error = %e,
                    "client_credentials renewal failed"
                );
                Renewal::Exhausted
            }
        }
    }

    fn refused(&self, error: &crate::Error) -> Renewal {
        warn!(
            backend = %self.backend_name,
            error = %error,
            "Background token renewal stopped: the destination policy refused it"
        );
        Renewal::Refused
    }

    /// Spawn a background task that proactively refreshes the token before it
    /// expires.  The task runs for the lifetime of the provided `Arc`, or
    /// until the destination policy refuses a renewal.
    ///
    /// The returned `JoinHandle` can be aborted to cancel the task.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn spawn_refresh_task(
        client: Arc<TokioMutex<Self>>,
        backend_name: String,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(Self::refresh_loop(
            client,
            backend_name,
            Duration::from_secs(60),
        ))
    }

    /// The refresh task's body, checking every `period`.
    pub(super) async fn refresh_loop(
        client: Arc<TokioMutex<Self>>,
        backend_name: String,
        period: Duration,
    ) {
        loop {
            tokio::time::sleep(period).await;

            // The task holds a strong `Arc`: dropping the transport does not
            // end it. Only a refusal or `abort()` on the handle does.
            let needs_refresh = {
                let guard = client.lock().await;
                guard.needs_proactive_refresh()
            };

            if needs_refresh {
                let renewal = {
                    let guard = client.lock().await;
                    guard.attempt_background_renewal().await
                };

                match renewal {
                    Renewal::Renewed => {}
                    Renewal::Refused => return,
                    Renewal::Exhausted => warn!(
                        backend = %backend_name,
                        "All automatic token renewal strategies failed — \
                         manual re-authorization required"
                    ),
                }
            }
        }
    }
}

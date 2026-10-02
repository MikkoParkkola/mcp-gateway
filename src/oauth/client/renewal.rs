// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Background token renewal: the headless grants tried before a token
//! expires, and the task that tries them.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, warn};

use super::{OAuthClient, destination};

impl OAuthClient {
    /// Try all headless renewal strategies (`refresh_token` → `client_credentials`).
    ///
    /// Returns `Ok(true)` on success, `Ok(false)` when all automatic methods
    /// are unavailable and manual re-authorization is required.
    pub(super) async fn attempt_background_renewal(&self) -> bool {
        // Strategy 1: refresh_token grant
        let refresh_token_opt = {
            let token = self.current_token.read();
            token.as_ref().and_then(|t| t.refresh_token.clone())
        };

        if let Some(refresh_token) = refresh_token_opt {
            match self.refresh_token(&refresh_token).await {
                Ok(_) => return true,
                // A policy refusal: no other grant will reach a different
                // place, and re-authorizing is not the remedy (MIK-7701).
                Err(e) if destination::is_policy_refusal(&e) => {
                    warn!(backend = %self.backend_name, error = %e, "Token renewal refused");
                    return false;
                }
                Err(e) => {
                    debug!(
                        backend = %self.backend_name,
                        error = %e,
                        "Token refresh failed, trying client_credentials"
                    );
                }
            }
        }

        // Strategy 2: client_credentials grant (headless, for Beeper-style tokens)
        match self.try_client_credentials().await {
            Ok(_) => return true,
            Err(e) => {
                debug!(
                    backend = %self.backend_name,
                    error = %e,
                    "client_credentials renewal failed"
                );
            }
        }

        false
    }

    /// Spawn a background task that proactively refreshes the token before it
    /// expires.  The task runs for the lifetime of the provided `Arc`; it
    /// stops automatically when the last strong reference is dropped.
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

            // Use a weak reference pattern: if the Arc has been dropped
            // (HttpTransport gone), stop the loop.
            let needs_refresh = {
                let guard = client.lock().await;
                guard.needs_proactive_refresh()
            };

            if needs_refresh {
                let success = {
                    let guard = client.lock().await;
                    guard.attempt_background_renewal().await
                };

                if !success {
                    warn!(
                        backend = %backend_name,
                        "All automatic token renewal strategies failed — \
                         manual re-authorization required"
                    );
                }
            }
        }
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Everything a backend keeps about signing in, grouped so the backend's
//! constructor builds it in one line.

use std::sync::Arc;

use crate::config::BackendConfig;
use crate::oauth::client::sign_in::{SignIn, SignInStatus};

/// A backend's sign-in state.
pub(crate) struct SignInState {
    /// What the operator is told, written by the OAuth client and read in
    /// memory, so it outlives any one transport.
    pub(crate) status: Arc<SignInStatus>,
    /// The UI sign-in in flight, if one is.
    #[cfg(feature = "webui")]
    pub(crate) flow: parking_lot::Mutex<Option<super::sign_in_flow::Flow>>,
    /// How long a sign-in waits at each stage.
    #[cfg(feature = "webui")]
    pub(crate) windows: parking_lot::Mutex<super::sign_in_flow::SignInWindows>,
    /// A test's pre-built OAuth client for the sign-in flow.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) installed_client: parking_lot::Mutex<Option<Arc<crate::oauth::OAuthClient>>>,
    /// Where a test holds the sign-in flow's expiry task.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) expiry_pause: crate::test_pause::Slot,
    /// Where a test holds the flow task after the exchange has returned, just
    /// before it stores the grant.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) hold_pause: crate::test_pause::Slot,
}

impl SignInState {
    /// The state of a backend with `config`. OAuth-ness is config's: an
    /// `oauth` block, never whether a client exists.
    pub(crate) fn for_config(config: &BackendConfig) -> Self {
        let initial = if config.oauth.as_ref().is_some_and(|oauth| oauth.enabled) {
            SignIn::NotYetChecked
        } else {
            SignIn::NotOAuth
        };
        Self {
            status: Arc::new(SignInStatus::new(initial)),
            #[cfg(feature = "webui")]
            flow: parking_lot::Mutex::new(None),
            #[cfg(feature = "webui")]
            windows: parking_lot::Mutex::default(),
            #[cfg(all(test, feature = "webui"))]
            installed_client: parking_lot::Mutex::new(None),
            #[cfg(all(test, feature = "webui"))]
            expiry_pause: crate::test_pause::Slot::default(),
            #[cfg(all(test, feature = "webui"))]
            hold_pause: crate::test_pause::Slot::default(),
        }
    }
}

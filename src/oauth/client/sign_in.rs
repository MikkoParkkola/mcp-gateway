// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's OAuth sign-in as an operator acts on it, and the grant a UI
//! sign-in holds between the callback and the operator's confirmation.
//!
//! The status is written by the client when it learns something about its
//! token (issuer resolution, a refresh) and read in memory by the backend:
//! a read never touches storage or the network.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use super::OAuthClient;
use crate::oauth::TokenInfo;

/// How long a callback's grant waits for the operator's confirmation, from the
/// callback. The pending grant lives in memory for at most this long.
#[allow(dead_code, reason = "the confirm step of the flow reads it")]
pub(crate) const SIGN_IN_CONFIRM_WINDOW: Duration = Duration::from_secs(60);

/// A backend's sign-in, as an operator acts on it. Secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum SignIn {
    /// No `oauth` block and no wait on a sign-in.
    #[serde(rename = "not_oauth")]
    NotOAuth,
    /// An OAuth backend whose issuer is not resolved yet, so its token state
    /// is not knowable without network discovery.
    NotYetChecked,
    /// A token is held, and it is unexpired or refreshable.
    SignedIn {
        /// When the access token expires, if it says.
        #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rfc3339")]
        expires_at: Option<SystemTime>,
    },
    /// A token is held but expired with no refresh token, or its slot waits
    /// on a sign-in.
    Expired,
    /// Resolved, with no 4.x token and no 3.x token file.
    NeverSignedIn,
    /// Resolved, with no 4.x token but a 3.x token file under the legacy key.
    ReSignInAfterUpgrade,
    /// No `oauth` block, but the slot waits on a sign-in made elsewhere.
    #[cfg_attr(
        not(any(test, feature = "webui")),
        expect(dead_code, reason = "constructed only on the web UI read path")
    )]
    WaitingElsewhere,
}

/// `expires_at` as RFC 3339.
#[expect(
    clippy::ref_option,
    reason = "serde's `serialize_with` hands the field over as `&Option<T>`"
)]
fn rfc3339<S: Serializer>(at: &Option<SystemTime>, out: S) -> Result<S::Ok, S::Error> {
    match at {
        Some(at) => out.serialize_str(&chrono::DateTime::<chrono::Utc>::from(*at).to_rfc3339()),
        None => out.serialize_none(),
    }
}

impl SignIn {
    /// Whether a person must sign in for this state to clear. A wait on a
    /// sign-in needs one whatever the state says.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn needs_a_person(self) -> bool {
        matches!(
            self,
            Self::Expired
                | Self::NeverSignedIn
                | Self::ReSignInAfterUpgrade
                | Self::WaitingElsewhere
        )
    }
}

/// The backend-owned sign-in status, independent of the transport's lifetime.
#[derive(Debug)]
pub(crate) struct SignInStatus {
    cell: parking_lot::Mutex<SignIn>,
}

impl SignInStatus {
    /// A cell holding `initial`.
    pub(crate) fn new(initial: SignIn) -> Self {
        Self {
            cell: parking_lot::Mutex::new(initial),
        }
    }

    /// Replace the value.
    pub(crate) fn set(&self, next: SignIn) {
        *self.cell.lock() = next;
    }

    /// The current value: one snapshot, so a variant and its `expires_at`
    /// cannot disagree.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn snapshot(&self) -> SignIn {
        *self.cell.lock()
    }
}

/// A callback's exchanged token, held in memory until the operator confirms.
///
/// Not `Clone` and not `Debug`: it exists once, its secrets are wiped on drop,
/// and it becomes a `TokenInfo` only inside the confirm path's save.
#[allow(
    dead_code,
    reason = "the flow holds a grant between callback and confirm"
)]
pub(crate) struct PendingGrant {
    /// The access token.
    pub(crate) access_token: Zeroizing<String>,
    /// The refresh token, if the provider issued one.
    pub(crate) refresh_token: Option<Zeroizing<String>>,
    /// The token type the provider named.
    pub(crate) token_type: Option<String>,
    /// Seconds the access token lives, as the provider said.
    pub(crate) expires_in: Option<u64>,
    /// The scope the provider granted.
    pub(crate) scope: Option<String>,
}

impl OAuthClient {
    /// This client publishing its backend's sign-in to `status`.
    pub(crate) fn with_sign_in_status(mut self, status: Arc<SignInStatus>) -> Self {
        self.sign_in_status = Some(status);
        self
    }

    /// Evaluate the token state and write it to the status cell: one token
    /// file load and one legacy-file check, done here and never on a read.
    pub(crate) fn publish_sign_in(&self) {
        if self.sign_in_status.is_none() {
            return;
        }
        let held = self
            .credential_key()
            .ok()
            .and_then(|key| self.storage.load(&key, &self.resource_url));
        self.publish_token_state(held.as_ref());
    }

    /// Write the state `held` (the token just loaded or saved, if any) puts
    /// this client in.
    pub(super) fn publish_token_state(&self, held: Option<&TokenInfo>) {
        let Some(status) = &self.sign_in_status else {
            return;
        };
        status.set(self.sign_in_of(held));
    }

    fn sign_in_of(&self, held: Option<&TokenInfo>) -> SignIn {
        if self.auth_metadata.is_none() {
            return SignIn::NotYetChecked;
        }
        match held {
            Some(token) => token_state(token),
            None if self
                .storage
                .legacy_token_exists(&self.backend_name, &self.resource_url) =>
            {
                SignIn::ReSignInAfterUpgrade
            }
            None => SignIn::NeverSignedIn,
        }
    }
}

/// The state a held token is in: refreshable (a refresh token is present) or
/// unexpired is signed in.
fn token_state(token: &TokenInfo) -> SignIn {
    if token.is_expired() && token.refresh_token.is_none() {
        return SignIn::Expired;
    }
    SignIn::SignedIn {
        expires_at: token
            .expires_at
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)),
    }
}

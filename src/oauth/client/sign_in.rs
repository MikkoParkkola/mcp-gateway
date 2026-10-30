// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's OAuth sign-in as an operator acts on it, and the grant a UI
//! sign-in holds between the callback and the operator's confirmation.
//!
//! Skeleton: the types and their signatures only. The status is written by the
//! client and read in memory, never from storage or the network.

// The readers land with the backends read; until then only tests call them.
#![allow(dead_code, reason = "skeleton: the first callers land with the read")]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use zeroize::Zeroizing;

use super::OAuthClient;

/// How long a callback's grant waits for the operator's confirmation, from the
/// callback. The pending grant lives in memory for at most this long.
pub(crate) const SIGN_IN_CONFIRM_WINDOW: Duration = Duration::from_secs(60);

/// A backend's sign-in, as an operator acts on it. Secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum SignIn {
    /// No `oauth` block and no wait on a sign-in.
    NotOAuth,
    /// An OAuth backend whose issuer is not resolved yet, so its token state
    /// is not knowable without network discovery.
    NotYetChecked,
    /// A token is held, and it is unexpired or refreshable.
    SignedIn {
        /// When the access token expires, if it says.
        #[serde(skip_serializing_if = "Option::is_none")]
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
    WaitingElsewhere,
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

    /// Replace the value. Skeleton: it stores nothing.
    #[expect(
        clippy::unused_self,
        reason = "skeleton: the cell is written once the client publishes"
    )]
    pub(crate) fn set(&self, _next: SignIn) {}

    /// The current value: one snapshot, so a variant and its `expires_at`
    /// cannot disagree.
    pub(crate) fn snapshot(&self) -> SignIn {
        *self.cell.lock()
    }
}

/// A callback's exchanged token, held in memory until the operator confirms.
///
/// Not `Clone` and not `Debug`: it exists once, its secrets are wiped on drop,
/// and it becomes a `TokenInfo` only inside the confirm path's save.
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
    /// Skeleton: it publishes nothing.
    #[expect(clippy::unused_self, reason = "skeleton: nothing is published yet")]
    pub(crate) fn publish_sign_in(&self) {}
}

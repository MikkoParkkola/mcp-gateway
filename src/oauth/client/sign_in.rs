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
    /// Bumped once a confirmed sign-in is durable in storage, so a client
    /// holding an older token knows to adopt the new one.
    installed: std::sync::atomic::AtomicU64,
}

impl SignInStatus {
    /// A cell holding `initial`.
    pub(crate) fn new(initial: SignIn) -> Self {
        Self {
            cell: parking_lot::Mutex::new(initial),
            installed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How many confirmed sign-ins have been installed.
    pub(crate) fn installed(&self) -> u64 {
        self.installed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record a confirmed sign-in, returning the new count.
    #[cfg(feature = "webui")]
    pub(crate) fn bump_installed(&self) -> u64 {
        self.installed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
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
#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "only the web UI flow holds a grant")
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

#[cfg(feature = "webui")]
impl PendingGrant {
    /// Hold what a code redemption issued. The secrets move into wiped
    /// buffers; no copy is left behind.
    pub(crate) fn from_token(token: TokenInfo) -> Self {
        Self {
            access_token: Zeroizing::new(token.access_token),
            refresh_token: token.refresh_token.map(Zeroizing::new),
            token_type: Some(token.token_type),
            expires_in: token.lifetime_secs,
            scope: token.scope,
        }
    }

    /// The token to save, its lifetime shortened by the time it was `held_for`.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock cannot be read.
    pub(crate) fn into_token(mut self, held_for: Duration) -> crate::Result<TokenInfo> {
        let now = super::issuance_clock()?;
        let remaining = self
            .expires_in
            .map(|secs| secs.saturating_sub(held_for.as_secs()));
        Ok(TokenInfo::from_response_at(
            std::mem::take(&mut *self.access_token),
            self.token_type.take(),
            self.refresh_token
                .as_mut()
                .map(|r| std::mem::take(&mut **r)),
            remaining,
            self.scope.take(),
            now,
        ))
    }
}

/// What a UI-started login hands the OAuth client: the channels its route and
/// engine wait on.
#[cfg(feature = "webui")]
pub(crate) struct UiSink {
    /// The authorization link goes here, once, and nowhere else.
    pub(crate) link: tokio::sync::oneshot::Sender<String>,
    /// Told when the callback has landed and its code is being redeemed.
    pub(crate) callback: tokio::sync::oneshot::Sender<()>,
    /// How long the redemption of the code may take from the callback: the
    /// flow's confirm window.
    pub(crate) confirm_window: Duration,
}

/// The sink a login may carry: only the web UI starts one that has it.
#[cfg(feature = "webui")]
pub(super) type Hook = UiSink;
/// The sink a login may carry: none, without the web UI.
#[cfg(not(feature = "webui"))]
pub(super) type Hook = std::convert::Infallible;

/// The confirm window a sink carries, else the default.
#[cfg(feature = "webui")]
pub(super) fn confirm_window_of(ui: Option<&Hook>) -> Duration {
    ui.map_or(SIGN_IN_CONFIRM_WINDOW, |sink| sink.confirm_window)
}

/// The confirm window a sink carries, else the default.
#[cfg(not(feature = "webui"))]
pub(super) fn confirm_window_of(_ui: Option<&Hook>) -> Duration {
    SIGN_IN_CONFIRM_WINDOW
}

/// The two channels of a sink, if the login has one.
#[cfg(feature = "webui")]
pub(super) fn split_hook(
    ui: Option<Hook>,
) -> (
    Option<tokio::sync::oneshot::Sender<String>>,
    Option<tokio::sync::oneshot::Sender<()>>,
) {
    ui.map_or((None, None), |sink| (Some(sink.link), Some(sink.callback)))
}

/// The two channels of a sink, if the login has one.
#[cfg(not(feature = "webui"))]
pub(super) fn split_hook(
    ui: Option<Hook>,
) -> (
    Option<tokio::sync::oneshot::Sender<String>>,
    Option<tokio::sync::oneshot::Sender<()>>,
) {
    match ui {
        Some(never) => match never {},
        None => (None, None),
    }
}

impl OAuthClient {
    /// This client publishing its backend's sign-in to `status`.
    pub(crate) fn with_sign_in_status(mut self, status: Arc<SignInStatus>) -> Self {
        self.installed_seen
            .store(status.installed(), std::sync::atomic::Ordering::SeqCst);
        self.sign_in_status = Some(status);
        self
    }

    /// Whether a sign-in was confirmed since this client last adopted from
    /// storage: its cached token may be an older one.
    pub(super) fn install_stale(&self) -> bool {
        self.sign_in_status.as_ref().is_some_and(|status| {
            status.installed()
                != self
                    .installed_seen
                    .load(std::sync::atomic::Ordering::SeqCst)
        })
    }

    /// Take the confirmed token from storage. The counter is sampled before
    /// storage is read and recorded only after the adopt succeeded; if it
    /// moved meanwhile, adopt again. A token inside the expiry buffer cannot
    /// be adopted as live, but is still loaded so a refresh can use its
    /// refresh token; `None` then.
    pub(super) fn adopt_installed(&self) -> Option<String> {
        let status = self.sign_in_status.as_ref()?;
        loop {
            let sampled = status.installed();
            let adopted = self.adopt_stored_login();
            if adopted.is_none()
                && let Some(stored) = self
                    .credential_key()
                    .ok()
                    .and_then(|key| self.storage.load(&key, &self.resource_url))
            {
                *self.current_token.write() = Some(stored);
            }
            self.installed_seen
                .store(sampled, std::sync::atomic::Ordering::SeqCst);
            if status.installed() == sampled {
                return adopted;
            }
        }
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

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
    /// A confirmed sign-in was saved under an issuer the serving client has
    /// not adopted: the provider changed, so a person must sign in again. Only
    /// adopting an install under that issuer clears it.
    ProviderChanged,
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
                | Self::ProviderChanged
        )
    }
}

/// What the cell keeps: a fixed status, or the secret-free facts of a held
/// token, classified against the clock each time the cell is read.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "only the web UI read (`snapshot`) classifies what the cell keeps"
    )
)]
enum Stored {
    Fixed(SignIn),
    Held {
        expires_at: Option<u64>,
        refreshable: bool,
    },
}

/// The backend-owned sign-in status, independent of the transport's lifetime.
#[derive(Debug)]
pub(crate) struct SignInStatus {
    cell: parking_lot::Mutex<Stored>,
    /// Bumped once a confirmed sign-in is durable in storage, so a client
    /// holding an older token knows to adopt the new one.
    installed: std::sync::atomic::AtomicU64,
    /// The storage key (which names the issuer) the latest confirmed sign-in
    /// was saved under; stored before the count is bumped.
    install_key: parking_lot::Mutex<Option<String>>,
}

impl SignInStatus {
    /// A cell holding `initial`.
    pub(crate) fn new(initial: SignIn) -> Self {
        Self {
            cell: parking_lot::Mutex::new(Stored::Fixed(initial)),
            installed: std::sync::atomic::AtomicU64::new(0),
            install_key: parking_lot::Mutex::new(None),
        }
    }

    /// How many confirmed sign-ins have been installed.
    pub(crate) fn installed(&self) -> u64 {
        self.installed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record a confirmed sign-in saved under `key`, returning the new count.
    /// The key and the count change under the install-key lock, so a reader
    /// that sees the new count sees the key it belongs to, and no
    /// [`Self::if_current`] write straddles the install.
    #[cfg(feature = "webui")]
    pub(crate) fn record_install(&self, key: &str) -> u64 {
        let mut installed = self.install_key.lock();
        *installed = Some(key.to_owned());
        self.installed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }

    /// Test-only: record an install unless the install-key lock is held.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn try_record_install_for_test(&self, key: &str) -> bool {
        let Some(mut installed) = self.install_key.try_lock() else {
            return false;
        };
        *installed = Some(key.to_owned());
        self.installed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        true
    }

    /// The storage key of the latest confirmed sign-in, if any.
    pub(crate) fn install_key(&self) -> Option<String> {
        self.install_key.lock().clone()
    }

    /// Run `write` unless the latest confirmed sign-in is under another key
    /// than `key`, holding the install-key lock across the check and the
    /// write, so no install lands between them. Whether it ran.
    pub(crate) fn if_current(&self, key: Option<&str>, write: impl FnOnce()) -> bool {
        let installed = self.install_key.lock();
        if let (Some(installed), Some(key)) = (installed.as_deref(), key)
            && installed != key
        {
            return false;
        }
        write();
        true
    }

    /// Replace the value.
    pub(crate) fn set(&self, next: SignIn) {
        let mut cell = self.cell.lock();
        // A publish from the old issuer's credential cannot clear the reason.
        if matches!(*cell, Stored::Fixed(SignIn::ProviderChanged))
            && next != SignIn::ProviderChanged
        {
            return;
        }
        *cell = Stored::Fixed(next);
    }

    /// The provider changed issuer: a person must sign in again. Only
    /// [`Self::clear_provider_changed`] ends it.
    pub(crate) fn raise_provider_changed(&self) {
        *self.cell.lock() = Stored::Fixed(SignIn::ProviderChanged);
    }

    /// An install under the serving client's own issuer was adopted.
    /// Whether a reason was cleared, so the caller can publish in its place.
    pub(crate) fn clear_provider_changed(&self) -> bool {
        let mut cell = self.cell.lock();
        let raised = matches!(*cell, Stored::Fixed(SignIn::ProviderChanged));
        if raised {
            *cell = Stored::Fixed(SignIn::NeverSignedIn);
        }
        raised
    }

    /// Keep a held token's expiry and whether it can be refreshed, so the
    /// status ages with the clock instead of freezing at publish time.
    pub(crate) fn set_held(&self, expires_at: Option<u64>, refreshable: bool) {
        let mut cell = self.cell.lock();
        if matches!(*cell, Stored::Fixed(SignIn::ProviderChanged)) {
            return;
        }
        *cell = Stored::Held {
            expires_at,
            refreshable,
        };
    }

    /// The current value: one snapshot, so a variant and its `expires_at`
    /// cannot disagree.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn snapshot(&self) -> SignIn {
        match *self.cell.lock() {
            Stored::Fixed(status) => status,
            // The one rule for a held token, `token_state`, on a token that
            // carries only its expiry and whether it has a refresh token.
            Stored::Held {
                expires_at,
                refreshable,
            } => {
                let mut token = TokenInfo::from_response_at(
                    String::new(),
                    None,
                    refreshable.then(String::new),
                    None,
                    None,
                    0,
                );
                token.expires_at = expires_at;
                token_state(&token)
            }
        }
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
    /// When the access token expires, as the exchange dated it.
    pub(crate) expires_at: Option<u64>,
    /// Seconds the access token lives, as the provider said.
    pub(crate) lifetime_secs: Option<u64>,
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
            expires_at: token.expires_at,
            lifetime_secs: token.lifetime_secs,
            scope: token.scope,
        }
    }

    /// The token to save: the exchange's own expiry and lifetime, rebuilt
    /// field by field. The secrets move out of their wiped buffers with
    /// `mem::take`, so no plain copy is left behind.
    pub(crate) fn into_token(mut self) -> TokenInfo {
        TokenInfo {
            access_token: std::mem::take(&mut *self.access_token),
            token_type: self
                .token_type
                .take()
                .unwrap_or_else(|| "Bearer".to_owned()),
            refresh_token: self
                .refresh_token
                .as_mut()
                .map(|r| std::mem::take(&mut **r)),
            expires_at: self.expires_at,
            scope: self.scope.take(),
            token_endpoint: None,
            client_id: None,
            client_secret: None,
            lifetime_secs: self.lifetime_secs,
        }
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

/// Proof that a grant of this client's credential may run. Its field is
/// private to this module, so only [`OAuthClient::issuer_current`] and
/// [`OAuthClient::ui_sign_in`] make one; every grant entry takes it, and a
/// grant path that skips the issuer check does not compile.
pub(crate) struct GrantAllowed {
    _only_here: (),
}

impl OAuthClient {
    /// This client publishing its backend's sign-in to `status`.
    pub(crate) fn with_sign_in_status(mut self, status: Arc<SignInStatus>) -> Self {
        self.installed_seen
            .store(status.installed(), std::sync::atomic::Ordering::SeqCst);
        self.sign_in_status = Some(status);
        self
    }

    /// What the task that completes a refresh runs once the state is settled:
    /// publish the stored token's state, so a caller that left earlier still
    /// sees it. Nothing under a credential key the latest install is not.
    pub(super) fn settled_publisher(&self, key: &str) -> Option<Box<dyn Fn() + Send + Sync>> {
        let status = Arc::clone(self.sign_in_status.as_ref()?);
        let (storage, resource_url, key) = (
            Arc::clone(&self.storage),
            self.resource_url.clone(),
            key.to_owned(),
        );
        Some(Box::new(move || {
            status.if_current(Some(&key), || {
                if let Some(token) = storage.load(&key, &resource_url) {
                    status.set_held(token.expires_at, token.refresh_token.is_some());
                }
            });
        }))
    }

    /// The one way a token loaded from storage enters the cache: only while the
    /// latest confirmed sign-in is under this client's own key, checked under
    /// the install-key lock. Whether it was cached.
    pub(super) fn cache_loaded(&self, token: TokenInfo) -> bool {
        let key = self.credential_key().ok();
        if let Some(status) = &self.sign_in_status {
            return status.if_current(key.as_deref(), || {
                *self.current_token.write() = Some(token);
            });
        }
        *self.current_token.write() = Some(token);
        true
    }

    /// Whether the latest confirmed sign-in was saved under another issuer
    /// than this client discovered: then no credential of either issuer is
    /// used until the client has re-discovered and agrees.
    pub(super) fn issuer_differs(&self) -> bool {
        let Some(status) = &self.sign_in_status else {
            return false;
        };
        match (status.install_key(), self.credential_key().ok()) {
            (Some(installed), Some(own)) => installed != own,
            _ => false,
        }
    }

    /// The check before any grant of this client's credential (a refresh, a
    /// client-credentials grant or a login): the proof a grant entry takes
    /// while the latest install is under this client's key, else the sign-in
    /// wait.
    pub(super) fn issuer_current(&self) -> crate::Result<GrantAllowed> {
        if self.issuer_differs() {
            return Err(self.issuer_wait());
        }
        Ok(GrantAllowed { _only_here: () })
    }

    /// The one grant that may run under another issuer than the latest
    /// install's: a web-UI sign-in, where a person signs in at the issuer this
    /// client just discovered and the confirm records the new install. Only
    /// `authorize_for_ui` calls it.
    #[cfg(feature = "webui")]
    pub(super) fn ui_sign_in() -> GrantAllowed {
        GrantAllowed { _only_here: () }
    }

    /// The sign-in wait a caller gets while the issuers differ.
    pub(super) fn issuer_wait(&self) -> crate::Error {
        crate::Error::AuthorizationRequired {
            backend: self.backend_name.clone(),
        }
    }

    /// Re-discover when the install was saved under another issuer, on the
    /// token step that holds `&mut` on the client. The documents are fetched
    /// without being kept; they are committed, without a second `initialize`,
    /// only if their issuer is the install's. A fetch or parse failure is the
    /// discovery's own error. A differing issuer fails closed with the sign-in
    /// wait, the in-memory token dropped and the reason raised on the status.
    pub(crate) async fn rediscover_if_moved(&mut self) -> crate::Result<()> {
        // No cell means no install record to compare against: nothing moved.
        // `issuer_differs` already answers no then; checked first so no path
        // below can find the cell missing.
        let Some(status) = self.sign_in_status.clone() else {
            return Ok(());
        };
        if !self.issuer_differs() {
            return Ok(());
        }
        let discovered = self.discover_documents().await?;
        #[cfg(all(test, feature = "webui"))]
        self.rediscovery_pause.pause().await;
        let found = super::storage_key(&self.backend_name, &discovered.auth.issuer);
        if status.install_key().as_deref() != Some(found.as_str()) {
            *self.current_token.write() = None;
            status.raise_provider_changed();
            return Err(self.issuer_wait());
        }
        status.clear_provider_changed();
        self.commit_discovery(discovered)
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
    /// this client in. Nothing while the latest install is under another
    /// issuer: the status is that sign-in's, as in `settled_publisher`.
    pub(super) fn publish_token_state(&self, held: Option<&TokenInfo>) {
        let Some(status) = &self.sign_in_status else {
            return;
        };
        let key = self.credential_key().ok();
        status.if_current(key.as_deref(), || {
            #[cfg(all(test, feature = "webui"))]
            self.publish_pause.pause_blocking();
            match held {
                Some(token) if self.auth_metadata.is_some() => {
                    status.set_held(token.expires_at, token.refresh_token.is_some());
                }
                _ => status.set(self.sign_in_of(held)),
            }
        });
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

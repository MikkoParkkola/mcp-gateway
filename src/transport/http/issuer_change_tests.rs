// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sign-in confirmed under a changed issuer reaches the serving client only
//! after it has re-discovered: adopted when discovery agrees, a sign-in wait
//! with a reason when it still disagrees, and no credential used across the
//! boundary in between. Rows drive the transport's own request path, once as
//! an interactive caller and once as a non-interactive one (the health probe).

use std::sync::Arc;

use super::HttpTransport;
use super::issuer_change_double::{BACKEND_NAME, Disco, cell, client_of, disco, serve};
use crate::Error;
use crate::oauth::TokenInfo;
use crate::oauth::client::sign_in::{PendingGrant, SignIn, SignInStatus};
use crate::oauth::client::storage_key;
use crate::oauth::{OAuthClient, login_gate};
use crate::test_wait::HANG_BOUND;

pub(super) fn a_token(access: &str, refresh: Option<&str>) -> TokenInfo {
    TokenInfo::from_response(
        access.to_owned(),
        None,
        refresh.map(str::to_owned),
        Some(3600),
        None,
    )
}

/// Which kind of caller asks for the token.
#[derive(Clone, Copy, Debug)]
pub(super) enum Caller {
    Interactive,
    NonInteractive,
}

pub(super) const CALLERS: [Caller; 2] = [Caller::Interactive, Caller::NonInteractive];

/// A serving client on issuer A holding a live "old" token, and a confirming
/// client that discovered issuer B, sharing one store and one status cell.
pub(super) struct World {
    pub(super) disco: Disco,
    pub(super) cell: Arc<SignInStatus>,
    pub(super) serving: Arc<HttpTransport>,
    pub(super) confirming: OAuthClient,
    _dir: tempfile::TempDir,
}

pub(super) async fn world() -> World {
    let disco = disco().await;
    let dir = tempfile::tempdir().unwrap();
    let cell = cell();
    let mut serving = client_of(&disco, dir.path(), &cell);
    serving.initialize().await.expect("discovery names A");
    serving.seed_token_for_test(&a_token("old", None));
    disco.name_b();
    let mut confirming = client_of(&disco, dir.path(), &cell);
    confirming.initialize().await.expect("discovery names B");
    World {
        disco,
        cell,
        serving: serve(serving),
        confirming,
        _dir: dir,
    }
}

impl World {
    /// The confirming client saves `token` under issuer B.
    pub(super) async fn confirm(&self, token: TokenInfo) {
        let cancel = tokio_util::sync::CancellationToken::new();
        let by = tokio::time::Instant::now() + HANG_BOUND;
        self.confirming
            .save_confirmed(PendingGrant::from_token(token), &cancel, by)
            .await
            .expect("the confirm saves");
    }

    /// The next token, through the request path, for `caller`.
    pub(super) async fn token(&self, caller: Caller) -> crate::Result<Option<String>> {
        let ask = self.serving.get_oauth_token();
        let answer = match caller {
            Caller::Interactive => tokio::time::timeout(HANG_BOUND, ask).await,
            Caller::NonInteractive => {
                tokio::time::timeout(HANG_BOUND, login_gate::non_interactive(ask)).await
            }
        };
        answer.expect("the request path answers within the bound")
    }

    /// The serving client's own mutex.
    pub(super) fn serving_client(&self) -> Arc<tokio::sync::Mutex<OAuthClient>> {
        self.serving.oauth_client_for_test().expect("a client")
    }
}

// The confirm is under B and discovery answers B: the next token is the new
// one, the serving client now holds B and the install's key, and the old A
// token was never served. Red today: the serving client reads its own (A) key
// and serves "old".
#[tokio::test]
async fn a_confirm_under_a_changed_issuer_is_adopted_only_after_rediscovery() {
    for caller in CALLERS {
        let w = world().await;
        w.confirm(a_token("new", Some("r2"))).await;

        let first = w.token(caller).await.expect("a token");

        assert_eq!(
            first.as_deref(),
            Some("new"),
            "{caller:?}: never the old A token"
        );
        let client = w.serving_client();
        let held = client.lock().await;
        assert_eq!(
            held.issuer_for_test().as_deref(),
            Some(w.disco.issuer_b.as_str())
        );
        assert_eq!(
            held.credential_key_for_test(),
            Some(storage_key(BACKEND_NAME, &w.disco.issuer_b)),
            "{caller:?}: the install's key"
        );
        assert!(!held.install_stale_for_test(), "{caller:?}: acknowledged");
        drop(held);
        assert_eq!(w.token(caller).await.unwrap().as_deref(), Some("new"));
    }
}

// Discovery still answers A: the call is a sign-in wait, the reason is on the
// status, nothing from either issuer is served, the install stays
// unacknowledged, and an old-issuer publish cannot clear the reason. Red
// today: the old token is served and the install is acknowledged.
#[tokio::test]
async fn a_confirm_under_a_changed_issuer_fails_closed_when_discovery_still_disagrees() {
    for caller in CALLERS {
        let w = world().await;
        w.confirm(a_token("new", Some("r2"))).await;
        w.disco.name_a();

        for round in 0..2 {
            let refused = w
                .token(caller)
                .await
                .expect_err("no token across the boundary");
            assert!(
                matches!(refused, Error::AuthorizationRequired { .. }),
                "{caller:?} round {round}: {refused}"
            );
            assert!(
                refused.is_authorization_wait(),
                "{caller:?}: a sign-in wait"
            );
        }
        assert_eq!(w.cell.snapshot(), SignIn::ProviderChanged, "{caller:?}");
        assert!(w.cell.snapshot().needs_a_person());
        let client = w.serving_client();
        let held = client.lock().await;
        assert!(
            held.install_stale_for_test(),
            "{caller:?}: not acknowledged"
        );
        // An old-issuer publish, as a renewal or a successful start does.
        held.publish_sign_in();
        assert_eq!(
            w.cell.snapshot(),
            SignIn::ProviderChanged,
            "{caller:?}: an old-issuer publish cannot clear it"
        );
    }
}

// Before any re-discovery, a direct `get_token` (the health probe's path)
// serves no token from either issuer. Red today: it serves "old".
#[tokio::test]
async fn a_probe_during_an_issuer_change_uses_no_credential() {
    let w = world().await;
    w.confirm(a_token("new", Some("r2"))).await;

    let client = w.serving_client();
    let probed = client.lock().await.get_token().await;

    let refused = probed.expect_err("no token while the issuers differ");
    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
}

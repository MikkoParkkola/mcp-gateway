// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The flow task's wait on the login and its callback signal.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::Run;
use crate::backend::Backend;
use crate::backend::sign_in_flow::{Flow, Phase};
use crate::config::{AuthConfig, BackendConfig, FailsafeConfig};
use crate::oauth::OAUTH_AUTHORIZATION_WINDOW;
use crate::oauth::client::authorize_tests::client;
use crate::oauth::client::sign_in::PendingGrant;
use crate::oauth::login_gate::Begin;
use crate::test_wait::HANG_BOUND;

fn a_grant() -> PendingGrant {
    PendingGrant {
        access_token: Zeroizing::new("held".to_owned()),
        refresh_token: None,
        token_type: None,
        expires_in: None,
        scope: None,
    }
}

/// A flow in `AwaitingCallback` with a far-off start deadline.
fn seeded_flow(client: &Arc<crate::oauth::OAuthClient>) -> Flow {
    Flow {
        owner: "owner".to_owned(),
        attempt_id: "probe".to_owned(),
        phase: Phase::AwaitingCallback,
        until: Instant::now() + OAUTH_AUTHORIZATION_WINDOW,
        until_at: crate::clock::system_time_or_before_epoch() + OAUTH_AUTHORIZATION_WINDOW,
        grant: None,
        held_since: None,
        wait_generation: 0,
        caller: None,
        ended: Arc::new(tokio::sync::Notify::new()),
        client: Arc::clone(client),
    }
}

/// M20's row. The callback signal and the login's result are both ready
/// before the task's first poll of its wait. With two ready branches
/// `tokio::select!` picks its start branch at random each poll, so a mutant
/// without `biased;` survives all 64 with probability 2^-64. The confirm
/// window must have started: phase `awaiting_confirm`, and an end within the
/// confirm window from now, not the start deadline.
#[tokio::test]
async fn the_confirm_window_starts_even_when_the_login_is_already_done() {
    let (state, _fixture) =
        crate::gateway::router::tests::audience_state(&AuthConfig::default(), (None, None), |m| m)
            .await;
    let backend = Arc::new(Backend::new(
        "probe",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let dir = tempfile::tempdir().unwrap();
    let oauth = Arc::new(client(dir.path(), None));
    let confirm = backend.sign_in_windows().confirm;
    for round in 0..64 {
        backend.with_flow(|slot| *slot = Some(seeded_flow(&oauth)));
        let Begin::Lead(lead) = backend.login_gate.begin(None, None) else {
            panic!("round {round}: the gate was not free");
        };
        let (signal, callback) = oneshot::channel();
        signal.send(()).expect("the receiver is alive");
        let run = Run {
            state: Arc::clone(&state),
            backend: Arc::clone(&backend),
            client: Arc::clone(&oauth),
            attempt_id: "probe".to_owned(),
            deadline: Instant::now() + OAUTH_AUTHORIZATION_WINDOW,
            ended: Arc::new(tokio::sync::Notify::new()),
        };

        let result = run
            .watch_login(&lead, std::future::ready(Ok(a_grant())), callback)
            .await;

        assert!(result.is_ok(), "round {round}");
        let (phase, until) = backend
            .with_flow(|slot| slot.as_ref().map(|flow| (flow.phase, flow.until)))
            .expect("the flow is still there");
        assert_eq!(phase, Phase::AwaitingConfirm, "round {round}");
        let left = until.saturating_duration_since(Instant::now());
        assert!(
            left <= confirm && left + HANG_BOUND > confirm,
            "round {round}: the end is the confirm window, not the start deadline: {left:?}"
        );
        lead.end(None);
        backend.with_flow(|slot| *slot = None);
    }
}

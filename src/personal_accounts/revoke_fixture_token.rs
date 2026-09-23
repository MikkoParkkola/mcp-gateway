// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fake authorization server's `/token` and clock for the consent
//! callback rows (design §11.1): scripted answers, a request log, a hold gate
//! the test releases explicitly, and a hook that runs inside the exchange
//! window (after consume, before commit).

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::super::provider::Clock;

/// One held `/token` request: `entered` fires when it arrives, and it waits
/// for `release`.
#[derive(Clone)]
pub(crate) struct Hold {
    pub(crate) entered: Arc<Notify>,
    pub(crate) release: Arc<Notify>,
}

type Hook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
pub(crate) struct TokenScript {
    log: Mutex<Vec<BTreeMap<String, String>>>,
    queued: Mutex<VecDeque<(u16, Value)>>,
    minted: AtomicU32,
    hold: Mutex<Option<Hold>>,
    hook: Mutex<Option<Hook>>,
}

/// The default grant: distinct tokens per request, the descriptor's scope.
pub(crate) fn minted_grant(n: u32) -> Value {
    json!({"access_token": format!("fresh-access-{n}-9e4a"),
           "refresh_token": format!("fresh-refresh-{n}-5c1d"),
           "token_type": "Bearer", "expires_in": 3600, "scope": "fixture.read"})
}

/// [`minted_grant`] already expired: custody reads expiry off the system
/// clock, so [`super::RevokeFixture::advance`] cannot age a grant.
pub(crate) fn expired_grant(n: u32) -> Value {
    let mut grant = minted_grant(n);
    grant["expires_in"] = json!(0);
    grant
}

pub(crate) async fn token_endpoint(
    State(script): State<Arc<TokenScript>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    script.log.lock().unwrap().push(form);
    let hook = script.hook.lock().unwrap().take();
    if let Some(hook) = hook {
        hook();
    }
    let hold = script.hold.lock().unwrap().take();
    if let Some(hold) = hold {
        hold.entered.notify_one();
        hold.release.notified().await;
    }
    let queued = script.queued.lock().unwrap().pop_front();
    let (status, body) = queued.unwrap_or_else(|| {
        let n = script.minted.fetch_add(1, Ordering::SeqCst) + 1;
        (200, minted_grant(n))
    });
    (StatusCode::from_u16(status).unwrap(), Json(body))
}

impl TokenScript {
    pub(crate) fn requests(&self) -> Vec<BTreeMap<String, String>> {
        self.log.lock().unwrap().clone()
    }

    pub(crate) fn queue(&self, status: u16, body: Value) {
        self.queued.lock().unwrap().push_back((status, body));
    }

    pub(crate) fn hold(&self) -> Hold {
        let hold = Hold {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        *self.hold.lock().unwrap() = Some(hold.clone());
        hold
    }

    pub(crate) fn on_next_request(&self, hook: impl FnOnce() + Send + 'static) {
        *self.hook.lock().unwrap() = Some(Box::new(hook));
    }
}

/// Wall clock plus an offset the test advances.
#[derive(Clone, Default)]
pub(crate) struct FixtureClock(pub(crate) Arc<AtomicU64>);

impl Clock for FixtureClock {
    fn now_unix(&self) -> u64 {
        super::super::provider::SystemClock.now_unix() + self.0.load(Ordering::SeqCst)
    }
}

impl super::RevokeFixture {
    /// `/token` requests with `grant_type=authorization_code`.
    pub(crate) fn exchanges(&self) -> Vec<BTreeMap<String, String>> {
        self.grants("authorization_code")
    }

    pub(crate) fn grants(&self, grant_type: &str) -> Vec<BTreeMap<String, String>> {
        self.token
            .requests()
            .into_iter()
            .filter(|form| form.get("grant_type").map(String::as_str) == Some(grant_type))
            .collect()
    }

    /// Move the custody clock forward (journey deadlines, token expiry).
    pub(crate) fn advance(&self, seconds: u64) {
        self.clock.0.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Fail the grant commit at its checkpoint, before the manifest moves.
    pub(crate) fn fail_next_commit(&self) {
        use super::super::faults::{Boundary, arm_dir};
        arm_dir(&self.config.authority_dir, Boundary::CommitCheckpoint);
    }

    /// Fail the next `journeys.json` directory sync once the exchange is
    /// under way: arming earlier would fire on the consume write (T-R2-1).
    pub(crate) fn fail_journeys_write_after_exchange(&self) {
        let dir = self.config.authority_dir.clone();
        self.token.on_next_request(move || {
            use super::super::faults::{Boundary, arm_dir};
            arm_dir(&dir, Boundary::JourneysParentSync);
        });
    }

    /// Every authority acquisition from now on (the oversize-state row).
    pub(crate) fn watch_store(&self) -> super::super::store_probe::Recording {
        super::super::store_probe::watch(&self.config.store_dir)
    }

    /// The access token a use of `key` would carry, if it is connected.
    pub(crate) async fn access_token(&self, key: &super::AccountKey) -> Option<String> {
        let lease = self.custody.resolve(key).await.ok()?;
        let released = self.custody.release(&lease).await.ok()?;
        Some(released.access_token)
    }

    /// As [`Self::access_token`], through the refresh path (T-REF).
    pub(crate) async fn refreshed_token(&self, key: &super::AccountKey) -> Option<String> {
        let lease = self.custody.refresh_if_expired(key).await.ok()?;
        let released = self.custody.release(&lease).await.ok()?;
        Some(released.access_token)
    }
}

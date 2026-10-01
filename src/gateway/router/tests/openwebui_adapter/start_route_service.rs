// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/journeys/{id}/start`: the pages for a reload that removed
//! the bridge or the account, and for custody that cannot answer.

use super::super::super::super::AppState;
use super::*;
use crate::personal_accounts::config::AccountDescriptor;
use crate::personal_accounts::{
    AccountHandles, AccountKey, CallbackOutcome, CallbackRequest, CustodyError, JourneyCreated,
    JourneyLimits, JourneyResult, JourneyService, JourneyStarted, JourneyView,
};

const UNAVAILABLE: &str = "The account service is unavailable";
const EXPIRED: &str = "This link has expired or is not valid";

/// Custody that is up for `account_of` or down for it; `start` is always down.
struct Busy {
    names_account: bool,
}

#[async_trait::async_trait]
impl JourneyService for Busy {
    async fn create(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        unreachable!("start never creates")
    }

    async fn offer(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        unreachable!("start never offers")
    }

    async fn status(
        &self,
        _: JourneyLimits,
        _: String,
        _: (String, String),
    ) -> JourneyResult<JourneyView> {
        unreachable!("start never reads status")
    }

    async fn account_of(&self, _: JourneyLimits, _: String) -> JourneyResult<String> {
        if self.names_account {
            Ok(Ok(WORK.to_owned()))
        } else {
            Err(CustodyError::Busy)
        }
    }

    async fn start(
        &self,
        _: JourneyLimits,
        _: String,
        _: AccountKey,
    ) -> JourneyResult<JourneyStarted> {
        Err(CustodyError::ShuttingDown)
    }

    async fn callback(&self, _: CallbackRequest) -> CallbackOutcome {
        unreachable!("start never completes a callback")
    }
}

/// The same gateway with its journey half replaced.
fn with_journeys(gw: Gateway, journeys: Arc<dyn JourneyService>) -> Gateway {
    let handles = AccountHandles {
        revocation: gw.fixture.handles().revocation,
        journeys,
    };
    let state: Arc<AppState> = Arc::clone(&gw.state);
    let router = create_router_with_accounts(state, None, Some(handles));
    Gateway { router, ..gw }
}

fn session_cookie() -> String {
    cookie_of(ALICE_TOKEN)
}

/// A reload that removed the `session` block leaves no bridge: the link reads
/// as expired and Open `WebUI` is never asked.
#[tokio::test(flavor = "multi_thread")]
async fn start_without_a_session_adapter_is_the_expired_page() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let mut config = (*gw.state.live_config.get()).clone();
    for adapter in &mut config.accounts.as_mut().unwrap().adapters {
        adapter.session = None;
    }
    gw.state.live_config.set(config);
    // WHEN
    let (status, _, body) = start(&gw, &id, &[&session_cookie()]).await;
    // THEN
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains(EXPIRED), "{body}");
    assert!(owui.seen().is_empty(), "{:?}", owui.seen());
}

/// A journey whose account a reload removed cannot be started: the same
/// expired page, and no authorize redirect.
#[tokio::test(flavor = "multi_thread")]
async fn start_for_an_account_removed_by_reload_is_the_expired_page() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let mut config = (*gw.state.live_config.get()).clone();
    let descriptors = config.accounts.as_mut().unwrap().descriptors.as_mut();
    descriptors.unwrap().remove(WORK);
    gw.state.live_config.set(config);
    // WHEN
    let (status, headers, body) = start(&gw, &id, &[&session_cookie()]).await;
    // THEN
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains(EXPIRED), "{body}");
    assert!(headers.get(header::LOCATION).is_none(), "{headers:?}");
}

/// Custody at its bound when the link is read: 503 before the browser's
/// session is looked at.
#[tokio::test(flavor = "multi_thread")]
async fn start_when_custody_cannot_name_the_account_is_unavailable() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = with_journeys(
        gateway(&owui, 5).await,
        Arc::new(Busy {
            names_account: false,
        }),
    );
    // WHEN
    let (status, _, body) = start(&gw, "j1", &[&session_cookie()]).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains(UNAVAILABLE), "{body}");
    assert!(owui.seen().is_empty(), "{:?}", owui.seen());
}

/// Custody shutting down between naming the account and arming the journey:
/// 503, and no authorize redirect or binding cookie.
#[tokio::test(flavor = "multi_thread")]
async fn start_when_custody_cannot_arm_the_journey_is_unavailable() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = with_journeys(
        gateway(&owui, 5).await,
        Arc::new(Busy { names_account: true }),
    );
    // WHEN
    let (status, headers, body) = start(&gw, "j1", &[&session_cookie()]).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains(UNAVAILABLE), "{body}");
    assert!(headers.get(header::LOCATION).is_none(), "{headers:?}");
    assert!(headers.get(header::SET_COOKIE).is_none(), "{headers:?}");
    assert_eq!(owui.seen().len(), 1);
}

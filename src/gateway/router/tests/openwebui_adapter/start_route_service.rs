// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/journeys/{id}/start`: the pages for a reload that removed
//! the bridge or the account, and for custody that cannot answer.

use super::super::super::super::AppState;
use super::*;
use crate::personal_accounts::config::AccountDescriptor;
use crate::personal_accounts::{
    AccountError, AccountHandles, AccountKey, CallbackOutcome, CallbackRequest, CustodyError,
    JourneyCreated, JourneyError, JourneyLimits, JourneyRefusal, JourneyResult, JourneyService,
    JourneyStarted, JourneyView,
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
        Arc::new(Busy {
            names_account: true,
        }),
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

/// The owner API's answer from custody: down, or one scripted refusal.
#[derive(Clone, Copy)]
enum Owner {
    Down,
    Refused(JourneyError),
}

impl Owner {
    fn answer<T>(self) -> JourneyResult<T> {
        match self {
            Self::Down => Err(CustodyError::Busy),
            Self::Refused(error) => Ok(Err(error)),
        }
    }
}

#[async_trait::async_trait]
impl JourneyService for Owner {
    async fn create(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        self.answer()
    }

    async fn offer(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        unreachable!("the owner API never offers")
    }

    async fn status(
        &self,
        _: JourneyLimits,
        _: String,
        _: (String, String),
    ) -> JourneyResult<JourneyView> {
        self.answer()
    }

    async fn account_of(&self, _: JourneyLimits, _: String) -> JourneyResult<String> {
        unreachable!("the owner API never names an account")
    }

    async fn start(
        &self,
        _: JourneyLimits,
        _: String,
        _: AccountKey,
    ) -> JourneyResult<JourneyStarted> {
        unreachable!("the owner API never starts")
    }

    async fn callback(&self, _: CallbackRequest) -> CallbackOutcome {
        unreachable!("the owner API never completes a callback")
    }
}

/// `POST /accounts/v1/journeys` for `account`, asserted as `subject` when given.
async fn post_journey(
    gw: &Gateway,
    subject: Option<&str>,
    account: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::post("/accounts/v1/journeys")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("content-type", "application/json");
    if let Some(subject) = subject {
        request = request.header("x-openwebui-assertion", assertion(subject));
    }
    let body = json!({"account_id": account, "return_path": "/"}).to_string();
    send(gw, request.body(Body::from(body)).unwrap()).await
}

async fn get_journey(gw: &Gateway, id: &str) -> (StatusCode, HeaderMap, String) {
    let request = Request::get(format!("/accounts/v1/journeys/{id}"))
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(ALICE))
        .body(Body::empty())
        .unwrap();
    send(gw, request).await
}

fn code_of(body: &str) -> String {
    let body: Value = serde_json::from_str(body).unwrap_or_else(|_| panic!("{body}"));
    body["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Mutant: a create refusal swapped for another, or dropped so the call
/// reaches custody it should never reach.
#[tokio::test(flavor = "multi_thread")]
async fn create_refuses_before_custody_and_maps_what_custody_answers() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = with_journeys(gateway(&owui, 5).await, Arc::new(Owner::Down));
    // WHEN / THEN: an API key with no adapter assertion has no principal
    let (status, _, body) = post_journey(&gw, None, WORK).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(code_of(&body), "unauthenticated", "{body}");
    // An account that is not a declared personal_managed descriptor
    let (status, _, body) = post_journey(&gw, Some(ALICE), "undeclared").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), "invalid_request", "{body}");
    // Custody that cannot answer
    let (status, _, body) = post_journey(&gw, Some(ALICE), WORK).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code_of(&body), "storage_unavailable", "{body}");
    // A refusal custody returns is mapped, with its wait
    let limited = JourneyError::Refused(JourneyRefusal::RateLimited { retry_after: 7 });
    let gw = with_journeys(gw, Arc::new(Owner::Refused(limited)));
    let (status, headers, body) = post_journey(&gw, Some(ALICE), WORK).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code_of(&body), "rate_limited", "{body}");
    assert_eq!(headers[header::RETRY_AFTER], "7", "{headers:?}");
}

/// Mutant: a status refusal mapped to the wrong status or code.
#[tokio::test(flavor = "multi_thread")]
async fn status_maps_every_custody_answer_to_its_refusal() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let mut gw = gateway(&owui, 5).await;
    let refused = |refusal| Owner::Refused(JourneyError::Refused(refusal));
    let cases = [
        (
            Owner::Down,
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
        ),
        (
            Owner::Refused(JourneyError::Storage(AccountError::StorageUnavailable)),
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
        ),
        (
            refused(JourneyRefusal::InvalidRequest),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            refused(JourneyRefusal::RateLimited { retry_after: 3 }),
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        ),
        (
            refused(JourneyRefusal::CapacityExceeded { retry_after: 3 }),
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exceeded",
        ),
        (
            refused(JourneyRefusal::OwnerMismatch),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ];
    for (owner, expected, code) in cases {
        gw = with_journeys(gw, Arc::new(owner));
        // WHEN
        let (status, _, body) = get_journey(&gw, "j1").await;
        // THEN
        assert_eq!(status, expected, "{body}");
        assert_eq!(code_of(&body), code, "{body}");
    }
}

/// A reload that removed the accounts block leaves no journey to report: the
/// adapter still vouches for the caller, and the answer is not found.
#[tokio::test(flavor = "multi_thread")]
async fn status_after_a_reload_removed_accounts_is_not_found() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = with_journeys(gateway(&owui, 5).await, Arc::new(Owner::Down));
    let mut config = (*gw.state.live_config.get()).clone();
    config.accounts = None;
    gw.state.live_config.set(config);
    // WHEN
    let (status, _, body) = get_journey(&gw, "j1").await;
    // THEN: before custody, which would have answered 503
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(code_of(&body), "not_found", "{body}");
}

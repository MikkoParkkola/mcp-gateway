// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11 T21: the reconnect OFFER itself, on the meta route.
//!
//! T7-meta proves the refusal reaches `with_connect_offer`, with no offers
//! installed. This cell installs them the way the gateway does
//! (`ConnectOffers` over a journey service and the live config), with a caller
//! from a bridged Open `WebUI` adapter and `accounts.hosted` configured
//! (predicate B, `gateway/router/accounts/offer.rs`). A revoked grant's 401 must
//! then come back as -32001 carrying a `connect_url`.

use std::sync::Arc;

use serde_json::json;

use super::super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Bind, Descriptors, ProviderStep, ROTATED_TOKEN, WORK, account_key_for,
    custody_with_steps, execute, expected_identity_key_for, gateway, grant,
};
use super::super::super::account_rest_fixture::{managed, rest_config};
use crate::config_reload::LiveConfig;
use crate::gateway::router::ConnectOffers;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::config::AccountDescriptor;
use crate::personal_accounts::refusal::offer_data;
use crate::personal_accounts::{
    AccountKey, CallbackOutcome, CallbackRequest, JourneyCreated, JourneyLimits, JourneyResult,
    JourneyService, JourneyStarted, JourneyView,
};

const FRESH: u64 = u64::MAX;
const INSTALLATION: &str = "owui-a11";
const ORIGIN: &str = "https://chat.a11.invalid";
const JOURNEY: &str = "journey-a11-offer";

/// Answers the one call a dispatch-site offer makes; nothing else is reached.
struct OfferingJourneys;

#[async_trait::async_trait]
impl JourneyService for OfferingJourneys {
    async fn create(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        unreachable!("an offer never creates through this entry")
    }

    async fn offer(
        &self,
        _: JourneyLimits,
        _: AccountKey,
        _: AccountDescriptor,
        _: String,
    ) -> JourneyResult<JourneyCreated> {
        Ok(Ok(JourneyCreated {
            journey_id: JOURNEY.to_string(),
            expires_at: u64::MAX,
        }))
    }

    async fn status(
        &self,
        _: JourneyLimits,
        _: String,
        _: (String, String),
    ) -> JourneyResult<JourneyView> {
        unreachable!("not reached by an offer")
    }

    async fn account_of(&self, _: JourneyLimits, _: String) -> JourneyResult<String> {
        unreachable!("not reached by an offer")
    }

    async fn start(
        &self,
        _: JourneyLimits,
        _: String,
        _: AccountKey,
    ) -> JourneyResult<JourneyStarted> {
        unreachable!("not reached by an offer")
    }

    async fn callback(&self, _: CallbackRequest) -> CallbackOutcome {
        unreachable!("not reached by an offer")
    }
}

/// A caller the bridged adapter vouches for: its issuer is the adapter's.
fn bridged_caller() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@a11.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: crate::gateway::openwebui_adapter::adapter_issuer(INSTALLATION),
    }
}

/// The live config offers read: the managed descriptor, one Open `WebUI`
/// adapter with a browser session, and the hosted journey. Built through
/// serde so the adapter and hosted blocks keep their production defaults.
fn offering_config() -> crate::config::Config {
    let mut config = rest_config(&[(WORK, managed(WORK))]);
    let accounts = config
        .accounts
        .take()
        .expect("the fixture declares accounts");
    let mut value = serde_json::to_value(&accounts).expect("accounts serialize");
    value["adapters"] = json!([{
        "kind": "openwebui_signed_header",
        "installation_id": INSTALLATION,
        "header": "X-OpenWebUI-Assertion",
        "issuer": "open-webui",
        "hmac_secret_ref": "env:A11_OFFER_FIXTURE_HMAC",
        "allowed_api_key_names": ["owui"],
        "session": {"user_endpoint": "http://127.0.0.1:9/api/v1/auths/"}
    }]);
    value["hosted"] = json!({"public_origin": ORIGIN, "return_paths": ["/"]});
    config.accounts = Some(serde_json::from_value(value).expect("accounts with offers parse"));
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_route_revoked_grant_401_carries_the_reconnect_offer() {
    let caller = bridged_caller();
    let key = account_key_for(&caller, WORK);
    let custody = custody_with_steps(
        &[(key.clone(), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::InvalidGrant],
    );
    let installed = custody.installed();
    let slots = vec![
        expected_identity_key_for(&key, 1),
        expected_identity_key_for(&key, 2),
    ];
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots,
    );
    let live = Arc::new(LiveConfig::new(offering_config()));
    meta.install_connect_offers(ConnectOffers::new(Arc::new(OfferingJourneys), live));
    dispatches.answer_with(&[401]);

    let error = Box::pin(execute(&meta, "mail", Some(&caller)))
        .await
        .expect_err("a 401 on a revoked grant must refuse with the offer");

    assert_eq!(
        error.to_rpc_code(),
        -32001,
        "the account refusal code: {error}"
    );
    let data = offer_data(&error).expect("a sealed, gateway-built offer");
    assert_eq!(
        data["connect_url"],
        format!("{ORIGIN}/accounts/v1/journeys/{JOURNEY}/start"),
        "{data}"
    );
    assert_eq!(data["error"]["code"], "reconnect_required", "{data}");
    assert_eq!(custody.refreshes(), 1, "exactly one forced refresh");
    assert_eq!(dispatches.count(), 1);
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the personal-account OAuth refresh provider.
//!
//! ACCEPTANCE BOUNDARY. Construction is `PersonalOAuthRefresh::bootstrap(..).await`
//! and it is EAGER: every managed descriptor's issuer metadata is discovered,
//! validated and pinned before the constructor returns. A descriptor whose
//! metadata cannot be accepted refuses the whole bootstrap, so the Gateway
//! cannot reach Serving holding a provider that would discover lazily on some
//! later refresh. Every discovery assertion in this file therefore reads the
//! call trace IMMEDIATELY AFTER the awaited construction, and every refresh
//! assertion then requires that the trace did NOT grow a metadata fetch.
//!
//! WHAT THESE PROVE AND WHAT THEY DO NOT. Every fixture here is an in-process
//! script behind `ProviderHttp`. They prove POLICY -- bootstrap eagerness,
//! discovery order, exact issuer/endpoint binding, which failures may advance
//! to the next candidate, descriptor selection, request composition, response
//! mapping. They prove NOTHING about real TLS, certificate validation, DNS
//! pinning or redirect handling: a `TerminalFailure::Certificate` here is a
//! value a fake returned, not a certificate that was rejected. The real
//! transport is unbuilt and those properties need a live check against the
//! gateway client. See HANDOFF.
//!
//! ONE ORDERED LOG. Metadata GETs, token POSTs and secret resolutions all append
//! to the same `Vec<Call>`, so "the secret was read after the metadata was
//! accepted" is a checkable position and not a comment. Two separate logs cannot
//! answer an ordering question. The log handle is cloned out BEFORE bootstrap is
//! called, because a bootstrap that refuses returns no provider to read it from
//! and the refusal rows are exactly the ones that must show what was attempted.
//!
//! Negative rows carry a POSITIVE anchor -- the call trace showing the fetch
//! they were meant to reach actually happened, and a `ProviderBuildError` variant
//! (`InvalidMetadata`) that a seam refusing unconditionally CANNOT produce.
//! Without both, a provider that refused everything up front would satisfy every
//! negative row and prove nothing, which is the failure mode these rows exist to
//! exclude.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::{
    Clock, GatewayProviderHttp, HttpError, HttpResponse, PersonalOAuthRefresh, ProviderBuildError,
    ProviderHttp, RetrievalFailure, SecretSource, TerminalFailure, discovery_urls,
};
use crate::personal_accounts::config::{AccountDescriptor, DescriptorMode};
use crate::personal_accounts::service::{ProviderRefreshError, RefreshProvider};
use crate::personal_accounts::{AccountKey, GrantRecord};

const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_AUTH: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE: &str = "https://oauth2.googleapis.com/revoke";
const GOOGLE_RFC8414: &str = "https://accounts.google.com/.well-known/oauth-authorization-server";
const GOOGLE_OIDC: &str = "https://accounts.google.com/.well-known/openid-configuration";
const ATTACKER_TOKEN: &str = "https://oauth2.attacker.example/token";

const LOGIN_ISSUER: &str = "https://login.example.com";
const LOGIN_RFC8414: &str = "https://login.example.com/.well-known/oauth-authorization-server";
const LOGIN_TOKEN: &str = "https://login.example.com/token";

const HOSTILE_ISSUER: &str = "https://idp.hostile.example";
const HOSTILE_RFC8414: &str = "https://idp.hostile.example/.well-known/oauth-authorization-server";

const RESOURCE: &str = "https://gateway.example.com/mcp";
const OTHER_RESOURCE: &str = "https://gateway.example.com/other";
const CLIENT_ID: &str = "1234.apps.googleusercontent.com";
const SECRET_REF: &str = "env:GOOGLE_CLIENT_SECRET";
const SECRET_VALUE: &str = "client-secret-value";
const REFRESH_TOKEN: &str = "refresh-token-alpha";
const NOW: u64 = 1_700_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Metadata(String),
    Token {
        url: String,
        form: Vec<(String, String)>,
    },
    Secret(String),
}

#[derive(Clone)]
struct TraceHttp {
    metadata: BTreeMap<String, Result<HttpResponse, HttpError>>,
    token: Result<HttpResponse, HttpError>,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl TraceHttp {
    fn new(
        metadata: Vec<(&str, Result<HttpResponse, HttpError>)>,
        token: Result<HttpResponse, HttpError>,
    ) -> Self {
        Self {
            metadata: metadata
                .into_iter()
                .map(|(url, outcome)| (url.to_string(), outcome))
                .collect(),
            token,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ProviderHttp for TraceHttp {
    fn get_metadata(
        &self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.calls.lock().unwrap().push(Call::Metadata(url.into()));
        // Unscripted location = nothing answers there.
        let outcome = self
            .metadata
            .get(url)
            .cloned()
            .unwrap_or(Err(HttpError::Retryable(RetrievalFailure::Unreachable)));
        async move { outcome }
    }

    fn post_token(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> impl std::future::Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.calls.lock().unwrap().push(Call::Token {
            url: url.into(),
            form: form.to_vec(),
        });
        let outcome = self.token.clone();
        async move { outcome }
    }
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Resolves only the one configured reference, and records the read in the same
/// ordered log as the HTTP calls.
struct MapSecrets {
    calls: Arc<Mutex<Vec<Call>>>,
}

impl SecretSource for MapSecrets {
    fn resolve(&self, reference: &str) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Secret(reference.to_string()));
        (reference == SECRET_REF).then(|| SECRET_VALUE.to_string())
    }
}

/// The single ordered log, held independently of the provider so a REFUSED
/// bootstrap is still inspectable.
#[derive(Clone)]
struct Trace(Arc<Mutex<Vec<Call>>>);

impl Trace {
    fn all(&self) -> Vec<Call> {
        self.0.lock().unwrap().clone()
    }

    fn metadata_calls(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|call| match call {
                Call::Metadata(url) => Some(url),
                _ => None,
            })
            .collect()
    }

    fn token_calls(&self) -> Vec<(String, Vec<(String, String)>)> {
        self.all()
            .into_iter()
            .filter_map(|call| match call {
                Call::Token { url, form } => Some((url, form)),
                _ => None,
            })
            .collect()
    }

    fn secret_reads(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|call| match call {
                Call::Secret(reference) => Some(reference),
                _ => None,
            })
            .collect()
    }
}

fn ok(body: &str) -> Result<HttpResponse, HttpError> {
    Ok(HttpResponse {
        status: 200,
        body: body.to_string(),
    })
}

fn status(code: u16, body: &str) -> Result<HttpResponse, HttpError> {
    Ok(HttpResponse {
        status: code,
        body: body.to_string(),
    })
}

fn metadata_doc(issuer: &str, authorization: &str, token: &str, revocation: &str) -> String {
    format!(
        r#"{{"issuer":"{issuer}","authorization_endpoint":"{authorization}",
            "token_endpoint":"{token}","revocation_endpoint":"{revocation}"}}"#
    )
}

fn google_doc() -> String {
    metadata_doc(GOOGLE_ISSUER, GOOGLE_AUTH, GOOGLE_TOKEN, GOOGLE_REVOKE)
}

fn descriptor_with(
    issuer: &str,
    resource: &str,
    send_resource: bool,
    token_endpoint: &str,
) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_string(),
        resource: Some(resource.to_string()),
        issuer: Some(issuer.to_string()),
        authorization_endpoint: Some(GOOGLE_AUTH.to_string()),
        token_endpoint: Some(token_endpoint.to_string()),
        revocation_endpoint: Some(GOOGLE_REVOKE.to_string()),
        client_id: Some(CLIENT_ID.to_string()),
        client_secret_ref: Some(SECRET_REF.to_string()),
        redirect_uri: Some("https://gateway.example.com/oauth/callback".to_string()),
        scopes: Some(vec![
            "https://www.googleapis.com/auth/drive.readonly".to_string(),
        ]),
        send_resource_parameter: Some(send_resource),
    }
}

fn descriptor(issuer: &str, resource: &str, send_resource: bool) -> AccountDescriptor {
    descriptor_with(issuer, resource, send_resource, GOOGLE_TOKEN)
}

fn account(backend_id: &str, issuer: &str, resource: &str) -> AccountKey {
    AccountKey {
        principal_authority: "open-webui".to_string(),
        principal_subject: "user-7".to_string(),
        backend_id: backend_id.to_string(),
        resource: resource.to_string(),
        oauth_issuer: issuer.to_string(),
    }
}

fn grant() -> GrantRecord {
    GrantRecord {
        generation: "gen-1".to_string(),
        token_revision: 4,
        authorization_epoch: 2,
        descriptor_revision: "rev-1".to_string(),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
        access_token: "expired-access-token".to_string(),
        refresh_token: Some(REFRESH_TOKEN.to_string()),
        token_type: "Bearer".to_string(),
        expires_at: NOW - 60,
        provider_account_id: Some("google-account-9".to_string()),
        client_id: CLIENT_ID.to_string(),
    }
}

type TestProvider = PersonalOAuthRefresh<TraceHttp, FixedClock, MapSecrets>;

/// Awaits bootstrap and hands back the log REGARDLESS of the outcome. The log
/// handle is cloned before the call: a refused bootstrap yields no provider, and
/// the refusal rows are precisely the ones that must assert what was attempted.
async fn bootstrap_rig(
    descriptors: Vec<(&str, AccountDescriptor)>,
    http: TraceHttp,
    now: u64,
) -> (Trace, Result<TestProvider, ProviderBuildError>) {
    let calls = Arc::clone(&http.calls);
    let secrets = MapSecrets {
        calls: Arc::clone(&calls),
    };
    let descriptors = descriptors
        .into_iter()
        .map(|(id, d)| (id.to_string(), d))
        .collect();
    let built = PersonalOAuthRefresh::bootstrap(descriptors, http, FixedClock(now), secrets).await;
    (Trace(calls), built)
}

async fn expect_bootstrap(
    descriptors: Vec<(&str, AccountDescriptor)>,
    http: TraceHttp,
    now: u64,
) -> (Trace, TestProvider) {
    let (trace, built) = bootstrap_rig(descriptors, http, now).await;
    let provider = built.expect("bootstrap accepted every managed descriptor");
    (trace, provider)
}

/// Google reachable at the second location with a valid document.
async fn google_rig(
    token: Result<HttpResponse, HttpError>,
    send_resource: bool,
    now: u64,
) -> (Trace, TestProvider) {
    let http = TraceHttp::new(
        vec![
            (GOOGLE_RFC8414, status(404, "")),
            (GOOGLE_OIDC, ok(&google_doc())),
        ],
        token,
    );
    expect_bootstrap(
        vec![(
            "workspace",
            descriptor(GOOGLE_ISSUER, RESOURCE, send_resource),
        )],
        http,
        now,
    )
    .await
}

fn token_ok(extra: &str) -> Result<HttpResponse, HttpError> {
    ok(&format!(
        r#"{{"access_token":"fresh-access","token_type":"Bearer","expires_in":3600{extra}}}"#
    ))
}

/// AC1 plus the declared unbuilt boundary. An empty descriptor map bootstraps
/// SUCCESSFULLY and touches nothing -- a store-only deployment with
/// `accounts.enabled` true and no managed descriptors must still reach Serving --
/// and an account the provider does not know is refused before anything leaves
/// the process.
///
/// This is the row that cannot be satisfied by a seam that refuses everything:
/// the positive outcome is the assertion.
#[tokio::test]
async fn empty_map_bootstraps_without_http_or_secrets_and_unknown_account_refuses() {
    let (trace, built) = bootstrap_rig(vec![], TraceHttp::new(vec![], status(500, "")), NOW).await;

    let provider = built.expect("an empty descriptor map has nothing to validate");
    assert!(
        trace.all().is_empty(),
        "nothing to discover means no HTTP and no secret read"
    );

    let outcome = provider
        .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
        .await;

    assert_eq!(outcome.err(), Some(ProviderRefreshError::Unavailable));
    assert!(
        trace.all().is_empty(),
        "refused before any metadata, token or secret access"
    );
}

/// AC2 order, asserted at bootstrap. A path-bearing issuer pins all three
/// locations and proves the issuer path survives into each one. The refresh
/// afterwards must add NO metadata fetch: discovery is not a refresh-time act.
#[tokio::test]
async fn bootstrap_tries_rfc8414_then_oidc_prefix_then_oidc_suffix() {
    let issuer = "https://idp.example.com/tenant/a";
    let rfc8414 = "https://idp.example.com/.well-known/oauth-authorization-server/tenant/a";
    let oidc_prefix = "https://idp.example.com/.well-known/openid-configuration/tenant/a";
    let oidc_suffix = "https://idp.example.com/tenant/a/.well-known/openid-configuration";

    assert_eq!(
        discovery_urls(issuer).unwrap(),
        vec![
            rfc8414.to_string(),
            oidc_prefix.to_string(),
            oidc_suffix.to_string()
        ]
    );

    let doc = metadata_doc(issuer, GOOGLE_AUTH, GOOGLE_TOKEN, GOOGLE_REVOKE);
    let http = TraceHttp::new(
        vec![
            (rfc8414, status(404, "")),
            // Second location unreachable: retryable, so the third is tried.
            (
                oidc_prefix,
                Err(HttpError::Retryable(RetrievalFailure::Unreachable)),
            ),
            (oidc_suffix, ok(&doc)),
        ],
        token_ok(""),
    );

    let (trace, provider) = expect_bootstrap(
        vec![("tenant", descriptor(issuer, RESOURCE, true))],
        http,
        NOW,
    )
    .await;

    // Immediately after the awaited constructor, before any refresh exists.
    assert_eq!(
        trace.metadata_calls(),
        vec![
            rfc8414.to_string(),
            oidc_prefix.to_string(),
            oidc_suffix.to_string()
        ],
        "discovery completed during bootstrap, in order"
    );

    assert!(
        provider
            .refresh(&account("tenant", issuer, RESOURCE), &grant())
            .await
            .is_ok()
    );
    assert_eq!(
        trace.metadata_calls().len(),
        3,
        "a refresh triggers no discovery: the snapshot was pinned at bootstrap"
    );
}

/// AC2 positive control. Google's cross-origin token endpoint is accepted on
/// exact metadata binding at BOOTSTRAP, the origin-only issuer produces two
/// locations and not three, metadata GETs carry no credential, no secret is read
/// while building, and the pinned snapshot survives repeated refreshes.
#[tokio::test]
async fn google_cross_origin_endpoints_accepted_at_bootstrap_and_never_refetched() {
    assert_eq!(
        discovery_urls(GOOGLE_ISSUER).unwrap(),
        vec![GOOGLE_RFC8414.to_string(), GOOGLE_OIDC.to_string()],
        "origin-only issuer deduplicates the two identical OIDC locations"
    );

    let (trace, provider) = google_rig(token_ok(""), true, NOW).await;
    let key = account("workspace", GOOGLE_ISSUER, RESOURCE);

    assert_eq!(
        trace.metadata_calls(),
        vec![GOOGLE_RFC8414.to_string(), GOOGLE_OIDC.to_string()],
        "both locations consulted before the constructor returned"
    );
    assert!(
        trace.secret_reads().is_empty(),
        "bootstrap validates metadata; it never touches a client secret"
    );
    assert!(
        trace.token_calls().is_empty(),
        "bootstrap issues no token request"
    );
    for url in trace.metadata_calls() {
        assert!(!url.contains(SECRET_VALUE) && !url.contains(REFRESH_TOKEN));
    }

    let first = provider.refresh(&key, &grant()).await;
    assert!(first.is_ok());
    assert_eq!(
        trace.metadata_calls().len(),
        2,
        "no discovery on refresh, first or otherwise"
    );
    assert_eq!(
        trace.token_calls()[0].0,
        GOOGLE_TOKEN,
        "cross-origin token endpoint accepted on exact metadata binding"
    );

    // Ordering, from the single log: the one secret read sits after the last
    // metadata fetch -- which happened during bootstrap -- and before the token
    // request. Secrets resolve only against already-accepted metadata.
    let calls = trace.all();
    let secret_at = calls
        .iter()
        .position(|call| matches!(call, Call::Secret(_)))
        .expect("secret resolved");
    let last_metadata = calls
        .iter()
        .rposition(|call| matches!(call, Call::Metadata(_)))
        .expect("metadata fetched");
    let token_at = calls
        .iter()
        .position(|call| matches!(call, Call::Token { .. }))
        .expect("token requested");
    assert!(last_metadata < secret_at && secret_at < token_at);
    assert_eq!(trace.secret_reads(), vec![SECRET_REF.to_string()]);

    let second = provider.refresh(&key, &grant()).await;
    assert!(second.is_ok());
    assert_eq!(trace.metadata_calls().len(), 2, "pinned, not re-fetched");
    assert_eq!(trace.token_calls().len(), 2);
}

/// AC3. Bad metadata refuses BOOTSTRAP, so a Gateway holding this provider never
/// reaches Serving. Each row states the fetch it must REACH, then the rejection.
///
/// Two anchors, both required. The reached-fetch trace excludes a provider that
/// refused early without asking anyone; `ProviderBuildError::InvalidMetadata`
/// excludes a seam that refuses unconditionally, because a stub can only produce
/// `RuntimeNotImplemented`.
#[tokio::test]
async fn hostile_or_broken_metadata_refuses_bootstrap_at_its_boundary_without_fallback() {
    let hostile = metadata_doc(GOOGLE_ISSUER, GOOGLE_AUTH, ATTACKER_TOKEN, GOOGLE_REVOKE);
    let wrong_issuer = metadata_doc(
        "https://accounts.attacker.example",
        GOOGLE_AUTH,
        GOOGLE_TOKEN,
        GOOGLE_REVOKE,
    );

    let rows: Vec<(
        &str,
        Vec<(&str, Result<HttpResponse, HttpError>)>,
        Vec<String>,
    )> = vec![
        // Reached the second location, got a document swapping only the token
        // URL. Rejected there; no further location is consulted.
        (
            "attacker token endpoint",
            vec![
                (GOOGLE_RFC8414, status(404, "")),
                (GOOGLE_OIDC, ok(&hostile)),
            ],
            vec![GOOGLE_RFC8414.to_string(), GOOGLE_OIDC.to_string()],
        ),
        // A document that claims another issuer ends discovery at the first
        // location: asking the second would be the attacker fallback.
        (
            "issuer mismatch",
            vec![(GOOGLE_RFC8414, ok(&wrong_issuer))],
            vec![GOOGLE_RFC8414.to_string()],
        ),
        (
            "certificate failure",
            vec![(
                GOOGLE_RFC8414,
                Err(HttpError::Terminal(TerminalFailure::Certificate)),
            )],
            vec![GOOGLE_RFC8414.to_string()],
        ),
        (
            "redirect",
            vec![(
                GOOGLE_RFC8414,
                Err(HttpError::Terminal(TerminalFailure::Redirect)),
            )],
            vec![GOOGLE_RFC8414.to_string()],
        ),
        (
            "ssrf blocked",
            vec![(
                GOOGLE_RFC8414,
                Err(HttpError::Terminal(TerminalFailure::Blocked)),
            )],
            vec![GOOGLE_RFC8414.to_string()],
        ),
        (
            "invalid response",
            vec![(GOOGLE_RFC8414, ok("{ not json"))],
            vec![GOOGLE_RFC8414.to_string()],
        ),
        // Every location exhausted with retryable failures: still a refusal,
        // never a provider that would try again later.
        (
            "no location answers",
            vec![],
            vec![GOOGLE_RFC8414.to_string(), GOOGLE_OIDC.to_string()],
        ),
    ];

    for (label, script, expected_fetches) in rows {
        let (trace, built) = bootstrap_rig(
            vec![("workspace", descriptor(GOOGLE_ISSUER, RESOURCE, true))],
            TraceHttp::new(script, token_ok("")),
            NOW,
        )
        .await;

        assert_eq!(
            trace.metadata_calls(),
            expected_fetches,
            "{label}: intended boundary reached, and no fallback past it"
        );
        assert_eq!(
            built.err(),
            Some(ProviderBuildError::InvalidMetadata),
            "{label}: bootstrap refuses, so Serving cannot start"
        );
        assert!(trace.token_calls().is_empty(), "{label}: no token request");
        assert!(
            trace.secret_reads().is_empty(),
            "{label}: no secret read on untrusted metadata"
        );
    }
}

/// AC3, prevalidation across the whole map. A good descriptor followed by a
/// hostile one refuses the entire bootstrap. Partial acceptance is the lazy
/// behaviour under another name: it would let Serving start on a provider that
/// still had a descriptor left to discover.
#[tokio::test]
async fn one_bad_descriptor_refuses_the_whole_bootstrap() {
    let wrong_issuer = metadata_doc(
        "https://idp.attacker.example",
        GOOGLE_AUTH,
        GOOGLE_TOKEN,
        GOOGLE_REVOKE,
    );
    let http = TraceHttp::new(
        vec![
            (GOOGLE_RFC8414, status(404, "")),
            (GOOGLE_OIDC, ok(&google_doc())),
            (HOSTILE_RFC8414, ok(&wrong_issuer)),
        ],
        token_ok(""),
    );

    // BTreeMap order: `alpha` (valid) is validated before `beta` (hostile).
    let (trace, built) = bootstrap_rig(
        vec![
            ("alpha", descriptor(GOOGLE_ISSUER, RESOURCE, true)),
            ("beta", descriptor(HOSTILE_ISSUER, OTHER_RESOURCE, true)),
        ],
        http,
        NOW,
    )
    .await;

    assert_eq!(
        trace.metadata_calls(),
        vec![
            GOOGLE_RFC8414.to_string(),
            GOOGLE_OIDC.to_string(),
            HOSTILE_RFC8414.to_string(),
        ],
        "the valid descriptor was accepted and the bad one was still reached"
    );
    assert_eq!(
        built.err(),
        Some(ProviderBuildError::InvalidMetadata),
        "one unacceptable descriptor refuses the whole provider"
    );
    assert!(trace.secret_reads().is_empty());
}

/// AC4 selection. Both descriptors are discovered and pinned before bootstrap
/// returns; the descriptor is then chosen by logical id, never joined by
/// provider name, and an account key bound to a different issuer or resource is
/// refused with no further traffic.
#[tokio::test]
async fn all_descriptors_pinned_at_bootstrap_then_selected_by_logical_id_and_bound_exactly() {
    // Two descriptors, same provider name, different issuers AND different token
    // endpoints, so a join onto the wrong one is visible in the token URL rather
    // than passing quietly.
    let login_doc = metadata_doc(LOGIN_ISSUER, GOOGLE_AUTH, LOGIN_TOKEN, GOOGLE_REVOKE);
    let http = TraceHttp::new(
        vec![
            (GOOGLE_RFC8414, status(404, "")),
            (GOOGLE_OIDC, ok(&google_doc())),
            (LOGIN_RFC8414, ok(&login_doc)),
        ],
        token_ok(""),
    );

    // BTreeMap order: `personal` before `workspace`.
    let (trace, provider) = expect_bootstrap(
        vec![
            ("personal", descriptor(GOOGLE_ISSUER, RESOURCE, true)),
            (
                "workspace",
                descriptor_with(LOGIN_ISSUER, OTHER_RESOURCE, true, LOGIN_TOKEN),
            ),
        ],
        http,
        NOW,
    )
    .await;

    assert_eq!(
        trace.metadata_calls(),
        vec![
            GOOGLE_RFC8414.to_string(),
            GOOGLE_OIDC.to_string(),
            LOGIN_RFC8414.to_string(),
        ],
        "every managed descriptor validated before the constructor returned"
    );

    assert!(
        provider
            .refresh(&account("personal", GOOGLE_ISSUER, RESOURCE), &grant())
            .await
            .is_ok(),
        "same provider, different id: the named descriptor is used"
    );
    assert_eq!(
        trace.token_calls()[0].0,
        GOOGLE_TOKEN,
        "the id's own pinned token endpoint, not the sibling's"
    );

    let before = trace.all().len();
    for key in [
        // Issuer belongs to the other descriptor; ids must not be crossed.
        account("personal", LOGIN_ISSUER, RESOURCE),
        account("personal", GOOGLE_ISSUER, OTHER_RESOURCE),
        account("unknown", GOOGLE_ISSUER, RESOURCE),
    ] {
        assert_eq!(
            provider.refresh(&key, &grant()).await.err(),
            Some(ProviderRefreshError::Unavailable)
        );
    }
    assert_eq!(
        trace.all().len(),
        before,
        "every mismatch refused before HTTP or secret access"
    );
}

/// AC4 composition. The request carries the current refresh token, the
/// configured client id and the resolved secret reference; `resource` follows
/// the descriptor's explicit boolean, which is what makes Google's REST
/// behaviour expressible.
#[tokio::test]
async fn token_request_carries_credentials_and_honours_send_resource_parameter() {
    let (with_trace, with_provider) = google_rig(token_ok(""), true, NOW).await;
    assert!(
        with_provider
            .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
            .await
            .is_ok()
    );
    let mut sent = with_trace.token_calls();
    let (url, form) = sent.remove(0);
    assert_eq!(url, GOOGLE_TOKEN);
    assert!(form.contains(&("grant_type".into(), "refresh_token".into())));
    assert!(form.contains(&("refresh_token".into(), REFRESH_TOKEN.into())));
    assert!(form.contains(&("client_id".into(), CLIENT_ID.into())));
    assert!(form.contains(&("client_secret".into(), SECRET_VALUE.into())));
    assert!(form.contains(&("resource".into(), RESOURCE.into())));

    let (without_trace, without_provider) = google_rig(token_ok(""), false, NOW).await;
    assert!(
        without_provider
            .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
            .await
            .is_ok()
    );
    let mut google_sent = without_trace.token_calls();
    let (_, google_form) = google_sent.remove(0);
    assert!(
        !google_form.iter().any(|(key, _)| key == "resource"),
        "explicit false omits the parameter entirely"
    );
}

/// AC5. A full response maps field for field against the pinned clock; a
/// minimal one preserves the provider's omissions as None so the service keeps
/// the stored refresh token and scopes; an unrepresentable expiry refuses.
#[tokio::test]
async fn successful_response_maps_to_token_refresh_and_preserves_omissions() {
    let (_, full) = google_rig(
        token_ok(r#","refresh_token":"rotated-refresh","scope":"drive.readonly gmail.readonly""#),
        true,
        NOW,
    )
    .await;
    let refreshed = full
        .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
        .await
        .expect("mapped");
    assert_eq!(refreshed.access_token, "fresh-access");
    assert_eq!(refreshed.token_type, "Bearer");
    assert_eq!(refreshed.expires_at, NOW + 3600);
    assert_eq!(refreshed.refresh_token.as_deref(), Some("rotated-refresh"));
    assert_eq!(
        refreshed.scopes,
        Some(vec![
            "drive.readonly".to_string(),
            "gmail.readonly".to_string()
        ])
    );

    let (_, minimal) = google_rig(token_ok(""), true, NOW).await;
    let kept = minimal
        .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
        .await
        .expect("mapped");
    assert_eq!(kept.refresh_token, None, "omitted rotation stays omitted");
    assert_eq!(kept.scopes, None, "omitted scope stays omitted");

    // The clock only reaches expiry mapping, so an unrepresentable `now` must
    // not prevent the provider from being built.
    let (_, overflow) = google_rig(token_ok(""), true, u64::MAX).await;
    assert_eq!(
        overflow
            .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
            .await
            .err(),
        Some(ProviderRefreshError::Unavailable),
        "an expiry that cannot be represented is refused, never truncated"
    );
}

/// AC6. `invalid_grant` is the reconnect-required signal and everything else is
/// transient. No response byte reaches the error or its Debug rendering.
#[tokio::test]
async fn invalid_grant_maps_distinctly_and_failures_leak_no_response_bytes() {
    let leaky = format!(
        r#"{{"error":"invalid_grant","error_description":"token {REFRESH_TOKEN} for {SECRET_VALUE}"}}"#
    );
    let rows: Vec<(&str, Result<HttpResponse, HttpError>, ProviderRefreshError)> = vec![
        (
            "invalid_grant",
            status(400, &leaky),
            ProviderRefreshError::InvalidGrant,
        ),
        (
            "other oauth error",
            status(400, r#"{"error":"temporarily_unavailable"}"#),
            ProviderRefreshError::Unavailable,
        ),
        (
            "server error, unparseable body",
            status(500, "<html>upstream</html>"),
            ProviderRefreshError::Unavailable,
        ),
        (
            "malformed success body",
            ok(r#"{"token_type":"Bearer"}"#),
            ProviderRefreshError::Unavailable,
        ),
        (
            "transport failure",
            Err(HttpError::Terminal(TerminalFailure::Certificate)),
            ProviderRefreshError::Unavailable,
        ),
    ];

    for (label, token, expected) in rows {
        // A token-endpoint failure is a REFRESH failure: metadata was already
        // accepted, so bootstrap must have succeeded.
        let (trace, provider) = google_rig(token, true, NOW).await;
        let outcome = provider
            .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
            .await;
        assert_eq!(
            trace.token_calls().len(),
            1,
            "{label}: the request was made"
        );
        let error = outcome.expect_err(label);
        assert_eq!(error, expected, "{label}");
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains(REFRESH_TOKEN) && !rendered.contains(SECRET_VALUE),
            "{label}: no credential in the error"
        );
    }
}

#[path = "provider_tests/pinned_userinfo_tests.rs"]
mod pinned_userinfo_tests;

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Form-shape tests for the consent-journey half of the provider: the authorize
//! URL, the authorization-code exchange and RFC 7009 revocation.
//!
//! Same fixtures as the refresh rows, so the same limits apply: these prove the
//! request each call COMPOSES and the endpoint it is sent to, never the wire.
//! Queries are parsed, not string-compared, and every pinned key is asserted to
//! appear exactly once -- a duplicate `state` or `code_challenge_method` is the
//! defect an appended "extra" parameter would introduce.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

use super::super::grant_flow::{
    AccessType, AuthorizeExtra, Prompt, ProviderRevocation, TokenTypeHint, code_challenge_s256,
    new_code_verifier, new_state,
};
use super::*;

const REDIRECT: &str = "https://gateway.example.com/oauth/callback";
const SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
const STATE: &str = "state-0123456789";
const CHALLENGE: &str = "challenge-abcdef";

fn google_extra() -> AuthorizeExtra {
    AuthorizeExtra {
        access_type: Some(AccessType::Offline),
        prompt: Some(Prompt::Consent),
        include_granted_scopes: None,
    }
}

/// Every query value for `key`, in order.
fn values(url: &url::Url, key: &str) -> Vec<String> {
    url.query_pairs()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .collect()
}

fn one(url: &url::Url, key: &str) -> String {
    let found = values(url, key);
    assert_eq!(found.len(), 1, "`{key}` must appear exactly once in {url}");
    found[0].clone()
}

fn sorted(form: &[(String, String)]) -> Vec<(String, String)> {
    let mut form = form.to_vec();
    form.sort();
    form
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut form: Vec<_> = expected
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    form.sort();
    form
}

/// Google shape: resource withheld, offline access and forced consent. The
/// base is the PINNED endpoint and building the URL touches no transport and
/// reads no secret -- a client secret has no business near a browser URL.
#[tokio::test]
async fn authorize_url_is_the_pinned_endpoint_with_every_pinned_parameter_once() {
    let (trace, provider) = google_rig(token_ok(""), false, NOW).await;
    let before = trace.all().len();

    let url = provider
        .authorize_url("workspace", google_extra(), STATE, CHALLENGE)
        .expect("managed descriptor builds an authorize URL");

    assert_eq!(url.as_str().split('?').next(), Some(GOOGLE_AUTH));
    assert_eq!(one(&url, "response_type"), "code");
    assert_eq!(one(&url, "client_id"), CLIENT_ID);
    assert_eq!(one(&url, "redirect_uri"), REDIRECT);
    assert_eq!(one(&url, "scope"), SCOPE);
    assert_eq!(one(&url, "state"), STATE);
    assert_eq!(one(&url, "code_challenge"), CHALLENGE);
    assert_eq!(one(&url, "code_challenge_method"), "S256");
    assert_eq!(one(&url, "access_type"), "offline");
    assert_eq!(one(&url, "prompt"), "consent");
    assert!(values(&url, "resource").is_empty(), "explicit false omits it");
    assert!(values(&url, "include_granted_scopes").is_empty());
    assert!(!url.as_str().contains(SECRET_VALUE));
    assert_eq!(trace.all().len(), before, "no HTTP and no secret read");
}

/// `resource` follows the descriptor's declared boolean; an undeclared one is
/// refused rather than defaulted. Scopes are space-joined. An empty extra adds
/// nothing, and each remaining closed value renders its wire spelling.
#[tokio::test]
async fn authorize_url_honours_send_resource_parameter_and_the_closed_extras() {
    let mut d = descriptor(GOOGLE_ISSUER, RESOURCE, true);
    d.scopes = Some(vec!["a.read".to_string(), "b.write".to_string()]);
    let mut undeclared = descriptor(LOGIN_ISSUER, RESOURCE, true);
    undeclared.authorization_endpoint = Some("https://login.example.com/authorize".into());
    undeclared.token_endpoint = Some(LOGIN_TOKEN.into());
    undeclared.revocation_endpoint = None;
    undeclared.send_resource_parameter = None;
    let login_doc = format!(
        r#"{{"issuer":"{LOGIN_ISSUER}","authorization_endpoint":"https://login.example.com/authorize","token_endpoint":"{LOGIN_TOKEN}"}}"#
    );
    let http = TraceHttp::new(
        vec![(GOOGLE_RFC8414, ok(&google_doc())), (LOGIN_RFC8414, ok(&login_doc))],
        token_ok(""),
    );
    let (_, provider) = expect_bootstrap(
        vec![("workspace", d), ("login", undeclared)],
        http,
        NOW,
    )
    .await;

    let url = provider
        .authorize_url("workspace", AuthorizeExtra::default(), STATE, CHALLENGE)
        .expect("declared true builds");
    assert_eq!(one(&url, "resource"), RESOURCE);
    assert_eq!(one(&url, "scope"), "a.read b.write");
    for key in ["access_type", "prompt", "include_granted_scopes"] {
        assert!(values(&url, key).is_empty(), "empty extra adds no `{key}`");
    }

    let extra = AuthorizeExtra {
        access_type: Some(AccessType::Online),
        prompt: Some(Prompt::SelectAccount),
        include_granted_scopes: Some(true),
    };
    let url = provider
        .authorize_url("workspace", extra, STATE, CHALLENGE)
        .expect("extras build");
    assert_eq!(one(&url, "access_type"), "online");
    assert_eq!(one(&url, "prompt"), "select_account");
    assert_eq!(one(&url, "include_granted_scopes"), "true");

    assert_eq!(
        provider.authorize_url("login", AuthorizeExtra::default(), STATE, CHALLENGE),
        Err(ProviderRefreshError::Unavailable),
        "undeclared send_resource_parameter is refused, not defaulted"
    );
    assert_eq!(
        provider.authorize_url("other-account", AuthorizeExtra::default(), STATE, CHALLENGE),
        Err(ProviderRefreshError::Unavailable)
    );
}

/// The extras are a closed vocabulary at the parse boundary: an unknown key
/// (including one that would shadow a pinned parameter) or an unknown value
/// is a configuration error, never a pass-through.
#[test]
fn authorize_extra_parses_only_the_closed_vocabulary() {
    let google: AuthorizeExtra =
        serde_json::from_str(r#"{"access_type":"offline","prompt":"consent"}"#).unwrap();
    assert_eq!(google, google_extra());
    let other: AuthorizeExtra =
        serde_json::from_str(r#"{"prompt":"none","include_granted_scopes":false}"#).unwrap();
    assert_eq!(other.prompt, Some(Prompt::None));
    assert_eq!(other.include_granted_scopes, Some(false));

    for hostile in [
        r#"{"access_type":"sometimes"}"#,
        r#"{"prompt":"login"}"#,
        r#"{"state":"attacker"}"#,
        r#"{"code_challenge_method":"plain"}"#,
    ] {
        assert!(
            serde_json::from_str::<AuthorizeExtra>(hostile).is_err(),
            "{hostile} must be rejected"
        );
    }
}

/// 256 bits of state: 43 unpadded URL-safe characters that decode to exactly
/// 32 bytes, fresh per call.
#[test]
fn state_is_256_bits_of_url_safe_randomness() {
    let (a, b) = (new_state(), new_state());
    assert_eq!(a.len(), 43);
    assert_eq!(URL_SAFE_NO_PAD.decode(&a).map(|bytes| bytes.len()), Ok(32));
    assert_ne!(a, b);
}

/// S256 against the RFC 7636 Appendix B vector, and a fresh verifier is a
/// 43-character, 256-bit value whose challenge is its own SHA-256.
#[test]
fn code_challenge_is_s256_and_the_verifier_is_256_bits() {
    assert_eq!(
        code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let (a, b) = (new_code_verifier(), new_code_verifier());
    assert_eq!(a.len(), 43);
    assert_eq!(URL_SAFE_NO_PAD.decode(&a).map(|bytes| bytes.len()), Ok(32));
    assert_ne!(a, b);
    assert_eq!(
        code_challenge_s256(&a),
        URL_SAFE_NO_PAD.encode(Sha256::digest(a.as_bytes()))
    );
}

/// The exchange form is exactly RFC 6749 §4.1.3 plus PKCE and client
/// authentication, sent to the PINNED token endpoint, with the same
/// `redirect_uri` the authorize URL carried. `resource` follows the declared
/// boolean. The secret is read only after the pinned snapshot existed.
#[tokio::test]
async fn exchange_posts_the_authorization_code_form_to_the_pinned_token_endpoint() {
    let issued = token_ok(r#","refresh_token":"fresh-refresh""#);
    let (trace, provider) = google_rig(issued, false, NOW).await;
    let authorize = provider
        .authorize_url("workspace", google_extra(), STATE, CHALLENGE)
        .expect("authorize URL");

    let tokens = provider
        .exchange_code("workspace", "code-xyz", "verifier-abc")
        .await
        .expect("200 maps to tokens");

    assert_eq!(tokens.access_token, "fresh-access");
    assert_eq!(tokens.refresh_token.as_deref(), Some("fresh-refresh"));
    assert_eq!(tokens.expires_at, NOW + 3600);
    let sent = trace.token_calls();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, GOOGLE_TOKEN);
    let redirect = one(&authorize, "redirect_uri");
    assert_eq!(
        sorted(&sent[0].1),
        pairs(&[
            ("grant_type", "authorization_code"),
            ("code", "code-xyz"),
            ("redirect_uri", &redirect),
            ("client_id", CLIENT_ID),
            ("code_verifier", "verifier-abc"),
            ("client_secret", SECRET_VALUE),
        ])
    );
    let calls = trace.all();
    let secret_at = calls.iter().position(|c| matches!(c, Call::Secret(_)));
    let last_metadata = calls.iter().rposition(|c| matches!(c, Call::Metadata(_)));
    assert!(secret_at > last_metadata, "secret read after pinning: {calls:?}");

    let (with_trace, with_provider) = google_rig(token_ok(""), true, NOW).await;
    with_provider
        .exchange_code("workspace", "code-xyz", "verifier-abc")
        .await
        .expect("200 maps to tokens");
    let (_, form) = with_trace.token_calls().remove(0);
    assert!(form.contains(&("resource".into(), RESOURCE.into())));
}

/// Refusals map through the refresh mapping: `invalid_grant` stays distinct,
/// any other failure is `Unavailable`, and an unconfigured account sends
/// nothing.
#[tokio::test]
async fn exchange_refusals_map_like_refresh_and_unconfigured_accounts_send_nothing() {
    let (_, provider) = google_rig(status(400, r#"{"error":"invalid_grant"}"#), false, NOW).await;
    assert_eq!(
        provider.exchange_code("workspace", "c", "v").await,
        Err(ProviderRefreshError::InvalidGrant)
    );
    let (trace, provider) = google_rig(status(503, "upstream detail"), false, NOW).await;
    assert_eq!(
        provider.exchange_code("workspace", "c", "v").await,
        Err(ProviderRefreshError::Unavailable)
    );
    assert_eq!(trace.token_calls().len(), 1, "the refusal came from the POST");
    assert_eq!(
        provider.exchange_code("other-account", "c", "v").await,
        Err(ProviderRefreshError::Unavailable)
    );
    assert_eq!(trace.token_calls().len(), 1, "unconfigured account: no POST");
}

/// RFC 7009 §2.1: the token, its hint and client authentication, POSTed to the
/// PINNED revocation endpoint; 200 is the only confirmation.
#[tokio::test]
async fn revoke_posts_the_rfc7009_form_to_the_pinned_revocation_endpoint() {
    let (trace, provider) = google_rig(ok(""), false, NOW).await;

    let refresh = provider
        .revoke_token("workspace", REFRESH_TOKEN, TokenTypeHint::RefreshToken)
        .await;
    let access = provider
        .revoke_token("workspace", "access-1", TokenTypeHint::AccessToken)
        .await;

    assert_eq!((refresh, access), (ProviderRevocation::Confirmed, ProviderRevocation::Confirmed));
    let sent = trace.token_calls();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0, GOOGLE_REVOKE);
    assert_eq!(
        sorted(&sent[0].1),
        pairs(&[
            ("token", REFRESH_TOKEN),
            ("token_type_hint", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("client_secret", SECRET_VALUE),
        ])
    );
    assert!(sent[1].1.contains(&("token".into(), "access-1".into())));
    assert!(sent[1].1.contains(&("token_type_hint".into(), "access_token".into())));
}

/// Anything but 200, a transport failure, or an account the provider does not
/// manage is `Failed` -- never `Confirmed`.
#[tokio::test]
async fn revoke_reports_failed_for_every_non_confirmation() {
    let outcomes = [
        status(400, r#"{"error":"unsupported_token_type"}"#),
        status(503, ""),
        Err(HttpError::Terminal(TerminalFailure::Unclassified)),
    ];
    for outcome in outcomes {
        let (trace, provider) = google_rig(outcome.clone(), false, NOW).await;
        let revoked = provider
            .revoke_token("workspace", REFRESH_TOKEN, TokenTypeHint::RefreshToken)
            .await;
        assert_eq!(revoked, ProviderRevocation::Failed, "{outcome:?}");
        assert_eq!(trace.token_calls().len(), 1, "{outcome:?} came from the POST");
    }
    let (trace, provider) = google_rig(ok(""), false, NOW).await;
    let revoked = provider
        .revoke_token("other-account", REFRESH_TOKEN, TokenTypeHint::RefreshToken)
        .await;
    assert_eq!(revoked, ProviderRevocation::Failed);
    assert!(trace.token_calls().is_empty());
}

/// A revocation endpoint the operator did not configure was never bound at
/// bootstrap, so even when the metadata advertises one it receives neither the
/// token nor the client secret.
#[tokio::test]
async fn revoke_without_a_configured_endpoint_is_unsupported_and_sends_nothing() {
    let mut d = descriptor(GOOGLE_ISSUER, RESOURCE, false);
    d.revocation_endpoint = None;
    let http = TraceHttp::new(vec![(GOOGLE_RFC8414, ok(&google_doc()))], ok(""));
    let (trace, provider) = expect_bootstrap(vec![("workspace", d)], http, NOW).await;

    let revoked = provider
        .revoke_token("workspace", REFRESH_TOKEN, TokenTypeHint::RefreshToken)
        .await;

    assert_eq!(revoked, ProviderRevocation::Unsupported);
    assert!(trace.token_calls().is_empty());
    assert!(trace.secret_reads().is_empty());
}

/// Custody holds the provider behind an `Arc` so the journey can share the
/// same pinned snapshot; refreshing through the `Arc` is the provider's own
/// refresh, with no second discovery.
#[tokio::test]
async fn an_arc_shared_provider_refreshes_through_the_same_pinned_snapshot() {
    let (trace, provider) = google_rig(token_ok(""), false, NOW).await;
    let fetched = trace.metadata_calls().len();
    let shared = Arc::new(provider);

    let refreshed = RefreshProvider::refresh(
        &shared,
        &account("workspace", GOOGLE_ISSUER, RESOURCE),
        &grant(),
    )
    .await;

    assert_eq!(refreshed.map(|t| t.access_token), Ok("fresh-access".to_string()));
    assert_eq!(trace.token_calls()[0].0, GOOGLE_TOKEN);
    assert_eq!(trace.metadata_calls().len(), fetched);
}

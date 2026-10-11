// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Eager bootstrap: discovery order, issuer and endpoint pinning, and the descriptors that refuse it.

use super::*;

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

    let rows: Vec<(&str, MetadataScript, Vec<String>)> = vec![
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

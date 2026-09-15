// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An endpoint carrying URL userinfo (`https://user:pass@host/..`) must be
//! refused AT BOOTSTRAP, not accepted and then rejected by the real client on
//! the first refresh. Descriptor and metadata AGREE on the tainted string in
//! every negative row, so the refusal cannot come from the exact-equality
//! binding -- it has to come from the endpoint check itself. These are policy
//! and bootstrap proofs, on synthetic fixtures; they say nothing about the wire.

use super::*;

/// `descriptor()` pins authorization and revocation; a row targeting one of
/// those slots edits it here, and the matching metadata is built to agree.
fn taint(slot: Slot, endpoint: &str) -> (AccountDescriptor, String) {
    let mut d = descriptor(GOOGLE_ISSUER, RESOURCE, true);
    let (auth, token, revoke) = match slot {
        Slot::Authorization => (endpoint, GOOGLE_TOKEN, GOOGLE_REVOKE),
        Slot::Token => (GOOGLE_AUTH, endpoint, GOOGLE_REVOKE),
        Slot::Revocation => (GOOGLE_AUTH, GOOGLE_TOKEN, endpoint),
    };
    d.authorization_endpoint = Some(auth.to_string());
    d.token_endpoint = Some(token.to_string());
    d.revocation_endpoint = Some(revoke.to_string());
    (d, metadata_doc(GOOGLE_ISSUER, auth, token, revoke))
}

#[derive(Clone, Copy, Debug)]
enum Slot {
    Authorization,
    Token,
    Revocation,
}

/// Ordinary endpoints still pass, and an `@` that is merely part of a path or
/// query is not userinfo -- a check that rejects on the character rather than
/// on the parsed authority would fail this row.
#[tokio::test]
async fn ordinary_and_at_bearing_paths_still_bootstrap() {
    let rows = [
        ("ordinary", GOOGLE_TOKEN),
        ("at in path", "https://oauth2.googleapis.com/t/a@b/token"),
        ("at in query", "https://oauth2.googleapis.com/token?u=a@b"),
    ];

    for (label, token_endpoint) in rows {
        let (mut d, doc) = taint(Slot::Token, token_endpoint);
        d.token_endpoint = Some(token_endpoint.to_string());

        let (trace, built) = bootstrap_rig(
            vec![("workspace", d)],
            TraceHttp::new(vec![(GOOGLE_RFC8414, ok(&doc))], token_ok("")),
            NOW,
        )
        .await;

        assert!(
            built.is_ok(),
            "{label}: no userinfo present, so nothing to refuse"
        );
        assert_eq!(
            trace.metadata_calls(),
            vec![GOOGLE_RFC8414.to_string()],
            "{label}: accepted at the first location"
        );
    }
}

/// Every negative row is a document the exact-equality binding ACCEPTS: the
/// descriptor was configured with the same tainted string the issuer served.
/// The only thing left to refuse it is the endpoint check, and the refusal has
/// to happen at bootstrap -- an endpoint the real client will not dial is
/// unusable, and a provider holding one is a deferred outage.
#[tokio::test]
async fn userinfo_bearing_endpoint_refuses_bootstrap_even_when_configured() {
    let forms = [
        ("user and password", "https://u:p@oauth2.googleapis.com/x"),
        ("username only", "https://u@oauth2.googleapis.com/x"),
        (
            "empty username with password",
            "https://:p@oauth2.googleapis.com/x",
        ),
    ];
    let slots = [Slot::Authorization, Slot::Token, Slot::Revocation];

    for slot in slots {
        for (form, endpoint) in forms {
            let label = format!("{slot:?} / {form}");
            let (d, doc) = taint(slot, endpoint);

            let (trace, built) = bootstrap_rig(
                vec![("workspace", d)],
                TraceHttp::new(vec![(GOOGLE_RFC8414, ok(&doc))], token_ok("")),
                NOW,
            )
            .await;

            // Positive anchor: the document really was fetched and delivered,
            // so this is a judgement on its content, not a seam refusing early.
            assert_eq!(
                trace.metadata_calls(),
                vec![GOOGLE_RFC8414.to_string()],
                "{label}: metadata delivered, and no fallback past the refusal"
            );
            assert_eq!(
                built.err(),
                Some(ProviderBuildError::InvalidMetadata),
                "{label}: unusable endpoint refuses bootstrap"
            );
            assert!(trace.token_calls().is_empty(), "{label}: no token request");
            assert!(
                trace.secret_reads().is_empty(),
                "{label}: no secret read on refused metadata"
            );
        }
    }
}

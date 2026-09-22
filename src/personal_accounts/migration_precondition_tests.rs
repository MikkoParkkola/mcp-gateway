// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §5.3a and §7.1b — the preconditions, both directions.
//!
//! The refusals here are the ones most likely to be written as a one-sided
//! suite, because each guards a rare shape. So every one is paired with the
//! ordinary install it must NOT refuse: a precondition that refuses everything
//! satisfies the letter of both sections and migrates nothing.

use super::{PreconditionRefusal, check_issuer, recover_client_id};
use crate::personal_accounts::config::{AccountDescriptor, DescriptorMode};

const ISSUER: &str = "https://accounts.google.com";

fn descriptor(client_id: Option<&str>) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_owned(),
        resource: Some("https://www.googleapis.com/drive/v3".to_owned()),
        issuer: Some(ISSUER.to_owned()),
        authorization_endpoint: None,
        token_endpoint: None,
        revocation_endpoint: None,
        client_id: client_id.map(str::to_owned),
        client_secret_ref: None,
        redirect_uri: None,
        scopes: Some(vec!["drive.readonly".to_owned()]),
        send_resource_parameter: Some(true),
        external_strategy: None,
    }
}

// ── §5.3a issuer binding ─────────────────────────────────────────────────────

/// THE POSITIVE CONTROL. An ordinary install migrates: the attestation matches
/// the destination and the record names no contradicting endpoint.
#[test]
fn a_matching_attestation_with_no_recorded_endpoint_passes() {
    assert_eq!(check_issuer(ISSUER, ISSUER, None), Ok(()));
}

/// A record whose endpoint sits on the attested origin passes.
///
/// Origin rather than exact equality is the point: providers host the token
/// endpoint at a path under the issuer, so demanding equality would refuse
/// every real record that carries one.
#[test]
fn a_recorded_endpoint_on_the_attested_origin_passes() {
    assert_eq!(
        check_issuer(
            ISSUER,
            ISSUER,
            Some("https://accounts.google.com/o/oauth2/token")
        ),
        Ok(())
    );
}

/// §5.3a requirement 3 — a credential from another authorization server is
/// REFUSED, not migrated.
///
/// This is the MCP rule the release shipped: a client must not reuse persisted
/// credentials with a different authorization server. `provider.rs` enforces it
/// at refresh time, so migrating across issuers would only produce a grant that
/// is refused on first use.
#[test]
fn an_attestation_naming_another_issuer_is_refused() {
    assert_eq!(
        check_issuer("https://login.microsoftonline.com", ISSUER, None),
        Err(PreconditionRefusal::IssuerMoved {
            attested: "https://login.microsoftonline.com".to_owned(),
            destination: ISSUER.to_owned(),
        })
    );
}

/// §5.3a requirement 2 — the record's own endpoint contradicts the attestation.
///
/// Evidence the FILE supplies, costing one comparison. The operator asserted
/// this credential came from one server; the record says it was issued against
/// another.
#[test]
fn a_recorded_endpoint_on_another_origin_is_refused() {
    let refusal = check_issuer(ISSUER, ISSUER, Some("https://evil.example/token"))
        .expect_err("a contradicting endpoint must refuse");
    assert!(matches!(
        refusal,
        PreconditionRefusal::IssuerContradicted { .. }
    ));
}

/// A different PORT on the same host is a different origin.
///
/// The check compares scheme, host and port; dropping the port would let a
/// credential issued against a development server migrate into a production
/// descriptor.
#[test]
fn a_recorded_endpoint_on_another_port_is_refused() {
    assert!(matches!(
        check_issuer(
            "https://auth.example",
            "https://auth.example",
            Some("https://auth.example:8443/token")
        ),
        Err(PreconditionRefusal::IssuerContradicted { .. })
    ));
}

/// An unparseable endpoint refuses rather than passing by accident.
///
/// A `None` from the parser must not read as "nothing to contradict": that
/// would turn a corrupt field into a silent pass, which is the shape of defect
/// this row keeps finding.
#[test]
fn an_unparseable_recorded_endpoint_is_refused() {
    assert!(matches!(
        check_issuer(ISSUER, ISSUER, Some("not a url")),
        Err(PreconditionRefusal::IssuerContradicted { .. })
    ));
}

// ── §7.1 / §7.1b client id ───────────────────────────────────────────────────

/// THE POSITIVE CONTROL. Config, registration and record all agree.
#[test]
fn an_agreeing_client_id_is_recovered() {
    assert_eq!(
        recover_client_id(
            &descriptor(Some("client-abc")),
            Some("client-abc"),
            Some("client-abc")
        ),
        Ok("client-abc".to_owned())
    );
}

/// §7.1b — a descriptor with no client id is REFUSED.
///
/// The refresh provider reads `descriptor.client_id` and refuses without it, so
/// migrating here produces an account that reads connected and cannot work —
/// and the user is never prompted, because nothing thinks anything is wrong.
#[test]
fn a_descriptor_with_no_client_id_is_refused() {
    assert_eq!(
        recover_client_id(&descriptor(None), Some("client-abc"), Some("client-abc")),
        Err(PreconditionRefusal::DescriptorCannotRefresh)
    );
}

/// §7.1b — the record naming a different client is REFUSED.
///
/// That id names the client the token was actually minted for, and another
/// registered client cannot redeem it.
#[test]
fn a_record_naming_a_different_client_is_refused() {
    assert_eq!(
        recover_client_id(&descriptor(Some("client-abc")), None, Some("client-other")),
        Err(PreconditionRefusal::ClientIdMismatch)
    );
}

/// THE CASE A BLANKET REFUSAL WOULD HAVE BROKEN, and it is a real install.
///
/// Dynamic Client Registration in 3.x leaves a `_client.json`; an operator
/// later sets a `client_id` in config. `restore_persisted_client_id` is a no-op
/// once a configured id is set, and `drop_credentials_from_other_issuer` keeps
/// a configured id across an issuer change because it belongs to the operator
/// rather than to an issuer. So both exist and legitimately differ, and
/// refusing on any disagreement would force the re-authentication this row
/// exists to avoid.
#[test]
fn a_stale_dynamic_registration_does_not_refuse_an_operator_configured_client() {
    assert_eq!(
        recover_client_id(
            &descriptor(Some("client-configured")),
            Some("client-registered-in-3x"),
            None
        ),
        Ok("client-configured".to_owned()),
        "operator config wins over a stale registration; only the RECORD's own \
         id disagreeing is fatal"
    );
}

/// Neither disk source present is fine: the descriptor's id is what the
/// provider will use, and that is what makes the grant refreshable.
#[test]
fn no_disk_sources_at_all_still_recovers_from_config() {
    assert_eq!(
        recover_client_id(&descriptor(Some("client-abc")), None, None),
        Ok("client-abc".to_owned())
    );
}

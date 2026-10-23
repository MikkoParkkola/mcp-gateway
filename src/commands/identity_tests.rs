// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `identity.rs`: the identity-grant CLI handlers and their parsers.

#![allow(
    clippy::disallowed_methods,
    reason = "test code reads the host clock (MIK-8202 AC.14)"
)]
use super::*;
use mcp_gateway::identity_grants::{
    CapabilityExposure, IdentityGrantRequest, LocalIdentityGrantStore,
};

/// MIK-8207: a `--ttl-seconds` too large for a timestamp is refused;
/// it panicked, either building the duration or adding it to now.
#[test]
fn a_ttl_too_large_for_a_timestamp_is_refused() {
    for ttl in [i64::MAX, 10_000_000_000_000] {
        let refused = parse_expiry(None, Some(ttl));
        assert!(refused.is_err(), "{ttl}: {refused:?}");
    }
    assert!(parse_expiry(None, Some(3_600)).expect("an hour").is_some());
}

fn grant_input(path: PathBuf) -> LocalGrantInput {
    LocalGrantInput {
        file: path,
        grant_id: "grant-alice-calendar".to_string(),
        subject: "api_key:alice".to_string(),
        subject_label: Some("Alice".to_string()),
        agent: None,
        any_agent: true,
        capability: "calendar_read_day".to_string(),
        tool: None,
        scope: IdentityGrantScopeArg::Read,
        owner: None,
        owner_label: None,
        expires_at: None,
        ttl_seconds: Some(3600),
        provenance: "test://identity-cli".to_string(),
        reason: "operator-approved test grant".to_string(),
        replace: false,
    }
}

#[tokio::test]
async fn grant_command_creates_file_and_revoke_marks_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity-grants.yaml");

    let (_, grant) = upsert_local_grant(grant_input(path.clone())).await.unwrap();

    assert_eq!(grant.grant_id, "grant-alice-calendar");
    assert_eq!(grant.owner.as_ref(), Some(&grant.subject));
    let file = read_identity_grants_file(&path).await.unwrap();
    assert_eq!(file.grants.len(), 1);
    assert_eq!(file.grants[0].grant_id, "grant-alice-calendar");

    let (_, revoked) =
        revoke_local_grant(&path, "grant-alice-calendar", Some("2026-06-29T14:00:00Z"))
            .await
            .unwrap();

    assert_eq!(
        revoked.revoked_at.map(|timestamp| timestamp.to_rfc3339()),
        Some("2026-06-29T14:00:00+00:00".to_string())
    );
}

/// T1a through the CLI handlers: add, `--replace` and revoke each journal
/// one entry, and a refused duplicate journals nothing (MIK-7570.AUDIT.4).
#[tokio::test]
async fn cli_handlers_journal_every_successful_change() {
    use mcp_gateway::identity_grants::journal::{JournalVerb, journal_path};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity-grants.yaml");

    upsert_local_grant(grant_input(path.clone())).await.unwrap();
    upsert_local_grant(grant_input(path.clone()))
        .await
        .unwrap_err();
    let mut replace = grant_input(path.clone());
    replace.replace = true;
    upsert_local_grant(replace).await.unwrap();
    revoke_local_grant(&path, "grant-alice-calendar", None)
        .await
        .unwrap();

    let journal = std::fs::read_to_string(journal_path(&path)).unwrap_or_default();
    let verbs: Vec<JournalVerb> = journal
        .lines()
        .map(|line| {
            serde_json::from_value(
                serde_json::from_str::<serde_json::Value>(line).unwrap()["verb"].clone(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        verbs,
        vec![JournalVerb::Add, JournalVerb::Replace, JournalVerb::Revoke]
    );
}

#[tokio::test]
async fn grant_command_rejects_duplicate_without_replace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity-grants.json");

    upsert_local_grant(grant_input(path.clone())).await.unwrap();
    let error = upsert_local_grant(grant_input(path)).await.unwrap_err();

    assert!(error.contains("already exists"));
}

/// A built-in authority is one word, so a colon in the subject belongs to
/// the subject: an mTLS SAN URI or an API-key name (#2291).
#[test]
fn subject_parser_keeps_colons_after_a_builtin_authority() {
    let mtls = parse_subject_spec("mtls:spiffe://corp/agent", None, "subject").unwrap();
    assert_eq!(mtls.authority, "mtls");
    assert_eq!(mtls.subject, "spiffe://corp/agent");

    let key = parse_subject_spec("api_key:team:alice", None, "subject").unwrap();
    assert_eq!(key.authority, "api_key");
    assert_eq!(key.subject, "team:alice");

    let agent = parse_subject_spec("agent_oauth:urn:corp:bot", None, "subject").unwrap();
    assert_eq!(agent.authority, "agent_oauth");
    assert_eq!(agent.subject, "urn:corp:bot");
}

#[test]
fn subject_parser_keeps_url_authority() {
    let subject = parse_subject_spec(
        "https://issuer.example:alice-sub",
        Some("Alice".to_string()),
        "subject",
    )
    .unwrap();

    assert_eq!(subject.authority, "https://issuer.example");
    assert_eq!(subject.subject, "alice-sub");
    assert_eq!(subject.label.as_deref(), Some("Alice"));
}

/// `grant_input` is the `docs/identity_grants.md` CLI example. The gateway
/// then sees that caller as an API key named `alice`, labelled with its own
/// name, carrying no proven agent id, calling a read-only capability.
#[tokio::test]
async fn the_documented_grant_command_allows_the_api_key_caller_it_names() {
    let doc = include_str!("../../docs/identity_grants.md");
    for flag in [
        "--subject api_key:alice",
        "--any-agent",
        "--capability calendar_read_day",
        "--scope read",
    ] {
        assert!(doc.contains(flag), "the documented example drifted: {flag}");
    }

    let dir = tempfile::tempdir().unwrap();
    let (_, grant) = upsert_local_grant(grant_input(dir.path().join("grants.yaml")))
        .await
        .unwrap();
    let request = IdentityGrantRequest {
        identity: Some(GrantSubject::new(
            "api_key",
            "alice",
            Some("alice".to_string()),
        )),
        agent_id: None,
        capability: "calendar_read_day".to_string(),
        tool: Some("calendar_read_day".to_string()),
        scope: GrantScope::Read,
        exposure: CapabilityExposure::Personal,
        owner: Some(GrantSubject::new("api_key", "alice", None)),
        now: Utc::now(),
    };

    let evaluation = LocalIdentityGrantStore::from_grants(vec![grant]).evaluate(&request);

    assert!(evaluation.allowed, "{:?}", evaluation.reason);
}

#[test]
fn agent_binding_requires_explicit_exact_or_any() {
    assert!(parse_agent_binding(None, false).is_err());
    assert!(parse_agent_binding(Some("jwt:agent-a".to_string()), true).is_err());
    assert_eq!(parse_agent_binding(None, true).unwrap(), GrantAgent::Any);
}

/// T33: an unqualified `--agent` names both prefixes; a declared label and
/// a DN fragment are refused, since neither is a selected proven id.
#[test]
fn an_unqualified_agent_flag_is_refused_naming_both_prefixes() {
    let error = parse_agent_binding(Some("runner".to_string()), false).unwrap_err();
    assert!(error.contains("mtls:") && error.contains("jwt:"), "{error}");
    for value in ["declared:x", "mtls:CN=x", "jwt:", "mtls:"] {
        assert!(
            parse_agent_binding(Some(value.to_string()), false).is_err(),
            "{value} must be refused"
        );
    }
}

/// C33: the accepted spellings, one per source.
/// Runtime keys a proven id verbatim (#2243), so the CLI writes it as
/// given; trimming would mint a grant for a different principal. Empty and
/// blank ids are still refused (#2284).
#[test]
fn padded_ids_are_written_verbatim() {
    let subject = parse_subject_spec("mtls: admin ", None, "subject").unwrap();
    assert_eq!(subject.subject, " admin ");

    let agent = parse_agent_binding(Some("jwt: runner ".to_string()), false).unwrap();
    let expected = GrantAgentKey {
        source: ProofSource::VerifiedJwtSubject,
        id: " runner ".to_string(),
    };
    assert_eq!(agent, GrantAgent::Exact(expected));

    let owner = parse_subject_spec("jwt: runner", None, "owner").unwrap();
    assert_eq!(owner.subject, " runner");

    let padded_source = parse_agent_binding(Some("  jwt: runner ".to_string()), false);
    let GrantAgent::Exact(key) = padded_source.unwrap() else {
        panic!("an exact agent key");
    };
    assert_eq!(key.id, " runner ");

    assert!(parse_subject_spec("mtls:  ", None, "subject").is_err());
    assert!(parse_agent_binding(Some("jwt:  ".to_string()), false).is_err());
}

/// A grant the CLI writes for `" admin "` survives the file and matches
/// that proven id, not the bare `admin` (#2284).
#[tokio::test]
async fn a_padded_grant_round_trips_to_its_own_principal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let mut input = grant_input(path.clone());
    input.subject = "mtls: admin ".to_string();
    upsert_local_grant(input).await.unwrap();
    let store = mcp_gateway::identity_grants::load_identity_grants_file(&path)
        .await
        .unwrap();

    let allowed = |id: &str| {
        let request = IdentityGrantRequest {
            identity: Some(GrantSubject::new("mtls", id, None)),
            agent_id: None,
            capability: "calendar_read_day".to_string(),
            tool: Some("calendar_read_day".to_string()),
            scope: GrantScope::Read,
            exposure: CapabilityExposure::Personal,
            owner: Some(GrantSubject::new("mtls", id, None)),
            now: Utc::now(),
        };
        store.evaluate(&request).allowed
    };
    assert!(allowed(" admin "));
    assert!(!allowed("admin"));
}

#[test]
fn a_qualified_agent_flag_keys_the_grant_by_source_and_id() {
    for (value, source) in [
        ("jwt:runner", ProofSource::VerifiedJwtSubject),
        ("mtls:runner", ProofSource::MutualTls),
    ] {
        let agent = parse_agent_binding(Some(value.to_string()), false).unwrap();
        let expected = GrantAgentKey {
            source,
            id: "runner".to_string(),
        };
        assert_eq!(agent, GrantAgent::Exact(expected), "{value}");
        assert_eq!(agent_summary(&agent), value);
    }
}

/// F18 I3: the CLI refuses a grants file other users can change, and
/// `upsert` does not overwrite it, because the file exists.
// Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
#[cfg(unix)]
#[tokio::test]
async fn identity_cli_refuses_group_writable_grants() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity-grants.yaml");
    let body = "schema_version: identity_grants.v1\ngrants: []\n";
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    let err = upsert_local_grant(grant_input(path.clone()))
        .await
        .unwrap_err();
    assert!(err.contains("change it"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        body,
        "not overwritten"
    );
}

/// MIK-8667 (lead ruling): a cut table cell fits its column. It used to keep
/// width-1 characters and add `...`, two wider than the column, so a cut row
/// pushed every later column right. One golden row at the table's widths.
#[test]
fn a_cut_identity_cell_fits_its_column() {
    let long = "abcdefghijklmnopqrstuvwxyz0123456789";
    let row = format!(
        "{:<28}|{:<24}|{:<16}|{:<24}|",
        truncate(long, 28),
        truncate(long, 24),
        truncate("short", 16),
        truncate("éééééééééééééééééééééééééé", 24),
    );
    assert_eq!(
        row,
        "abcdefghijklmnopqrstuvwxy...|abcdefghijklmnopqrstu...|short           |ééééééééééééééééééééé...|"
    );
}

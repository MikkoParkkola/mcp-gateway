// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity and local grant administration command handlers.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use chrono::{DateTime, Duration, Utc};
use mcp_gateway::{
    cli::{IdentityCommand, IdentityGrantScopeArg, IdentityGrantsCommand, output::OutputFormat},
    identity_grants::{
        GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile,
        journal, read_identity_grants_file,
    },
    security::ProofSource,
};
use serde_json::json;

/// Run an `identity` subcommand.
pub async fn run_identity_command(cmd: IdentityCommand) -> ExitCode {
    let result = match cmd {
        IdentityCommand::Grants(command) => run_identity_grants_command(command).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_identity_grants_command(command: IdentityGrantsCommand) -> Result<(), String> {
    match command {
        IdentityGrantsCommand::List {
            file,
            active_only,
            format,
        } => list_local_grants(&file, active_only, format).await,
        IdentityGrantsCommand::Grant {
            file,
            grant_id,
            subject,
            subject_label,
            agent,
            any_agent,
            capability,
            tool,
            scope,
            owner,
            owner_label,
            expires_at,
            ttl_seconds,
            provenance,
            reason,
            replace,
            format,
        } => {
            let input = LocalGrantInput {
                file,
                grant_id,
                subject,
                subject_label,
                agent,
                any_agent,
                capability,
                tool,
                scope,
                owner,
                owner_label,
                expires_at,
                ttl_seconds,
                provenance,
                reason,
                replace,
            };
            let (path, grant) = upsert_local_grant(input).await?;
            print_grant_result("granted", &path, &grant, format);
            Ok(())
        }
        IdentityGrantsCommand::Revoke {
            file,
            grant_id,
            revoked_at,
            format,
        } => {
            let (path, grant) = revoke_local_grant(&file, &grant_id, revoked_at.as_deref()).await?;
            print_grant_result("revoked", &path, &grant, format);
            Ok(())
        }
    }
}

async fn list_local_grants(
    file: &Path,
    active_only: bool,
    format: OutputFormat,
) -> Result<(), String> {
    let path = expand_home_path(file);
    let grant_file = read_identity_grants_file(&path).await?;
    let now = super::clock_now()?;
    let grants = grant_file
        .grants
        .into_iter()
        .filter(|grant| !active_only || is_grant_active(grant, now))
        .collect::<Vec<_>>();

    print_grants(&path, &grants, format, now);
    Ok(())
}

struct LocalGrantInput {
    file: PathBuf,
    grant_id: String,
    subject: String,
    subject_label: Option<String>,
    agent: Option<String>,
    any_agent: bool,
    capability: String,
    tool: Option<String>,
    scope: IdentityGrantScopeArg,
    owner: Option<String>,
    owner_label: Option<String>,
    expires_at: Option<String>,
    ttl_seconds: Option<i64>,
    provenance: String,
    reason: String,
    replace: bool,
}

async fn upsert_local_grant(input: LocalGrantInput) -> Result<(PathBuf, IdentityGrant), String> {
    let path = expand_home_path(&input.file);

    let subject = parse_subject_spec(&input.subject, input.subject_label, "subject")?;
    let owner = match input.owner {
        Some(owner) => Some(parse_subject_spec(&owner, input.owner_label, "owner")?),
        None => Some(GrantSubject::new(
            subject.authority.clone(),
            subject.subject.clone(),
            input.owner_label.or_else(|| subject.label.clone()),
        )),
    };
    let grant = IdentityGrant {
        grant_id: non_empty(&input.grant_id, "grant-id")?,
        subject,
        agent: parse_agent_binding(input.agent, input.any_agent)?,
        capability: non_empty(&input.capability, "capability")?,
        tool: trim_optional(input.tool),
        scope: grant_scope(input.scope),
        owner,
        expires_at: parse_expiry(input.expires_at.as_deref(), input.ttl_seconds)?,
        revoked_at: None,
        provenance: non_empty(&input.provenance, "provenance")?,
        reason: non_empty(&input.reason, "reason")?,
    };

    let replace = input.replace;
    let change: journal::GrantChange = Box::new(move |grant_file: &mut IdentityGrantFile| {
        let existing = grant_file
            .grants
            .iter()
            .any(|existing| existing.grant_id == grant.grant_id);
        if existing && !replace {
            return Err(format!(
                "grant id '{}' already exists; pass --replace to overwrite it",
                grant.grant_id
            ));
        }
        grant_file
            .grants
            .retain(|existing| existing.grant_id != grant.grant_id);
        let grant_id = grant.grant_id.clone();
        grant_file.grants.push(grant);
        let verb = if existing {
            journal::JournalVerb::Replace
        } else {
            journal::JournalVerb::Add
        };
        Ok((verb, grant_id))
    });
    let grant = journal::apply_change(&path, true, change)
        .await
        .map_err(|error| error.to_string())?;
    Ok((path, grant))
}

async fn revoke_local_grant(
    file: &Path,
    grant_id: &str,
    revoked_at: Option<&str>,
) -> Result<(PathBuf, IdentityGrant), String> {
    let path = expand_home_path(file);
    let revoked_at = revoked_at.map_or_else(super::clock_now, |value| {
        parse_timestamp(value, "revoked-at")
    })?;
    let grant_id = grant_id.to_string();
    let shown = path.display().to_string();
    let change: journal::GrantChange = Box::new(move |grant_file: &mut IdentityGrantFile| {
        let grant = grant_file
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id == grant_id)
            .ok_or_else(|| format!("grant id '{grant_id}' was not found in {shown}"))?;
        grant.revoked_at = Some(revoked_at);
        Ok((journal::JournalVerb::Revoke, grant_id))
    });
    let updated = journal::apply_change(&path, false, change)
        .await
        .map_err(|error| error.to_string())?;
    Ok((path, updated))
}

fn print_grants(path: &Path, grants: &[IdentityGrant], format: OutputFormat, now: DateTime<Utc>) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": path.display().to_string(),
                "grants": grants
            }))
            .unwrap_or_default()
        ),
        OutputFormat::Plain => {
            for grant in grants {
                println!("{}", grant.grant_id);
            }
        }
        OutputFormat::Table => {
            if grants.is_empty() {
                println!("No identity grants found in {}.", path.display());
                return;
            }
            println!(
                "{:<28}  {:<24}  {:<16}  {:<24}  {:<8}  EXPIRES",
                "GRANT", "SUBJECT", "AGENT", "CAPABILITY", "STATUS"
            );
            println!("{}", "-".repeat(122));
            for grant in grants {
                println!(
                    "{:<28}  {:<24}  {:<16}  {:<24}  {:<8}  {}",
                    truncate(&grant.grant_id, 28),
                    truncate(&subject_summary(&grant.subject), 24),
                    truncate(&agent_summary(&grant.agent), 16),
                    truncate(&grant.capability, 24),
                    grant_status(grant, now),
                    grant
                        .expires_at
                        .map_or_else(|| "never".to_string(), |expires| expires.to_rfc3339())
                );
            }
        }
    }
}

fn print_grant_result(action: &str, path: &Path, grant: &IdentityGrant, format: OutputFormat) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": action,
                "path": path.display().to_string(),
                "grant": grant
            }))
            .unwrap_or_default()
        ),
        OutputFormat::Plain => println!("{}", grant.grant_id),
        OutputFormat::Table => {
            println!("{action}: {}", grant.grant_id);
            println!("file: {}", path.display());
            println!("subject: {}", subject_summary(&grant.subject));
            println!("agent: {}", agent_summary(&grant.agent));
            println!("capability: {}", grant.capability);
            println!("scope: {:?}", grant.scope);
            // Both verbs route through here, and BOTH have this gap: the CLI
            // is a different process from the gateway, so it can only change
            // the file. The ticket only ever named `revoke`, but an `add` that
            // nobody reloads is just as inert.
            println!(
                "note: written to disk and journalled. A running gateway applies this \
                 on its next config reload."
            );
        }
    }
}

fn parse_subject_spec(
    spec: &str,
    label: Option<String>,
    field_name: &str,
) -> Result<GrantSubject, String> {
    // A built-in authority is one word, so the subject after it keeps its
    // colons (an mTLS SAN URI); an issuer URL splits at the last colon (#2291).
    let (authority, subject) = ["api_key", "mtls", "agent_oauth"]
        .into_iter()
        .find_map(|builtin| Some((builtin, spec.strip_prefix(builtin)?.strip_prefix(':')?)))
        .or_else(|| spec.rsplit_once(':'))
        .ok_or_else(|| {
            format!("{field_name} must use AUTHORITY:SUBJECT, for example api_key:alice")
        })?;
    Ok(GrantSubject::new(
        non_empty(authority, field_name)?,
        verbatim_id(subject, field_name)?,
        label.and_then(|label| {
            let trimmed = label.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }),
    ))
}

fn parse_agent_binding(agent: Option<String>, any_agent: bool) -> Result<GrantAgent, String> {
    // Only the leading source prefix may be padded; the id keeps its bytes.
    let agent = agent
        .map(|agent| agent.trim_start().to_string())
        .filter(|agent| !agent.is_empty());
    match (agent, any_agent) {
        (Some(_), true) => Err("--agent and --any-agent are mutually exclusive".to_string()),
        (Some(agent), false) => parse_agent_key(&agent).map(GrantAgent::Exact),
        (None, true) => Ok(GrantAgent::Any),
        (None, false) => Err("pass --agent mtls:<id> | jwt:<id>, or --any-agent".to_string()),
    }
}

/// `mtls:<id>` or `jwt:<id>`. An unqualified id is refused rather than given
/// a default source: a wrong guess grants the other namespace.
fn parse_agent_key(agent: &str) -> Result<GrantAgentKey, String> {
    let (source, id) = match agent.split_once(':') {
        Some(("jwt", id)) => (ProofSource::VerifiedJwtSubject, id),
        Some(("mtls", id)) => (ProofSource::MutualTls, id),
        Some(("declared", _)) => {
            return Err(format!(
                "--agent {agent}: a declared label is not proof and cannot hold a grant; \
                 use mtls:<id> or jwt:<id>"
            ));
        }
        _ => {
            return Err(format!(
                "--agent {agent} must name its proof source: mtls:<SAN URI or bare CN> or \
                 jwt:<client_id>"
            ));
        }
    };
    if id.trim().is_empty() {
        return Err(format!("--agent {agent}: the id after the source is empty"));
    }
    // The selected mTLS id is the first SAN URI, else the bare CN; a DN
    // fragment never matches a caller, so writing one would mint a dead grant.
    if source == ProofSource::MutualTls && id.contains('=') && !id.contains("://") {
        return Err(format!(
            "--agent {agent}: use the SAN URI or the bare CN value, not a DN fragment"
        ));
    }
    Ok(GrantAgentKey {
        source,
        id: id.to_string(),
    })
}

fn parse_expiry(
    expires_at: Option<&str>,
    ttl_seconds: Option<i64>,
) -> Result<Option<DateTime<Utc>>, String> {
    match (expires_at, ttl_seconds) {
        (Some(_), Some(_)) => {
            Err("--expires-at and --ttl-seconds are mutually exclusive".to_string())
        }
        (Some(value), None) => parse_timestamp(value, "expires-at").map(Some),
        (None, Some(seconds)) if seconds <= 0 => {
            Err("--ttl-seconds must be greater than zero".to_string())
        }
        // MIK-8207: both the duration and the sum are checked; either one
        // out of range used to panic.
        (None, Some(seconds)) => {
            let now = super::clock_now()?;
            Duration::try_seconds(seconds)
                .and_then(|ttl| now.checked_add_signed(ttl))
                .map(Some)
                .ok_or_else(|| format!("--ttl-seconds {seconds} is too large"))
        }
        (None, None) => Ok(None),
    }
}

fn parse_timestamp(value: &str, field_name: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| format!("{field_name} must be RFC3339: {error}"))
}

fn grant_scope(scope: IdentityGrantScopeArg) -> GrantScope {
    match scope {
        IdentityGrantScopeArg::Read => GrantScope::Read,
        IdentityGrantScopeArg::Execute => GrantScope::Execute,
        IdentityGrantScopeArg::Any => GrantScope::Any,
    }
}

fn expand_home_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if crate::home_dir::tilde_rest(text).is_none() {
        return path.to_path_buf();
    }
    crate::home_dir::expand_or_cwd(text)
}

fn grant_status(grant: &IdentityGrant, now: DateTime<Utc>) -> &'static str {
    if grant.revoked_at.is_some() {
        "revoked"
    } else if grant.expires_at.is_some_and(|expires_at| expires_at <= now) {
        "expired"
    } else {
        "active"
    }
}

fn is_grant_active(grant: &IdentityGrant, now: DateTime<Utc>) -> bool {
    grant.revoked_at.is_none() && grant.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn subject_summary(subject: &GrantSubject) -> String {
    subject.label.as_ref().map_or_else(
        || format!("{}:{}", subject.authority, subject.subject),
        |label| format!("{label} ({}:{})", subject.authority, subject.subject),
    )
}

fn agent_summary(agent: &GrantAgent) -> String {
    match agent {
        GrantAgent::Any => "any".to_string(),
        GrantAgent::Exact(key) => key.to_string(),
    }
}

fn non_empty(value: &str, field_name: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{field_name} cannot be empty"))
    } else {
        Ok(value.to_string())
    }
}

/// A proven id is keyed verbatim at runtime (#2243), so it is stored as given:
/// trimming `" admin "` would grant the distinct principal `admin` (#2284).
fn verbatim_id(value: &str, field_name: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{field_name} cannot be empty"))
    } else {
        Ok(value.to_string())
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let take = width.saturating_sub(1);
    format!("{}...", value.chars().take(take).collect::<String>())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;

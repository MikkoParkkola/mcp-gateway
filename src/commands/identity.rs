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
        GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile,
        read_identity_grants_file,
    },
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
    let now = Utc::now();
    let grants = grant_file
        .grants
        .into_iter()
        .filter(|grant| !active_only || is_grant_active(grant, now))
        .collect::<Vec<_>>();

    print_grants(&path, &grants, format);
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
    let mut grant_file = read_or_create_grant_file(&path).await?;

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

    let existing = grant_file
        .grants
        .iter()
        .any(|existing| existing.grant_id == grant.grant_id);
    if existing && !input.replace {
        return Err(format!(
            "grant id '{}' already exists; pass --replace to overwrite it",
            grant.grant_id
        ));
    }

    grant_file
        .grants
        .retain(|existing| existing.grant_id != grant.grant_id);
    grant_file.grants.push(grant.clone());
    write_identity_grant_file(&path, &grant_file).await?;
    Ok((path, grant))
}

async fn revoke_local_grant(
    file: &Path,
    grant_id: &str,
    revoked_at: Option<&str>,
) -> Result<(PathBuf, IdentityGrant), String> {
    let path = expand_home_path(file);
    let mut grant_file = read_identity_grants_file(&path).await?;
    let revoked_at = revoked_at.map_or_else(
        || Ok(Utc::now()),
        |value| parse_timestamp(value, "revoked-at"),
    )?;
    let grant = grant_file
        .grants
        .iter_mut()
        .find(|grant| grant.grant_id == grant_id)
        .ok_or_else(|| format!("grant id '{grant_id}' was not found in {}", path.display()))?;

    grant.revoked_at = Some(revoked_at);
    let updated = grant.clone();
    write_identity_grant_file(&path, &grant_file).await?;
    Ok((path, updated))
}

async fn read_or_create_grant_file(path: &Path) -> Result<IdentityGrantFile, String> {
    match read_identity_grants_file(path).await {
        Ok(file) => Ok(file),
        Err(_error) if !path.exists() => Ok(IdentityGrantFile::new(Vec::new())),
        Err(error) => Err(error),
    }
}

async fn write_identity_grant_file(
    path: &Path,
    grant_file: &IdentityGrantFile,
) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            format!(
                "failed to create identity grants directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let content = if is_json_path(path) {
        serde_json::to_string_pretty(grant_file)
            .map_err(|error| format!("failed to serialize identity grants JSON: {error}"))?
    } else {
        serde_yaml::to_string(grant_file)
            .map_err(|error| format!("failed to serialize identity grants YAML: {error}"))?
    };

    tokio::fs::write(path, content).await.map_err(|error| {
        format!(
            "failed to write identity grants file {}: {error}",
            path.display()
        )
    })
}

fn print_grants(path: &Path, grants: &[IdentityGrant], format: OutputFormat) {
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
            let now = Utc::now();
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
        }
    }
}

fn parse_subject_spec(
    spec: &str,
    label: Option<String>,
    field_name: &str,
) -> Result<GrantSubject, String> {
    let (authority, subject) = spec.rsplit_once(':').ok_or_else(|| {
        format!("{field_name} must use AUTHORITY:SUBJECT, for example local:alice")
    })?;
    Ok(GrantSubject::new(
        non_empty(authority, field_name)?,
        non_empty(subject, field_name)?,
        label.and_then(|label| {
            let trimmed = label.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }),
    ))
}

fn parse_agent_binding(agent: Option<String>, any_agent: bool) -> Result<GrantAgent, String> {
    match (trim_optional(agent), any_agent) {
        (Some(_), true) => Err("--agent and --any-agent are mutually exclusive".to_string()),
        (Some(agent), false) => Ok(GrantAgent::Exact(agent)),
        (None, true) => Ok(GrantAgent::Any),
        (None, false) => Err("pass --agent AGENT_ID or --any-agent".to_string()),
    }
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
        (None, Some(seconds)) => Ok(Some(Utc::now() + Duration::seconds(seconds))),
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
        IdentityGrantScopeArg::Write => GrantScope::Write,
        IdentityGrantScopeArg::Execute => GrantScope::Execute,
        IdentityGrantScopeArg::Any => GrantScope::Any,
    }
}

fn expand_home_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    path.to_path_buf()
}

fn is_json_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
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
        GrantAgent::Exact(agent_id) => agent_id.clone(),
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
mod tests {
    use super::*;

    fn grant_input(path: PathBuf) -> LocalGrantInput {
        LocalGrantInput {
            file: path,
            grant_id: "grant-alice-calendar".to_string(),
            subject: "local:alice".to_string(),
            subject_label: Some("Alice".to_string()),
            agent: Some("agent-a".to_string()),
            any_agent: false,
            capability: "personal_calendar".to_string(),
            tool: Some("read_day".to_string()),
            scope: IdentityGrantScopeArg::Read,
            owner: None,
            owner_label: None,
            expires_at: Some("2026-06-29T13:00:00Z".to_string()),
            ttl_seconds: None,
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

    #[tokio::test]
    async fn grant_command_rejects_duplicate_without_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity-grants.json");

        upsert_local_grant(grant_input(path.clone())).await.unwrap();
        let error = upsert_local_grant(grant_input(path)).await.unwrap_err();

        assert!(error.contains("already exists"));
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

    #[test]
    fn agent_binding_requires_explicit_exact_or_any() {
        assert!(parse_agent_binding(None, false).is_err());
        assert!(parse_agent_binding(Some("agent-a".to_string()), true).is_err());
        assert_eq!(
            parse_agent_binding(Some("agent-a".to_string()), false).unwrap(),
            GrantAgent::Exact("agent-a".to_string())
        );
        assert_eq!(parse_agent_binding(None, true).unwrap(), GrantAgent::Any);
    }
}

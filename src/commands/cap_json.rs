// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `cap list`, `cap search`, `cap registry-list`, `cap validate` and `cap test` documents under `--json`
//! (MIK-9764.JSONF.1, design 3a). CLI-owned views with fixed keys: an absent value is null, an empty list `[]`.

use mcp_gateway::capability::CapabilityDefinition;
use mcp_gateway::registry::RegistryEntry;
use serde::Serialize;

/// One `cap list` item: `auth_type` is null exactly when no auth is required, `missing_credential` the text the
/// text form prints after "off: needs".
#[derive(Serialize)]
pub(super) struct ListItem<'a> {
    pub(super) name: &'a str,
    pub(super) description: &'a str,
    pub(super) auth_type: Option<&'a str>,
    pub(super) missing_credential: Option<String>,
}

/// `cap list --json`.
pub(super) fn list(directory: &str, capabilities: Vec<ListItem<'_>>) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        directory: &'a str,
        capabilities: Vec<ListItem<'a>>,
    }
    crate::cli::output::document(&View {
        directory,
        capabilities,
    })
}

#[derive(Serialize)]
struct Indexed<'a> {
    name: &'a str,
    description: &'a str,
    requires_key: bool,
    tags: &'a [String],
}

fn indexed(entry: &RegistryEntry) -> Indexed<'_> {
    Indexed {
        name: &entry.name,
        description: &entry.description,
        requires_key: entry.requires_key,
        tags: &entry.tags,
    }
}

/// `cap search --json`: the query and its hits in rank order.
pub(super) fn search(query: &str, hits: &[&RegistryEntry]) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        query: &'a str,
        capabilities: Vec<Indexed<'a>>,
    }
    crate::cli::output::document(&View {
        query,
        capabilities: hits.iter().map(|entry| indexed(entry)).collect(),
    })
}

/// `cap registry-list --json`: every indexed capability.
pub(super) fn registry_list(entries: &[RegistryEntry]) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        capabilities: Vec<Indexed<'a>>,
    }
    crate::cli::output::document(&View {
        capabilities: entries.iter().map(indexed).collect(),
    })
}

/// `cap validate --json` for a capability that validated: its provider (null without a primary one), its auth
/// (null exactly when none is required) and its warning-severity issues as printed.
pub(super) fn validate(
    cap: &CapabilityDefinition,
    warnings: Vec<String>,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Provider<'a> {
        service: &'a str,
        method: &'a str,
        base_url: &'a str,
        path: &'a str,
    }
    #[derive(Serialize)]
    struct Auth<'a> {
        r#type: &'a str,
        key: &'a str,
    }
    #[derive(Serialize)]
    struct View<'a> {
        name: &'a str,
        description: &'a str,
        provider: Option<Provider<'a>>,
        auth: Option<Auth<'a>>,
        warnings: Vec<String>,
    }
    crate::cli::output::document(&View {
        name: &cap.name,
        description: &cap.description,
        provider: cap.primary_provider().map(|p| Provider {
            service: &p.service,
            method: &p.config.method,
            base_url: &p.config.base_url,
            path: &p.config.path,
        }),
        auth: cap.auth.required.then(|| Auth {
            r#type: &cap.auth.auth_type,
            key: &cap.auth.key,
        }),
        warnings,
    })
}

/// `cap test --json` after a successful call.
pub(super) fn test(
    capability: &str,
    arguments: &serde_json::Value,
    result: &serde_json::Value,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        capability: &'a str,
        arguments: &'a serde_json::Value,
        result: &'a serde_json::Value,
    }
    crate::cli::output::document(&View {
        capability,
        arguments,
        result,
    })
}

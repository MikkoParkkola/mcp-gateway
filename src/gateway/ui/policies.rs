// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/policies`: the Policies screen's read model, computed from
//! the published config's lists (not the compiled policies, which merge
//! entries and lose where each came from). Admin only: it shows every rule
//! and key name.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::guard::Guard;
use crate::config::Config;
use crate::gateway::router::AppState;
use crate::gateway::routes;
use crate::security::policy::{ToolPolicy, ToolPolicyConfig};

/// The policies route.
pub(super) fn policies_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_POLICIES, get(read_policies))
}

pub(super) async fn read_policies(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // One generation for every section: a reload between two reads cannot
    // mix them.
    let generation = state.live_config.generation();
    Json(read_model(generation.config())).into_response()
}

/// The read model for `config`.
pub(super) fn read_model(config: &Config) -> Value {
    json!({
        "tool_policy": tool_policy(&config.security.tool_policy),
        "finding_rules": finding_rules(config),
    })
}

/// The firewall's finding rules; none in a build without the firewall,
/// whose config cannot hold any.
#[cfg(feature = "firewall")]
fn finding_rules(config: &Config) -> Value {
    super::policies_rules::finding_rules(&config.security.firewall.rules)
}

#[cfg(not(feature = "firewall"))]
fn finding_rules(_config: &Config) -> Value {
    Value::Array(Vec::new())
}

/// The tool policy: its switches, the built-in denies and each configured
/// entry, with every deny's coverage by the allow entries.
fn tool_policy(policy: &ToolPolicyConfig) -> Value {
    let allows: Vec<(String, &str)> = policy
        .allow
        .iter()
        .enumerate()
        .map(|(i, e)| (format!("security.tool_policy.allow[{i}]"), e.as_str()))
        .collect();
    let covered = |deny: &str| {
        let (mut full, mut part) = (Vec::new(), Vec::new());
        for (path, allow) in &allows {
            match coverage(deny, allow) {
                Coverage::Full => full.push(path.clone()),
                Coverage::Part => part.push(path.clone()),
                Coverage::None => {}
            }
        }
        (full, part)
    };
    let default_denies: Vec<Value> = ToolPolicyConfig::default_denies()
        .iter()
        .map(|name| {
            let (full, part) = if policy.use_default_deny {
                covered(name)
            } else {
                (Vec::new(), Vec::new())
            };
            json!({
                "name": name,
                "path": "security.tool_policy.use_default_deny",
                "active": policy.use_default_deny,
                "overridden_by": full,
                "partly_overridden_by": part,
            })
        })
        .collect();
    let deny: Vec<Value> = policy
        .deny
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let (full, part) = covered(entry);
            json!({
                "entry": entry,
                "path": format!("security.tool_policy.deny[{i}]"),
                "overridden_by": full,
                "partly_overridden_by": part,
            })
        })
        .collect();
    let allow: Vec<Value> = allows
        .iter()
        .map(|(path, entry)| json!({ "entry": entry, "path": path }))
        .collect();
    json!({
        "enabled": policy.enabled,
        "default_action": policy.default_action,
        "use_default_deny": policy.use_default_deny,
        "default_denies": default_denies,
        "allow": allow,
        "deny": deny,
    })
}

/// How much of a deny entry's pairs an allow entry also matches.
enum Coverage {
    Full,
    Part,
    None,
}

/// Decided over concrete (server, tool) pairs, judged by the real matcher
/// (`ToolPolicy`, one entry at a time), on witnesses built from both
/// entries' literals. Both matchers compare only the tool name and
/// `server:tool` against an exact string or a prefix, so a pair's membership
/// depends only on which literals those two strings equal or start with,
/// and every such class has a witness below.
fn coverage(deny: &str, allow: &str) -> Coverage {
    let (servers, tools) = witnesses(&[deny, allow]);
    let (mut meet, mut uncovered) = (false, false);
    let (deny_m, allow_m) = (single(deny), single(allow));
    for server in &servers {
        for tool in &tools {
            if deny_m.check(server, tool).is_err() {
                if allow_m.check(server, tool).is_err() {
                    meet = true;
                } else {
                    uncovered = true;
                }
            }
        }
    }
    match (meet, uncovered) {
        (true, false) => Coverage::Full,
        (true, true) => Coverage::Part,
        (false, _) => Coverage::None,
    }
}

/// A policy whose only rule denies `entry`.
fn single(entry: &str) -> ToolPolicy {
    ToolPolicy::from_config(&ToolPolicyConfig {
        deny: vec![entry.to_owned()],
        use_default_deny: false,
        log_denied: false,
        ..ToolPolicyConfig::default()
    })
}

/// Candidate servers and tools: each entry's literal, a fresh character
/// after it, every split of it at `:` (left a server, right a tool, each
/// also with the fresh character), and names sharing nothing with any.
fn witnesses(entries: &[&str]) -> (Vec<String>, Vec<String>) {
    const FRESH: &str = "\u{1}";
    let mut servers = vec![format!("{FRESH}s")];
    let mut tools = vec![format!("{FRESH}t")];
    for entry in entries {
        let literal = entry.strip_suffix('*').unwrap_or(entry);
        for name in [literal.to_owned(), format!("{literal}{FRESH}")] {
            servers.push(name.clone());
            tools.push(name);
        }
        for (i, _) in literal.match_indices(':') {
            let (left, right) = (&literal[..i], &literal[i + 1..]);
            for name in [left.to_owned(), format!("{left}{FRESH}")] {
                servers.push(name);
            }
            for name in [right.to_owned(), format!("{right}{FRESH}")] {
                tools.push(name);
            }
        }
    }
    servers.sort();
    servers.dedup();
    tools.sort();
    tools.dedup();
    (servers, tools)
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8298: refuse at load a pattern its section cannot match.
//!
//! Each section matches with its own fixed grammar, and nothing here changes
//! what any matcher accepts (refusal only, never wider):
//! - tool lists (`security.tool_policy`, `auth.api_keys[].allowed_tools` and
//!   `denied_tools`, `key_server.policies[].scopes.tools`): an exact name or a
//!   trailing `prefix*` (`security/policy.rs`, `gateway/auth.rs`,
//!   `key_server/policy.rs`);
//! - backend lists (`auth.api_keys[].backends`,
//!   `key_server.policies[].scopes.backends`): an exact name or `*` alone
//!   (`AuthenticatedClient::can_access_backend`);
//! - agent scopes (`agent_auth.agents[].scopes`): `tools:<backend>:<tool>:<action>`,
//!   backend and tool each an exact name or `*` alone, the action one of
//!   `read`, `write`, `execute` or `*` (`gateway/oauth/scopes.rs`);
//! - backend names, `capabilities.name` included: no `*`.
//!
//! Any other `*` used to load as a literal and match nothing: a deny that
//! denies nothing, or an allow that grants nothing. The refusal says, on one
//! line, what was written, why it matches nothing, and what to write instead.
//! It runs whether or not the section is enabled, so turning a section on can
//! never be the first time its rules are checked.

use super::{Config, Error, Result};

/// Whether a tool list grants or blocks: the safe hint differs. A broader
/// `prefix*` only blocks more on a deny list, but grants more on an allow list.
#[derive(Clone, Copy)]
enum Role {
    Allow,
    Deny,
}

/// What a list can match.
#[derive(Clone, Copy)]
enum Grammar {
    /// An exact tool name or a trailing `prefix*`.
    ToolPrefix(Role),
    /// An exact name or `*` alone; the noun names what the list holds.
    ExactOrStar(&'static str),
}

/// Why `pattern` matches nothing under `grammar`, and what to write instead;
/// `None` when the section can match it.
fn unmatchable(pattern: &str, grammar: Grammar) -> Option<String> {
    let star = pattern.find('*')?;
    match grammar {
        Grammar::ToolPrefix(_) if star + 1 == pattern.len() => None,
        Grammar::ToolPrefix(role) => {
            let prefix = &pattern[..star];
            if prefix.is_empty() {
                return Some(
                    "matches no tool: here '*' works only at the end, so there is no suffix \
                     match. List the exact tool names (suffix patterns work in \
                     routing_profiles, not here)."
                        .to_string(),
                );
            }
            let broader = format!("{prefix}*");
            Some(match role {
                Role::Deny => format!(
                    "matches no tool: here '*' works only at the end. Use {broader:?} (broader: \
                     every tool starting {prefix:?}) or list the exact tool names."
                ),
                Role::Allow => format!(
                    "matches no tool: here '*' works only at the end. List the exact tool names, \
                     or use {broader:?} if every tool starting {prefix:?} may be allowed \
                     (broader)."
                ),
            })
        }
        Grammar::ExactOrStar(_) if pattern == "*" => None,
        Grammar::ExactOrStar(noun) => Some(format!(
            "matches no {noun}: here only exact names or '*' work. List the exact {noun} names, \
             or use \"*\" if every {noun} may be reached."
        )),
    }
}

fn refuse(key: &str, patterns: &[String], grammar: Grammar) -> Result<()> {
    for (i, pattern) in patterns.iter().enumerate() {
        if let Some(why) = unmatchable(pattern, grammar) {
            return Err(Error::ConfigValidation(format!(
                "{key}[{i}] = {pattern:?} {why}"
            )));
        }
    }
    Ok(())
}

/// An agent scope: the `tools:` prefix, backend and tool each exact or `*`
/// alone, and a known action.
fn refuse_agent_scope(key: &str, scope: &str) -> Result<()> {
    let Some(rest) = scope.strip_prefix("tools:") else {
        return Err(Error::ConfigValidation(format!(
            "{key} = {scope:?} grants nothing: an agent scope starts with 'tools:' \
             (\"tools:<backend>:<tool>:<action>\")."
        )));
    };
    let mut parts = rest.splitn(3, ':');
    for noun in ["backend", "tool"] {
        if let Some(segment) = parts.next()
            && let Some(why) = unmatchable(segment, Grammar::ExactOrStar(noun))
        {
            return Err(Error::ConfigValidation(format!(
                "{key} = {scope:?}: segment {segment:?} {why}"
            )));
        }
    }
    if let Some(action) = parts.next()
        && !matches!(action, "read" | "write" | "execute" | "*")
    {
        return Err(Error::ConfigValidation(format!(
            "{key} = {scope:?}: {action:?} is not an action, so the scope grants nothing. \
             Use read, write, execute or '*'."
        )));
    }
    Ok(())
}

impl Config {
    /// Refuse a pattern its section cannot match (MIK-8298).
    pub(super) fn validate_pattern_grammar(&self) -> Result<()> {
        let policy = &self.security.tool_policy;
        refuse(
            "security.tool_policy.allow",
            &policy.allow,
            Grammar::ToolPrefix(Role::Allow),
        )?;
        refuse(
            "security.tool_policy.deny",
            &policy.deny,
            Grammar::ToolPrefix(Role::Deny),
        )?;
        for (i, key) in self.auth.api_keys.iter().enumerate() {
            let at = format!("auth.api_keys[{i}]");
            refuse(
                &format!("{at}.backends"),
                &key.backends,
                Grammar::ExactOrStar("backend"),
            )?;
            if let Some(list) = &key.allowed_tools {
                refuse(
                    &format!("{at}.allowed_tools"),
                    list,
                    Grammar::ToolPrefix(Role::Allow),
                )?;
            }
            if let Some(list) = &key.denied_tools {
                refuse(
                    &format!("{at}.denied_tools"),
                    list,
                    Grammar::ToolPrefix(Role::Deny),
                )?;
            }
        }
        for (i, rule) in self.key_server.policies.iter().enumerate() {
            let at = format!("key_server.policies[{i}].scopes");
            refuse(
                &format!("{at}.backends"),
                &rule.scopes.backends,
                Grammar::ExactOrStar("backend"),
            )?;
            refuse(
                &format!("{at}.tools"),
                &rule.scopes.tools,
                Grammar::ToolPrefix(Role::Allow),
            )?;
        }
        // The capability backend is a backend too: '*' is never in a name.
        let name = &self.capabilities.name;
        if name.contains('*') {
            return Err(Error::ConfigValidation(format!(
                "capabilities.name = {name:?} names a backend, and a backend name may not \
                 contain '*'. Rename it."
            )));
        }
        for (i, agent) in self.agent_auth.agents.iter().enumerate() {
            for (j, scope) in agent.scopes.iter().enumerate() {
                refuse_agent_scope(&format!("agent_auth.agents[{i}].scopes[{j}]"), scope)?;
            }
        }
        Ok(())
    }
}

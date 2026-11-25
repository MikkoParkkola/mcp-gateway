// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/policies`: the Policies screen's read model, computed from
//! the published config's lists (not the compiled policies, which merge
//! entries and lose where each came from). Admin only: it shows every rule
//! and key name.

use std::ops::ControlFlow;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::activity::access::{self, Access};
use super::activity::counts::{COUNT_SCAN_BYTES, Days, Pass, RuleHits, Stopped, count_rule_hits};
use super::activity::{log_paths, stream_read};
use super::guard::Guard;
use crate::config::Config;
use crate::config_reload::Generation;
use crate::gateway::router::AppState;
use crate::gateway::routes;
use crate::security::policy::{ToolPolicy, ToolPolicyConfig};
use crate::security::rule_id::RuleId;

/// The policies route.
pub(super) fn policies_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_POLICIES, get(read_policies))
}

pub(super) async fn read_policies(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let access = caller_access(&generation, &guard);
    let logs = log_paths(&state);
    let served = Arc::clone(&state);
    let reader = access.clone();
    // The log read holds one of Activity's read slots, off the runtime.
    let read = stream_read(&state, move |_| {
        let logs = logs
            .as_ref()
            .map(|(inv, gov)| (inv.as_path(), gov.as_deref()));
        let now = crate::clock::utc_now().map(|t| t.fixed_offset());
        Ok(read_model_with_hits(
            &Sources::of(&served.live_config),
            logs,
            &reader,
            now,
            COUNT_SCAN_BYTES,
            |_| ControlFlow::Continue(()),
        ))
    })
    .await;
    let model = read.unwrap_or_else(|error| {
        tracing::warn!(%error, "the policy hits read did not run");
        let sources = Sources::of(&state.live_config);
        with_hits(read_model(&sources), &sources, &RuleHits::unread(&access))
    });
    Json(model).into_response()
}

/// Whose calls the hits count: the caller's Activity access, as the Activity
/// list applies it, resolved with the request's pinned role mapping. The
/// route admits only a gateway admin, so in practice this is every row; a
/// resolver refusal counts no one's calls.
fn caller_access(generation: &Generation, guard: &Guard) -> Access {
    let mapping = &generation.config().control_plane.role_mapping;
    access::resolve(guard.client.as_ref(), guard.identity.as_ref(), mapping).unwrap_or(
        Access::Scoped {
            owner: None,
            backends: Vec::new(),
        },
    )
}

/// What the read model reads: one published generation (the file's values,
/// and the live fields the gateway applies through it) and the config the
/// process runs (the restart-only fields it enforces). Each is taken once,
/// so a reload between two reads cannot mix them.
pub(super) struct Sources<'a> {
    pub(super) generation: Arc<crate::config_reload::Generation>,
    #[cfg_attr(
        not(feature = "firewall"),
        expect(
            dead_code,
            reason = "only the firewall sections read restart-only fields"
        )
    )]
    pub(super) running: &'a Config,
}

impl<'a> Sources<'a> {
    pub(super) fn of(live: &'a crate::config_reload::LiveConfig) -> Self {
        Self {
            generation: live.generation(),
            running: live.running(),
        }
    }
}

/// One setting: its path, the file's value, the enforced value and whether
/// they differ (the screen says "takes effect after restart").
pub(super) fn setting(path: &str, file: Value, enforced: Value) -> Value {
    let pending = file != enforced;
    setting_pending(path, file, enforced, pending)
}

/// A setting with its pending state given. `read_only` is true unless the
/// save table lists `path`: the table is the one answer to what a save can
/// change, so the read and the save cannot disagree.
pub(super) fn setting_pending(path: &str, file: Value, enforced: Value, pending: bool) -> Value {
    let mut s = serde_json::Map::new();
    s.insert("path".to_owned(), Value::from(path));
    s.insert("file".to_owned(), file);
    s.insert("enforced".to_owned(), enforced);
    s.insert("pending_restart".to_owned(), Value::Bool(pending));
    let read_only = crate::config_reload::ui_fields::FieldId::of(path).is_none();
    s.insert("read_only".to_owned(), Value::Bool(read_only));
    Value::Object(s)
}

/// A switch, `on` when its enforced value is.
pub(super) fn switch(path: &str, file: bool, enforced: bool) -> Value {
    let mut s = setting(path, json!(file), json!(enforced));
    s["on"] = json!(enforced);
    s
}

/// The read model for `sources`.
pub(super) fn read_model(sources: &Sources<'_>) -> Value {
    let config = sources.generation.config();
    let mut model = json!({
        "tool_policy": tool_policy(&config.security.tool_policy),
        "finding_rules": finding_rules(config),
        "tool_limits": tool_limits(),
        "request_checks": request_checks(config),
    });
    for (section, value) in firewall_sections(sources) {
        model[section] = value;
    }
    model
}

/// [`read_model`] with each rule's id, its hits in the last 24 hours and the
/// 24 hours before, and its exception count, counted in `logs` (invocation,
/// governance; `None` when no log is kept) under `access`.
pub(super) fn read_model_with_hits(
    sources: &Sources<'_>,
    logs: Option<(&std::path::Path, Option<&std::path::Path>)>,
    access: &Access,
    now: Result<chrono::DateTime<chrono::FixedOffset>, crate::clock::ClockBeforeEpoch>,
    byte_cap: u64,
    after_pass: impl FnMut(Pass) -> ControlFlow<()>,
) -> Value {
    let hits = match logs {
        Some((invocation, governance)) => {
            count_rule_hits(now, invocation, governance, access, byte_cap, after_pass)
                .unwrap_or_else(|error| {
                    // The rule list is configuration: it is served whatever
                    // happened to the log, with every count unknown.
                    tracing::warn!(%error, "policy hits could not be counted");
                    RuleHits::unread(access)
                })
        }
        None => RuleHits::unread(access),
    };
    with_hits(read_model(sources), sources, &hits)
}

/// `model` with the four members on every rule entry and the `hits` object.
/// The ids come from the policies `sources.generation` compiled, joined by
/// each entry's list and pattern or position; never hashed here.
fn with_hits(mut model: Value, sources: &Sources<'_>, hits: &RuleHits) -> Value {
    let generation = &sources.generation;
    let policy = generation.tool_policy();
    let add = |entry: &mut Value, id: Option<&RuleId>, exceptions: usize| {
        let id = id.map(RuleId::as_str);
        let counts = hits.counts(id);
        entry["rule_id"] = id.into();
        entry["hits_24h"] = counts.map(|(newer, _)| newer).into();
        entry["hits_prev_24h"] = counts.map(|(_, older)| older).into();
        entry["exceptions"] = exceptions.into();
    };
    // A deny's exceptions are the allows that override it, wholly or partly.
    let overriding = |entry: &Value| {
        ["overridden_by", "partly_overridden_by"]
            .iter()
            .map(|list| entry[list].as_array().map_or(0, Vec::len))
            .sum::<usize>()
    };
    let lists = &mut model["tool_policy"];
    for entry in each(&mut lists["deny"]) {
        let id = entry["entry"]
            .as_str()
            .and_then(|p| policy.entry_id("deny", p));
        let exceptions = overriding(entry);
        add(entry, id, exceptions);
    }
    for entry in each(&mut lists["allow"]) {
        let id = entry["entry"]
            .as_str()
            .and_then(|p| policy.entry_id("allow", p));
        add(entry, id, 0);
    }
    for entry in each(&mut lists["default_denies"]) {
        let id = entry["name"]
            .as_str()
            .and_then(|p| policy.entry_id("builtin_deny", p));
        let exceptions = overriding(entry);
        add(entry, id, exceptions);
    }
    #[cfg(feature = "firewall")]
    for (i, entry) in each(&mut model["finding_rules"]).enumerate() {
        let id = generation.firewall_policy().rule_id(i);
        let exceptions = entry["except"].as_array().map_or(0, Vec::len);
        add(entry, id, exceptions);
    }
    let days = hits.days();
    let bound = |at: fn(&Days) -> chrono::DateTime<chrono::FixedOffset>| {
        days.as_ref().map(|d| at(d).to_rfc3339())
    };
    model["hits"] = json!({
        "complete": hits.stop == Some(Stopped::End),
        "stopped": hits.stop.map(Stopped::word),
        "from": bound(|d| d.from),
        "older_to": bound(|d| d.older_to),
        "split": bound(|d| d.split),
        "to": bound(|d| d.to),
        "scope": hits.scope,
    });
    model
}

/// The entries of a list member, none when it is not a list.
fn each(list: &mut Value) -> impl Iterator<Item = &mut Value> {
    list.as_array_mut().into_iter().flatten()
}

/// The scan types, guards, credentials and relay sections: `null` in a
/// build without the firewall, as `finding_rules`.
#[cfg(feature = "firewall")]
fn firewall_sections(sources: &Sources<'_>) -> [(&'static str, Value); 4] {
    super::policies_part2::sections(sources)
}

#[cfg(not(feature = "firewall"))]
fn firewall_sections(_sources: &Sources<'_>) -> [(&'static str, Value); 4] {
    [
        ("scan_types", Value::Null),
        ("guards", Value::Null),
        ("credentials", Value::Null),
        ("relay", Value::Null),
    ]
}

/// The two request checks, as the published generation holds them: the value
/// the config view serves and the request paths read. Both apply live, so the
/// file and the enforced value are one. Under the hardened posture SSRF
/// protection is held on at load whatever the file says; the read says so and
/// marks it read-only, since a save of it would not take effect.
fn request_checks(config: &Config) -> Value {
    let security = &config.security;
    let mut ssrf = switch(
        "security.ssrf_protection",
        security.ssrf_protection,
        security.ssrf_protection,
    );
    if security.posture == crate::security::posture::SecurityPosture::Hardened {
        ssrf["forced_by"] = json!("security.posture");
        ssrf["read_only"] = json!(true);
    }
    json!({
        "sanitize_input": switch(
            "security.sanitize_input",
            security.sanitize_input,
            security.sanitize_input,
        ),
        "ssrf_protection": ssrf,
    })
}

/// The four configured tool limits, in ADR-029's display order ("Tool
/// limits"; on HTTP the key's backend scope runs before the global policy and
/// its tool scope after), each with where it is edited. A list, not a
/// judgement: finding rules are not among them.
fn tool_limits() -> Value {
    json!([
        { "limit": "global", "setting": "security.tool_policy", "edited_on": "policies_screen" },
        {
            "limit": "key",
            "setting": "auth.api_keys[].allowed_tools, auth.api_keys[].denied_tools and the key's backend scope",
            "edited_on": "keys_screen"
        },
        { "limit": "certificate", "setting": "mtls policy", "edited_on": "gateway_yaml" },
        { "limit": "agent", "setting": "OAuth agent scopes", "edited_on": "gateway_yaml" },
    ])
}

/// The firewall's finding rules. A build without the firewall answers
/// `null`, not `[]`: its config cannot hold rules, and an empty list would
/// read as "the firewall is built and no rule is configured".
#[cfg(feature = "firewall")]
fn finding_rules(config: &Config) -> Value {
    super::policies_rules::finding_rules(
        &config.security.firewall.rules,
        &crate::security::firewall::RuleKeys::of(config),
    )
}

#[cfg(not(feature = "firewall"))]
fn finding_rules(_config: &Config) -> Value {
    Value::Null
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
    // The three values the save can change, as setting objects with their
    // save paths; all apply live, so file and enforced come from one config.
    json!({
        "enabled": switch("security.tool_policy.enabled", policy.enabled, policy.enabled),
        "default_action": setting(
            "security.tool_policy.default_action",
            json!(policy.default_action),
            json!(policy.default_action),
        ),
        "use_default_deny": switch(
            "security.tool_policy.use_default_deny",
            policy.use_default_deny,
            policy.use_default_deny,
        ),
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

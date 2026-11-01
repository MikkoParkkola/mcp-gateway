// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The key-by-policy barrier (ADR-029, amended, item 1): a request is judged
//! by the one generation pinned on it, so it never combines one generation's
//! key scope with another's tool policy.
//!
//! Each row pins one configuration, then publishes the other the moment the
//! pin is taken (`seams::after_pin`), before authentication runs: every layer
//! after the pin sees the other configuration as current. The answer must
//! equal the one where the pinned configuration is also current. The two
//! configurations each refuse the call, and either mix admits it.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_firewalled_with, post_direct, post_meta_invoke,
};
use crate::config::Config;
use crate::gateway::meta_mcp::visible::seams;

/// The key's scope admits `read` and the tool policy denies it.
fn key_admits_policy_denies(c: &mut Config) {
    key_std(c).denied_tools = None;
    c.security.tool_policy.enabled = true;
    c.security.tool_policy.deny = vec!["alpha:read".to_string()];
}

/// The key's scope denies `read` and the tool policy admits it.
fn key_denies_policy_admits(c: &mut Config) {
    key_std(c).denied_tools = Some(vec!["read".to_string()]);
    c.security.tool_policy.enabled = true;
    c.security.tool_policy.deny.clear();
}

fn key_std(c: &mut Config) -> &mut crate::config::ApiKeyConfig {
    c.auth
        .api_keys
        .iter_mut()
        .find(|k| k.name == "k-std")
        .expect("the fixture's k-std key")
}

fn configured(fx: &Fx, edit: fn(&mut Config)) -> Config {
    let mut config = (*fx.state.live_config.get()).clone();
    edit(&mut config);
    config
}

/// What a call answered: whether it was refused, its refusal text, and how
/// many backend calls it made.
#[derive(Debug, PartialEq)]
struct Outcome {
    refused: bool,
    message: Value,
    calls: usize,
}

fn outcome(body: &Value, calls: usize) -> Outcome {
    let refused = body.get("error").is_some()
        || body.pointer("/result/isError").and_then(Value::as_bool) == Some(true);
    let message = body
        .pointer("/error/message")
        .or_else(|| body.pointer("/result/content/0/text"))
        .cloned()
        .unwrap_or(Value::Null);
    Outcome {
        refused,
        message,
        calls,
    }
}

/// Which route a row calls `alpha:read` through.
#[derive(Clone, Copy, Debug)]
enum Route {
    Direct,
    MetaInvoke,
}

/// Call `alpha:read` as `k-std` with `pinned` current at arrival and
/// `current` published once the pin is taken.
async fn call(fx: &Fx, route: Route, pinned: &Config, current: &Config) -> Outcome {
    fx.state.live_config.set(pinned.clone());
    let fired = Rc::new(Cell::new(false));
    let (live, next, flag) = (
        std::sync::Arc::clone(&fx.state.live_config),
        current.clone(),
        Rc::clone(&fired),
    );
    seams::after_pin(move || {
        live.set(next);
        flag.set(true);
    });
    let before = fx.calls.load(Ordering::SeqCst);
    let args = json!({"cmd": "x"});
    let (_, body) = match route {
        Route::Direct => post_direct(fx, "alpha", "k-std", "read", args, None, None).await,
        Route::MetaInvoke => post_meta_invoke(fx, "k-std", "alpha", "read", args, None, None).await,
    };
    assert!(fired.get(), "the reload published after the pin");
    outcome(&body, fx.calls.load(Ordering::SeqCst) - before)
}

/// The barrier on one route: each complete configuration refuses, and a
/// request pinned to one while the other is current answers as its own.
async fn barrier(route: Route) {
    let fx = fixture_firewalled_with(Answer::Ok, None, false).await;
    let a = configured(&fx, key_admits_policy_denies);
    let b = configured(&fx, key_denies_policy_admits);
    let under_a = call(&fx, route, &a, &a).await;
    let under_b = call(&fx, route, &b, &b).await;
    assert!(
        under_a.refused && under_a.calls == 0,
        "premise, {route:?}: {under_a:?}"
    );
    assert!(
        under_b.refused && under_b.calls == 0,
        "premise, {route:?}: {under_b:?}"
    );
    assert_eq!(
        call(&fx, route, &a, &b).await,
        under_a,
        "{route:?}: pinned key-admits/policy-denies, current the reverse"
    );
    assert_eq!(
        call(&fx, route, &b, &a).await,
        under_b,
        "{route:?}: pinned key-denies/policy-admits, current the reverse"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_barrier_holds_on_gateway_invoke() {
    barrier(Route::MetaInvoke).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_barrier_holds_on_the_direct_route() {
    barrier(Route::Direct).await;
}

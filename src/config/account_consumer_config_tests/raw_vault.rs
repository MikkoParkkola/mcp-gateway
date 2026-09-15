// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Raw `identity_propagation.strategy: vault` with NO `account` reference.
//!
//! ROOT, CONFIRMED. `account_bindings::compile` iterates `backends[*].account`
//! and `continue`s past a backend that declares none, so a hand-written `vault`
//! propagation block is never seen by the account compiler; and
//! `IdentityPropagationConfig::validate` now lists `Vault` among the implemented
//! kinds (it joined when managed custody became the strategy behind it). The two
//! together let a descriptorless `vault` backend LOAD, after which the resolver
//! sees `account_bound == false` and borrows the unrelated process-wide
//! signed-assertion strategy.
//!
//! CONTRACT: `vault` is the COMPILATION TARGET of a `personal_managed`
//! descriptor. An operator cannot write it directly, because there is no account
//! to take custody of — the refusal belongs at load, for BOTH `required: true`
//! and `required: false`.
//!
//! This module evaluates real `Config::load_evaluated` through the existing
//! `evaluate` helper. Nothing here touches a personal store: the declared
//! descriptor is the existing unrelated `shared` one, which `compile` returns
//! `(None, None)` for. Semantic RED.

use super::*;

/// One transport, one audience, one session mode for the control and both
/// negatives, so the only field that differs is `strategy` (and `required`).
const AUDIENCE: &str = "https://vaultless.example.invalid/";

fn propagation_backend(strategy: &str, required: bool) -> String {
    format!(
        "backends:\n  vaultless-backend:\n    \
         http_url: https://vaultless.example.invalid/mcp\n    \
         identity_propagation:\n      \
         strategy: {strategy}\n      \
         audience: {AUDIENCE}\n      \
         session_mode: stateless\n      \
         required: {required}\n"
    )
}

/// CONTRACT: a raw `vault` propagation block with no `account` is refused at
/// load, `required` either way. CURRENT CODE: it loads, and dispatch then falls
/// back to the global signed-assertion strategy. Semantic RED.
///
/// FALSIFIER / OVER-RESTRICTION GUARD: the `signed_assertion` control runs
/// FIRST on the SAME transport, audience and session mode. If a vendor refused
/// this whole shape — or if the fixture were malformed, missing its accounts
/// block, or its directories unwritable — the control fails and the negatives
/// below are never credited.
#[test]
fn raw_vault_strategy_without_account_must_refuse_load() {
    let root = tempfile::TempDir::new().unwrap();
    // An ordinary unrelated `shared` descriptor: declared so the accounts block
    // is a real one, never referenced, and never opening a personal store.
    let descriptors = shared_descriptor("team-bot", "slack");

    // POSITIVE CONTROL FIRST.
    evaluate(
        root.path(),
        18731,
        &descriptors,
        &propagation_backend("signed_assertion", true),
    )
    .expect("an existing signed_assertion backend on this exact shape must keep loading");

    for (port, required) in [(18732, true), (18733, false)] {
        let text = refusal_text(
            evaluate(
                root.path(),
                port,
                &descriptors,
                &propagation_backend("vault", required),
            ),
            &format!("a raw vault propagation block with no account (required: {required})"),
        );
        let lowered = text.to_lowercase();
        assert!(
            lowered.contains("vault"),
            "refusal must name the strategy the operator wrote (required: {required}): {text}"
        );
        assert!(
            lowered.contains("account"),
            "refusal must say vault is reached through an account descriptor, so the operator \
             knows what to write instead (required: {required}): {text}"
        );
        assert!(
            text.contains("vaultless-backend"),
            "refusal must name the offending backend (required: {required}): {text}"
        );
    }
}

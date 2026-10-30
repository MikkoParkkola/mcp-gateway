// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the closed stage table and its dependency allowlists.

/// How a stage takes the orchestrator-owned values it may touch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ExtraKind {
    /// `&mut` to the refund witness; matched on the `Witnessed` tail.
    Witness,
    /// `&mut Option` to the idempotency reservation.
    Reservation,
}

/// One row of the closed B1 table: where the stage lives and what it may use.
pub(super) struct StageSpec {
    pub(super) file: &'static str,
    pub(super) func: &'static str,
    pub(super) input: &'static str,
    pub(super) extra: &'static [ExtraKind],
    pub(super) allow: &'static [&'static str],
}

/// The groups B1 knows, each with its exhaustive field set.
pub(super) const GROUPS: &[(&str, &[&str])] = &[("Step", &["server", "tool"])];

/// Names the collectors never flag, with why each is inert.
/// Option and result constructors appear in every stage's exits.
/// Control-flow and ordering paths are the dispatch match and the epoch load.
/// Macro names are never collected as calls; listing them makes that explicit.
/// Listing `warn` and `json` here does NOT mean calls nested in their arguments are checked.
pub(super) const STD_OK: &[&str] = &[
    "Some",
    "None",
    "Ok",
    "Err",
    "Option",
    "Result",
    "ControlFlow",
    "Continue",
    "Break",
    "ControlFlow::Continue",
    "ControlFlow::Break",
    "std::ops::ControlFlow::Continue",
    "std::ops::ControlFlow::Break",
    "Ordering",
    "Ordering::Acquire",
    "format",
    "vec",
    "warn",
    "json",
    "debug",
    "info",
];

// Line references below cite invoke.rs at acf56382d, before the stages
// moved out of it (MIK-8488 PR-B1).

/// S1 `intake`, from invoke.rs:136-157.
pub(super) const S1_INTAKE_ALLOW: &[&str] = &[
    "self.hint_surface",         // invoke.rs:143
    "self.policy_epoch",         // invoke.rs:148
    "self.gated",                // invoke.rs:155
    "CallerProof::new",          // invoke.rs:139
    "support::credential_owner", // invoke.rs:141 canonical: `super::` stripped for the move
    "gateway_writes::mark",      // invoke.rs:151
    "extract_required_str",      // invoke.rs:153
    "TracedOutcome::Live", // invoke.rs:156 the gate answer mapping; the stage exit keeps this shape in the live body
];

/// S2 `directives`, now `invoke/intake.rs` `directives` (it was invoke.rs:159-199
/// at acf56382d); the line references in this block cite intake.rs (MIK-8663).
pub(super) const S2_DIRECTIVES_ALLOW: &[&str] = &[
    "parse_tool_arguments",                     // intake.rs:147
    "admission::execution_arguments",           // intake.rs:161 the shared directive strip
    "extract_client_claim",                     // intake.rs:158 read before the strip
    "crate::projection::projection_key_suffix", // intake.rs:174
    "self.projection_mode",                     // intake.rs:174
    "tracing::Span::current",                   // intake.rs:176 the span record stays in S2
    "self.active_profile",                      // intake.rs:178
];

/// S3 `resolve`, from invoke.rs:214-252.
/// The witness take at :214 stays in the orchestrator per r11, so it is absent here.
pub(super) const S3_RESOLVE_ALLOW: &[&str] = &[
    "self.dispatch_resolution",       // invoke.rs:217
    "self.scoped",                    // invoke.rs:218
    "self.admit_after_credential",    // invoke.rs:242
    "self.lift_deferred",             // invoke.rs:245
    "self.refuse_name_clash",         // resolve.rs: a backend and the capability share the name
    "nonce_settle::ask_if_transient", // invoke.rs:232
    "rw::dispatch_effect",            // invoke.rs:238
    "TracedOutcome::Live",            // invoke.rs:227 the Break exit; listed from the live body
    "TracedOutcome::Stored", // invoke.rs:248 the lift replay exit; listed from the live body
];

/// S4 `admit_keys`, from invoke.rs:253-322.
pub(super) const S4_ADMIT_KEYS_ALLOW: &[&str] = &[
    "support::caller_cache_principal", // invoke.rs:266 canonical: `super::` stripped for the move
    "idempotency_key_for",             // invoke.rs:278
    "support::step_scoped",            // invoke.rs:280 canonical: `super::` stripped for the move
    "self.idempotency_cache",          // invoke.rs:282
    "derive_key",                      // invoke.rs:296
    "self.admit_idempotency_key",      // invoke.rs:305
    "nonce_settle::settle_pre_send",   // invoke.rs:316
    "nonce_settle::PreSendExit::Served", // invoke.rs:318 the Served constructor nested in the mapping call
    "stored_proof::refuse_unproven",     // invoke.rs:322
    "TracedOutcome::Live", // invoke.rs:320 the stored-hit exit; listed from the live body
];

/// S5 `pre_send`, from invoke.rs:324-397.
/// The `fills` closure at :335 is a local, so its calls need no entry.
pub(super) const S5_PRE_SEND_ALLOW: &[&str] = &[
    "crate::protocol::meta::served_revision", // invoke.rs:331 the revision check passed as a callback
    "self.answer_undeclared_key",             // invoke.rs:338
    "rw::schema_effect",                      // invoke.rs:352
    "nonce_settle::settle_pre_send",          // invoke.rs:354 also :392
    "nonce_settle::PreSendExit::AskRefund",   // invoke.rs:354 the undeclared refusal kind
    "self.cache",                             // invoke.rs:360
    "support::note_cache_bypass", // invoke.rs:361 canonical: `super::` stripped for the move
    "self.is_chained",            // invoke.rs:364
    "self.cache_admits",          // invoke.rs:370
    "crate::gateway::ui_call::gate", // U12: a web UI call's confirm and caller gate, before the cache
    "crate::gateway::ui_call_runs_live", // U12: a web UI call skips the response cache
    "self.serve_cached_response",    // invoke.rs:376
    "nonce_settle::PreSendExit::Served", // invoke.rs:394
    "TracedOutcome::Live", // invoke.rs:355 the refusal and hit exits; listed from the live body, also :396
];

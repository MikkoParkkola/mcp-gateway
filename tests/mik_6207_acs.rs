//! Acceptance-criterion test stubs for MIK-6207.
//!
//! - AC.1: MIK-6207.AC.1 AC.1: HTTP layer extracts a per-request caller identity from a configurable trusted header (default `Cf-Access-Authenticated-User-Email`, fallback `X-Gateway-Identity`) into an `Option<VerifiedIdentity>`, and threads it as a method param from `handle_tools_call` through to `CapabilityExecutor::execute`. CHECK: file `src/gateway/router/handlers.rs` matches regex `fn extract_caller_identity` AND file `src/capability/executor/mod.rs` matches regex `pub async fn execute\([^)]*identity: Option<&(crate::)?key_server::oidc::VerifiedIdentity>|identity: Option<&VerifiedIdentity>`.
//! - AC.2: MIK-6207.AC.2 AC.2: `fetch_credential` signature carries `Option<&VerifiedIdentity>`; when identity is `None` behaviour is byte-identical to today (back-compat). CHECK: `cargo test --lib fetch_credential_none_is_backcompat` exits 0 (expected: test asserts identical resolution for all of `env:`/`file:`/bare-`UPPER` sources with `None` vs the pre-change path).
//! - AC.3: MIK-6207.AC.3 AC.3: Two distinct caller emails reaching the gateway produce two distinct identities observable downstream (log/test assertion), proving end-to-end propagation. CHECK: `cargo test --test identity_propagation two_distinct_emails_reach_executor` exits 0 (expected: an executor seam captures `alice@example.com` and `bob@example.com` as distinct `VerifiedIdentity.email` values within one process).
//! - AC.4: MIK-6207.AC.4 AC.4: Identity threading does not alter credential resolution when absent and the full quality gate is green. CHECK: `bash scripts/check_quality.sh` exits 0 (expected: fmt + clippy `-D warnings` + tests pass).
//! - AC.5: MIK-6207.AC.5 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and post-deploy gateway logs confirm at least one real request carrying a non-`None` caller identity reaches the executor seam. CHECK: `git log origin/main --grep 'MIK-6207' --oneline` exits 0 AND `rg -n 'caller_identity|VerifiedIdentity' src/capability/executor/mod.rs` finds the threaded param in the deployed source.

/// MIK-6207.AC.1 AC.1: HTTP layer extracts a per-request caller identity from a configurable trusted header (default `Cf-Access-Authenticated-User-Email`, fallback `X-Gateway-Identity`) into an `Option<VerifiedIdentity>`, and threads it as a method param from `handle_tools_call` through to `CapabilityExecutor::execute`. CHECK: file `src/gateway/router/handlers.rs` matches regex `fn extract_caller_identity` AND file `src/capability/executor/mod.rs` matches regex `pub async fn execute\([^)]*identity: Option<&(crate::)?key_server::oidc::VerifiedIdentity>|identity: Option<&VerifiedIdentity>`.
#[test]
fn ac_1_mik_6207_ac_1_ac_1_http_layer_extracts_a_per_re() {
    panic!("MIK-6207: pre-seeded stub not implemented");
}

/// MIK-6207.AC.2 AC.2: `fetch_credential` signature carries `Option<&VerifiedIdentity>`; when identity is `None` behaviour is byte-identical to today (back-compat). CHECK: `cargo test --lib fetch_credential_none_is_backcompat` exits 0 (expected: test asserts identical resolution for all of `env:`/`file:`/bare-`UPPER` sources with `None` vs the pre-change path).
#[test]
fn ac_2_mik_6207_ac_2_ac_2_fetch_credential_signature() {
    panic!("MIK-6207: pre-seeded stub not implemented");
}

/// MIK-6207.AC.3 AC.3: Two distinct caller emails reaching the gateway produce two distinct identities observable downstream (log/test assertion), proving end-to-end propagation. CHECK: `cargo test --test identity_propagation two_distinct_emails_reach_executor` exits 0 (expected: an executor seam captures `alice@example.com` and `bob@example.com` as distinct `VerifiedIdentity.email` values within one process).
#[test]
fn ac_3_mik_6207_ac_3_ac_3_two_distinct_caller_emails_r() {
    panic!("MIK-6207: pre-seeded stub not implemented");
}

/// MIK-6207.AC.4 AC.4: Identity threading does not alter credential resolution when absent and the full quality gate is green. CHECK: `bash scripts/check_quality.sh` exits 0 (expected: fmt + clippy `-D warnings` + tests pass).
#[test]
fn ac_4_mik_6207_ac_4_ac_4_identity_threading_does_not() {
    panic!("MIK-6207: pre-seeded stub not implemented");
}

/// MIK-6207.AC.5 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and post-deploy gateway logs confirm at least one real request carrying a non-`None` caller identity reaches the executor seam. CHECK: `git log origin/main --grep 'MIK-6207' --oneline` exits 0 AND `rg -n 'caller_identity|VerifiedIdentity' src/capability/executor/mod.rs` finds the threaded param in the deployed source.
#[test]
fn ac_5_mik_6207_ac_5_ac_deploy_diff_merged_to_main() {
    panic!("MIK-6207: pre-seeded stub not implemented");
}


//! Acceptance-criterion test stubs for MIK-6208.
//!
//! - AC.1: MIK.VAULT.1: Per-identity credential store (extend key_server): resolve `cred:{identity}:{provider}` keyed by `VerifiedIdentity.subject`.
//! - AC.2: MIK.VAULT.2: `fetch_credential` prefers per-user credential when the capability is tagged `personal`; falls back to shared key for non-personal/shared tools (brave, wikipedia, weather).
//! - AC.3: MIK.VAULT.3: A user without their own credential for a personal tool gets a clear "connect your account" error, NEVER the operator's token (security boundary test asserting no cross-user leak).
//! - AC.4: MIK.VAULT.4: Per-user OAuth connect flow (reuse `src/oauth/`) writes tokens under the identity, not global backend key.
//! - AC.5: MIK.VAULT.5: `scripts/check_quality.sh` green + cross-user isolation integration test.
//! - AC.6: AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.

/// MIK.VAULT.1: Per-identity credential store (extend key_server): resolve `cred:{identity}:{provider}` keyed by `VerifiedIdentity.subject`.
#[test]
fn ac_1_mik_vault_1_per_identity_credential_store_exte() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}

/// MIK.VAULT.2: `fetch_credential` prefers per-user credential when the capability is tagged `personal`; falls back to shared key for non-personal/shared tools (brave, wikipedia, weather).
#[test]
fn ac_2_mik_vault_2_fetch_credential_prefers_per_user() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}

/// MIK.VAULT.3: A user without their own credential for a personal tool gets a clear "connect your account" error, NEVER the operator's token (security boundary test asserting no cross-user leak).
#[test]
fn ac_3_mik_vault_3_a_user_without_their_own_credential() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}

/// MIK.VAULT.4: Per-user OAuth connect flow (reuse `src/oauth/`) writes tokens under the identity, not global backend key.
#[test]
fn ac_4_mik_vault_4_per_user_oauth_connect_flow_reuse() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}

/// MIK.VAULT.5: `scripts/check_quality.sh` green + cross-user isolation integration test.
#[test]
fn ac_5_mik_vault_5_scripts_check_quality_sh_green() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}

/// AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.
#[test]
fn ac_6_ac_deploy_diff_merged_to_main_target_main() {
    panic!("MIK-6208: pre-seeded stub not implemented");
}


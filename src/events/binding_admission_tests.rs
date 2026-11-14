// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! B4: event holders follow their own digest and their CLI approval binding.

use super::*;
use crate::gateway::auth::ResolvedAuthConfig;

fn at() -> DateTime<Utc> {
    DateTime::from_timestamp(1_794_225_600, 0).expect("fixed time")
}

fn root_and_child() -> (ApiKeyConfig, ApiKeyConfig) {
    let root = ApiKeyConfig {
        admin: true,
        backends: vec!["*".into()],
        ..key("root", "root-secret", None)
    };
    let auth = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![root.clone()],
        ..Default::default()
    };
    let resolved =
        ResolvedAuthConfig::from_config(&auth, crate::gateway::record_principal::TEST_RECORD_KEY)
            .with_runtime(Arc::new(
                crate::gateway::auth::runtime::AuthRuntime::default(),
            ));
    let quota = resolved
        .validate_token_at("root-secret", at())
        .expect("root validates")
        .quota_principal
        .expect("named root");
    let child = ApiKeyConfig {
        approved_by: Some(crate::config::ApiKeyBinding {
            quota_principal: quota.limit_store_key().to_owned(),
            digest_tag: crate::gateway::auth::secret_tag("root-secret"),
        }),
        cli_host: Some("laptop".into()),
        expires_at: Some(at() + chrono::Duration::hours(1)),
        ..ApiKeyConfig {
            name: "cli".into(),
            key_sha256: Some(api_key_digest_spec(b"child-secret")),
            ..root.clone()
        }
    };
    (root, child)
}

fn live(keys: Vec<ApiKeyConfig>) -> Services {
    let mut config = Config::default();
    config.auth.enabled = true;
    config.auth.api_keys = keys;
    let resolved = ResolvedAuthConfig::from_config(
        &config.auth,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    Services {
        live: Arc::new(LiveConfig::with_auth(config, Arc::new(resolved))),
        ..services(vec![])
    }
}

fn admitted(s: &Services, holder: &ApiKeyRef, now: DateTime<Utc>) -> bool {
    s.admits_grant(Some(KeyCheck::Holder(holder)), Some("x"), Ok(now))
}

#[test]
fn a_cli_childs_subscription_is_admitted_while_its_root_lives() {
    let (root, child) = root_and_child();
    let s = live(vec![root, child]);
    let holder = presented("cli", "child-secret");
    assert!(admitted(&s, &holder, at()));
    assert!(s.binding_test_admin(&holder.principal, at()));
}

#[test]
fn root_removal_ends_admission_and_standing() {
    let (_, child) = root_and_child();
    let s = live(vec![child]);
    let holder = presented("cli", "child-secret");
    // RED: raw-config admission ignores the missing approving root.
    let admission = admitted(&s, &holder, at());
    // RED: raw-config standing still treats the orphan child as an admin.
    let admin = s.binding_test_admin(&holder.principal, at());
    assert_eq!((admission, admin), (false, false));
}

#[test]
fn child_previous_grace_end_denies_only_old_tag_holders() {
    let (root, mut child) = root_and_child();
    let old = presented("cli", "child-secret");
    child.principal = Some(old.principal.clone());
    child.key_sha256 = Some(api_key_digest_spec(b"child-new"));
    child.previous_key_sha256 = Some(api_key_digest_spec(b"child-secret"));
    child.previous_expires_at = Some(at());
    let current = ApiKeyRef {
        digest_tag: Some(crate::gateway::auth::secret_tag("child-new")),
        ..old.clone()
    };
    let s = live(vec![root, child]);
    assert!(admitted(&s, &old, at() - chrono::Duration::seconds(1)));
    assert!(!admitted(&s, &old, at()));
    assert!(admitted(&s, &current, at()));
    assert!(s.binding_test_admin(&old.principal, at()));
}

#[test]
fn an_unreadable_clock_denies_admission() {
    let (root, child) = root_and_child();
    let s = live(vec![root, child]);
    let holder = presented("cli", "child-secret");
    assert!(!s.admits_grant(
        Some(KeyCheck::Holder(&holder)),
        Some("x"),
        Err(crate::clock::ClockBeforeEpoch)
    ));
}

#[test]
fn a_root_digest_grace_end_denies_the_child() {
    let (mut root, child) = root_and_child();
    root.principal = Some(presented("root", "root-secret").principal);
    root.key_sha256 = Some(api_key_digest_spec(b"root-new"));
    root.previous_key_sha256 = Some(api_key_digest_spec(b"root-secret"));
    root.previous_expires_at = Some(at());
    let s = live(vec![root, child]);
    let holder = presented("cli", "child-secret");
    let before = at() - chrono::Duration::seconds(1);
    assert!(admitted(&s, &holder, before));
    assert!(s.binding_test_admin(&holder.principal, before));
    // RED: admission must reject when the approving root digest's grace ends.
    let admission = admitted(&s, &holder, at());
    // RED: principal standing must also follow the approving digest's grace.
    let admin = s.binding_test_admin(&holder.principal, at());
    assert_eq!((admission, admin), (false, false));
}

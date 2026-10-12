// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377 rows: a stream's request-time identity is re-checked at every
//! decision (design d2.1, test plan t1.1). MIK-8350 captures the identity at
//! attach (`ViewSubject`); these rows pin that a decision uses what is true
//! now, not what was true at attach.

use std::sync::Arc;

use serde_json::json;

use super::audience_fixture::{World, tool};
use crate::gateway::oauth::{AgentDefinition, AgentRegistry};

const AUDIENCE: &str = "mik-8377";

/// Register (or replace) `client_id` with `scopes` and return a token it
/// validates. Re-registering keeps the secret, so an issued token stays valid
/// while its scopes change.
fn agent(registry: &AgentRegistry, client_id: &str, scopes: &[&str]) -> String {
    let secret = format!("{client_id}-mik-8377-secret-0123456789abcdef");
    registry.register(AgentDefinition {
        client_id: client_id.to_string(),
        name: client_id.to_string(),
        hs256_secret: Some(secret.clone()),
        rs256_public_key: None,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        issuer: None,
        audience: Some(AUDIENCE.to_string()),
    });
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": client_id, "exp": now + 3600, "iat": now, "aud": AUDIENCE }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

fn alpha(read: &str, write: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", write),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// AGENT.3: an agent whose registered scopes are narrowed after its listener
/// attaches is judged by the live registry, not the attach-time scopes. A
/// change to a tool it can no longer see tells it nothing; a change to a tool
/// it still sees tells it, and the stream stays open. Registry replacement
/// emits no notification, so the row triggers each decision itself.
#[tokio::test]
async fn agent_3_a_narrowed_agent_is_judged_by_its_live_scopes() {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let mut ear = w.listen(&token).await;
    assert!(
        w.served_names(&token).await.contains(&"read".to_string()),
        "premise: a1 sees read before narrowing"
    );

    agent(&registry, "a1", &["tools:alpha:write"]);
    assert!(
        !w.served_names(&token).await.contains(&"read".to_string()),
        "premise: the narrowed a1 no longer sees read through POST"
    );
    let _ = ear.told(&w).await;

    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "a change to a tool the live scopes withdrew tells nothing"
    );
    w.store_shared("alpha", alpha("r2", "w2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "a change to a still-visible tool tells it"
    );
    assert!(
        !ear.closed(&w).await,
        "the narrowed agent's stream stays open"
    );
}

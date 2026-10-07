// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8002 test 4f: a `base_path` the config check accepts mounts its webhook
//! routes beside the gateway's own without an axum startup panic, so the
//! matcher's acceptance and the router's compatibility agree.

use std::sync::Arc;

use super::create_router_with;
use super::tests::test_router_app_state;
use crate::config::WebhookConfig;
use crate::gateway::webhooks::WebhookRegistry;

#[tokio::test]
async fn an_accepted_base_path_mounts_beside_the_gateway_routes() {
    let (state, _store) = test_router_app_state().await;
    for base_path in ["/webhooks", "/hooks/in", "/mcpx", "/uix", "/healthz"] {
        let config = WebhookConfig {
            base_path: base_path.to_string(),
            ..WebhookConfig::default()
        };
        config
            .validate()
            .unwrap_or_else(|e| panic!("{base_path} refused: {e}"));
        let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(config)));
        let webhooks =
            WebhookRegistry::create_dynamic_routes(registry, Arc::clone(&state.multiplexer));
        // Panics here if axum refuses the composition.
        let _router = create_router_with(Arc::clone(&state), Some(webhooks));
    }
}

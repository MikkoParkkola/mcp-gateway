// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/costs` — cost governance dashboard endpoint.
//!
//! Returns current daily spend, limits, and aggregate token/call stats.
//! Gated behind the `cost-governance` feature flag.

/// Cost governance API handler.
#[cfg(feature = "cost-governance")]
pub mod handler {
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::State;
    use serde_json::{Value, json};

    use crate::gateway::router::AppState;

    /// `GET /ui/api/costs` — live cost governance status.
    pub async fn costs_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
        let meta_mcp = &state.meta_mcp;

        let mut response = json!({
            "enabled": false,
            "global_daily_spend_usd": 0.0,
        });

        if let Some(ref enforcer) = meta_mcp.budget_enforcer {
            let snap = enforcer.snapshot();
            response = json!({
                "enabled": true,
                "global_daily_spend_usd": snap.global_daily_usd,
                "global_daily_limit_usd": snap.global_daily_limit,
                "tool_daily": snap.tool_daily,
                "tool_limits": snap.tool_limits,
                "key_daily": snap.key_daily,
                "key_limits": snap.key_limits,
            });

            // Merge tool cost registry if available
            if let Some(ref registry) = meta_mcp.cost_registry {
                response["tool_costs"] = json!(registry.snapshot());
            }
        }

        // Merge existing CostTracker aggregate stats
        let agg = meta_mcp.cost_tracker.aggregate();
        response["aggregate"] = json!({
            "session_count": agg.session_count,
            "total_calls": agg.total_calls,
            "total_tokens": agg.total_tokens,
            "total_cost_usd": agg.total_cost_usd,
        });

        Json(response)
    }
}

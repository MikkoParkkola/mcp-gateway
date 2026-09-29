// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7597 §2.1a: `DirectOutcome::from_response` classifies a per-backend
//! dispatch result for spend eligibility and error-budget class, one row per
//! input arm.

use super::DirectOutcome;
use crate::protocol::{JsonRpcResponse, RequestId};
use serde_json::json;

fn ok(is_error: bool, text: &str) -> JsonRpcResponse {
    JsonRpcResponse::success(
        RequestId::Number(1),
        json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
    )
}

fn rpc(message: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, message)
}

#[test]
fn every_input_arm_is_classified() {
    let rows: Vec<(&str, crate::Result<JsonRpcResponse>, DirectOutcome)> = vec![
        (
            "ok result",
            Ok(ok(false, "fine")),
            DirectOutcome::Success { spend: true },
        ),
        (
            "isError result",
            Ok(ok(true, "tool said no")),
            DirectOutcome::Success { spend: true },
        ),
        (
            "rate limit as isError",
            Ok(ok(true, "rate limit exceeded")),
            DirectOutcome::IgnoredRateLimit { spend: true },
        ),
        (
            "rate limit as JSON-RPC error",
            Ok(rpc("rate limit exceeded")),
            DirectOutcome::IgnoredRateLimit { spend: false },
        ),
        (
            "rate limit as transport error",
            Err(crate::Error::RateLimited("backend".to_string())),
            DirectOutcome::IgnoredRateLimit { spend: false },
        ),
        (
            "other JSON-RPC error",
            Ok(rpc("backend says no")),
            DirectOutcome::Failure { spend: false },
        ),
        (
            "other transport error",
            Err(crate::Error::Transport("connection refused".to_string())),
            DirectOutcome::Failure { spend: false },
        ),
    ];
    for (name, input, expected) in rows {
        assert_eq!(DirectOutcome::from_response(&input), expected, "{name}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the answer to a caller found dead at attach is the auth layer's
//! answer to an invalid credential, byte for byte.

use axum::body::to_bytes;
use axum::response::Response;

use super::dead_attach_refusal;
use crate::gateway::middleware::bearer_unauthorized_response;

async fn parts(response: Response) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let (parts, body) = response.into_parts();
    let mut headers: Vec<_> = parts
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = to_bytes(body, usize::MAX).await.expect("a bounded body");
    (parts.status.as_u16(), headers, body.to_vec())
}

#[tokio::test]
async fn a_dead_attach_is_answered_as_an_invalid_credential_is() {
    let dead = parts(dead_attach_refusal()).await;
    let invalid = parts(bearer_unauthorized_response("Invalid token")).await;
    assert_eq!(dead, invalid, "status, headers and body all equal");
    assert_eq!(dead.0, 401);
}

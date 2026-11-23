// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MCP opening exchange, shared by a stdio backend's start and the
//! command preview's pipe: pick the protocol revision, then tell the server
//! the session is ready and give it a moment before the first real call.

use serde_json::Value;
use tracing::{debug, info, warn};

use super::Transport;
use crate::protocol::{
    JsonRpcResponse, Selectable, checked_selection, initialize_params, is_version_mismatch_error,
    negotiate_best_version, parse_supported_versions_from_error,
};
use crate::{Error, Result};

/// Sends `initialize` proposing `version` through `send`, retries once on a
/// rejection that lists a revision both sides speak, and returns the revision
/// the server's answer selected (the proposal when the answer names none).
/// `command` only labels errors and log lines.
pub(crate) async fn negotiate<F, Fut>(version: &str, command: &str, mut send: F) -> Result<String>
where
    F: FnMut(Value) -> Fut,
    Fut: Future<Output = Result<JsonRpcResponse>>,
{
    let mut response = send(initialize_params(version)).await?;
    let mut proposed = version;

    if let Some(ref error) = response.error {
        // Code only, here and below: the message is the backend's own
        // text and may quote back a credential the gateway passed it.
        if !is_version_mismatch_error(&error.message) {
            return Err(Error::Protocol(format!(
                "Initialize failed for '{command}': backend error code {}",
                error.code
            )));
        }
        let Some(negotiated) = parse_supported_versions_from_error(&error.message)
            .as_deref()
            .and_then(negotiate_best_version)
        else {
            return Err(Error::Protocol(format!(
                "Protocol version negotiation failed for '{command}': server rejected {version}, \
                     no compatible version found (backend error code {})",
                error.code
            )));
        };
        warn!(
            command = %command,
            rejected = %version,
            negotiated = %negotiated,
            "Retrying initialize with negotiated protocol version"
        );
        response = send(initialize_params(negotiated)).await?;
        if let Some(ref error) = response.error {
            return Err(Error::Protocol(format!(
                "Initialize failed for '{command}' even with negotiated version {negotiated}: \
                     backend error code {}",
                error.code
            )));
        }
        proposed = negotiated;
    }

    // The client proposes and the server selects: what this handshake's
    // answer selected governs the session, or what was proposed when it
    // names nothing. Checked before it is written, so a refusal leaves
    // the stored version as it was.
    let selected = checked_selection(response.result.as_ref(), Selectable::LegacyOrModern)?
        .unwrap_or(proposed);
    info!(
        command = %command,
        requested = %proposed,
        negotiated = %selected,
        "Protocol version agreed"
    );
    Ok(selected.to_owned())
}

/// Sends `notifications/initialized` on `transport` and waits the settle
/// time some servers need before they answer the first call.
pub(crate) async fn settle(transport: &dyn Transport) -> Result<()> {
    // Yield to ensure I/O is processed before sending notification
    tokio::task::yield_now().await;

    // Send initialized notification
    transport.notify("notifications/initialized", None).await?;

    // Yield again to ensure notification reaches the server
    tokio::task::yield_now().await;

    // Give the server time to fully transition to ready state
    // This is necessary because some MCP servers (like fulcrum) have async
    // initialization that continues after receiving the notification
    debug!("Waiting for server to complete initialization");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    Ok(())
}

/// A command preview's opening exchange over `transport`: proposes
/// `configured`, else the latest revision this gateway speaks, then settles.
/// Returns the revision agreed.
#[cfg_attr(
    not(all(test, unix)),
    expect(dead_code, reason = "the preview route calls it")
)]
pub(crate) async fn preview_handshake(
    transport: &dyn Transport,
    configured: Option<&str>,
) -> Result<String> {
    let first = configured.unwrap_or(crate::protocol::PROTOCOL_VERSION);
    let agreed = negotiate(first, "the command preview", |params| {
        transport.request("initialize", Some(params))
    })
    .await?;
    settle(transport).await?;
    Ok(agreed)
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What an MCP HTTP route returns (design §4.1, MIK-7116 MIN.2 typing). The
//! type has a private field and three named origins, so a handler cannot
//! return a bare `Response`, `Json` or `impl IntoResponse`: it must say whether
//! its body was judged by the outbound sink, is a stream whose frames the
//! stream judge writes, or is a gateway-authored refusal that carries no
//! backend content. A source test (`mcp_route_signatures`) pins that every
//! handler registered on an MCP path is declared to return this type.

use axum::response::{IntoResponse, Response};

/// A reply an MCP route may send. Built only by [`judged_reply`],
/// [`stream_reply`] and [`gateway_reply`].
#[derive(Debug)]
#[must_use]
pub(crate) struct OutboundReply(Response);

impl IntoResponse for OutboundReply {
    fn into_response(self) -> Response {
        self.0
    }
}

/// An answer that went through the outbound sink (`emit_http`): judged,
/// recorded, and committed when its body is read.
pub(crate) async fn judged_reply(
    response: Response,
    log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
) -> OutboundReply {
    judged_reply_checked(response, log).await.0
}

/// [`judged_reply`], also saying whether the answer went out as built (`false`:
/// a failed read record replaced it): what a relay receipt may follow.
pub(crate) async fn judged_reply_checked(
    response: Response,
    log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
) -> (OutboundReply, bool) {
    let (response, written) = super::emit_http_checked(response, log).await;
    hand_off_written(&response, written);
    (OutboundReply(response), written)
}

/// MIK-8176: a JSON answer its delivery record let through is handed off, so
/// the slots it carries live until redeemed or expired. A refused record
/// replaced the response, so its holds were left behind and release. The
/// stream path never comes here: it hands off when its event is yielded.
fn hand_off_written(response: &Response, written: bool) {
    if !written {
        return;
    }
    if let Some(carried) = response
        .extensions()
        .get::<crate::gateway::meta_mcp::sealed_hold::CarriedHolds>()
    {
        crate::gateway::meta_mcp::sealed_hold::hand_off(carried);
    }
}

/// A response whose frames are judged one by one by a stream judge (the
/// listen stream, the GET session stream, the POST-SSE stream).
pub(crate) fn stream_reply(response: Response) -> OutboundReply {
    OutboundReply(response)
}

/// A gateway-authored refusal or status-only answer: no backend content, so
/// nothing to judge. Every use names this origin on purpose.
pub(crate) fn gateway_reply(response: impl IntoResponse) -> OutboundReply {
    OutboundReply(response.into_response())
}

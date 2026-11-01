// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Meta-MCP handler for the MCP gateway.

use super::{AppState, Arc, OutboundReply, State, judged_reply, meta_mcp_dispatch, stream_reply};

/// Meta-MCP handler (POST /mcp).
///
/// `Accept` ALONE decides the body shape (S-01): a stream carrying only the
/// result frame is a conforming answer, so branching on whether the backend
/// happened to raise a notification would give one `Accept` two body types.
///
/// The dispatch runs inside a notification sink, and the sink IS the request
/// scoping (S-03): two concurrent POSTs are two tasks, so a backend
/// notification can only ever be appended to the call that provoked it.
/// `MIK-7272.SUB.2b`.
pub(in crate::gateway) async fn meta_mcp_handler(
    state: State<Arc<AppState>>,
    http_request: axum::http::Request<axum::body::Body>,
) -> OutboundReply {
    let offers_event_stream = http_request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/event-stream"));

    // D3-a: one grant-decision slot spans signing, admission and dispatch.
    let logger = state.meta_mcp.transparency_logger.clone();
    // MIN.2: the dispatch notes what its inner calls read before transforms,
    // so the answer's judge sees tenants the delivered value no longer shows.
    let guard = super::super::helpers::read_guard(&state);
    let audit = offers_event_stream.then(|| state.meta_mcp.rejection_audit());
    let guard_for_scope = guard.clone();
    // MIK-8161: a backend's mid-call notifications meet the egress scan too.
    let screen = Some(state.meta_mcp.notification_screen("http", ""));
    // MIK-8176: the slots this request's mints take are owned here, outside
    // the grant-audit replacer, and by the dispatch future itself, so a
    // stream that polls it after this handler returns still has its scope.
    // MIK-8176: every answer is handed off where its bytes leave (the JSON
    // reply, or the stream's answer event), so unsent slots are given back.
    let dispatch = crate::gateway::meta_mcp::sealed_hold::scoped(
        crate::gateway::meta_mcp::grant_audit::slot_http(
            logger.clone(),
            // COLLUDE.1: one relay-receipt collector spans dispatch and finalize.
            Box::pin(async move {
                crate::gateway::outbound::read_scoped(
                    guard_for_scope,
                    Box::pin(crate::gateway::meta_mcp::invoke::relay::collecting_http(
                        Arc::clone(&state.meta_mcp),
                        // One visibility judgement per request (MIK-8340),
                        // from intake's sanitize exemption (MIK-8154 D1) to
                        // the dispatch: the scope rides this future, so a
                        // notification-first stream polling it after the
                        // handler returns still reads the same answers.
                        // Boxed first: the memo then wraps a pointer, so no
                        // frame polled through the dispatch holds a copy of it.
                        // The minted-receipt scope rides outside the memo.
                        crate::gateway::meta_mcp::invoke::with_minted_receipts(Box::pin(
                            // The caller's hiding judgment, filled at intake.
                            crate::gateway::meta_mcp::hiding::with_caller_slot(
                                crate::gateway::meta_mcp::visible::memo::with_visibility_memo(
                                    // One delivery's facts: the dispatch and its record.
                                    Box::pin(crate::gateway::delivery_facts::scope(
                                        meta_mcp_dispatch(state, http_request),
                                    )),
                                ),
                            ),
                        )),
                    )),
                )
                .await
                .0
            }),
        ),
    );

    if let Some(audit) = audit {
        // Scope rather than collect: the client offered a stream, so the first
        // notification decides the body shape instead of waiting for dispatch.
        // Each notification is judged for this caller as it is queued.
        let judge = Arc::new(crate::gateway::outbound::StreamJudge::new(
            guard, audit, logger,
        ));
        let (scoped, rx) =
            crate::transport::notification_sink::scope_judged(screen, dispatch, Arc::clone(&judge));
        stream_reply(crate::gateway::streaming::first_event_wins_stream(scoped, rx, judge).await)
    } else {
        // Still scoped, and still drained alongside: `publish` sheds on a full
        // sink, and a client that did not offer a stream must not make a
        // backend's notifications count against that depth.
        let (response, _notifications) =
            crate::transport::notification_sink::collect(screen, dispatch).await;
        // The answer's read record, written after every late replacer.
        judged_reply(response, logger.as_ref()).await
    }
}

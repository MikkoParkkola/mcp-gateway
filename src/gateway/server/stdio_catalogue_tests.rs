// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7942: the stdio catalogue relay caller.

/// D6.CATALOGUE.2: a catalogue relay refusal is audited under the session id
/// the stdio dispatcher keys the connection by, so it correlates with the
/// session's other rows.
#[test]
fn the_catalogue_caller_uses_the_stdio_session_id() {
    assert_eq!(super::operator().session, super::super::STDIO_SESSION_ID);
}

/// MIK-8195 W4: the catalogue relay answers only its own methods. Anything
/// else is refused as not found, never forwarded under the stdio identity.
#[tokio::test]
async fn a_method_outside_the_catalogue_is_refused() {
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    for method in ["tools/call", "sampling/createMessage"] {
        let answer =
            super::dispatch(&meta, method, crate::protocol::RequestId::Number(7), None).await;
        assert!(answer.result.is_none(), "{method}: no result");
        let error = answer.error.unwrap_or_else(|| panic!("{method}: refused"));
        assert_eq!(error.code, -32601, "{method}");
    }
}

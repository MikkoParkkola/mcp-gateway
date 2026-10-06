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

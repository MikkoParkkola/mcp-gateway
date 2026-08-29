// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Which protocol generation a peer speaks, and how we find out.
//!
//! MCP 2026-07-28 removed the `initialize` handshake, so a client can no longer
//! learn a server's version by handshaking with it. It probes `server/discover`
//! instead and reads the *shape* of the answer.
//!
//! The subtlety, and the reason this is a module rather than an `if`: a legacy
//! server does not answer the probe with "I am legacy". It answers with an
//! arbitrary error, or with nothing at all. Only a **recognised modern error**
//! proves a modern peer. The specification's compatibility matrix puts it
//! plainly — *"the probe returns a non-modern error or times out, and the client
//! falls back to `initialize`"*.
//!
//! So the rule is asymmetric, and getting it backwards is the easy mistake:
//! evidence of modernity must be positive, and everything else is legacy.

/// What a peer speaks, as far as we have been able to establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// Speaks 2026-07-28 or later: stateless, per-request `_meta`, no handshake.
    Modern,
    /// Speaks a revision with the `initialize` handshake.
    Legacy,
}

/// JSON-RPC error code for `UnsupportedProtocolVersion` in 2026-07-28.
///
/// Renumbered from `-32004` by that revision's error-code allocation policy,
/// which reserves `-32020..=-32099` for the specification and leaves
/// `-32000..=-32019` implementation-defined.
pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// JSON-RPC error code for `HeaderMismatch` in 2026-07-28 (was `-32001`).
pub const HEADER_MISMATCH: i32 = -32020;

/// JSON-RPC error code for `MissingRequiredClientCapability` (was `-32003`).
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;

/// What came back from a `server/discover` probe.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// A result object. Whether it is a *valid* discovery document is decided
    /// by [`classify`], not by the caller.
    Result(serde_json::Value),
    /// A JSON-RPC error with this code.
    Error(i32),
    /// Nothing arrived before the deadline, or the transport failed.
    NoAnswer,
}

/// Decide which era a peer speaks from the outcome of one `server/discover`
/// probe.
///
/// Modern requires positive evidence. Everything else is legacy, including
/// silence — a peer that cannot be reached at all is not thereby modern, and
/// treating it as modern would send it requests it cannot parse.
#[must_use]
pub fn classify(outcome: &ProbeOutcome) -> Era {
    match outcome {
        // A document that names the protocol versions it speaks. The field is
        // what distinguishes a discovery result from some other server's idea
        // of what `server/discover` might mean.
        ProbeOutcome::Result(doc) if doc.get("protocolVersions").is_some() => Era::Modern,

        // A recognised modern error proves a modern peer just as well as a
        // document does: only a server that implements this revision knows
        // these codes. The client retries with a version they share rather than
        // falling back — so misreading this as legacy would downgrade a peer
        // that was ready to talk.
        ProbeOutcome::Error(code)
            if matches!(
                *code,
                UNSUPPORTED_PROTOCOL_VERSION | HEADER_MISMATCH | MISSING_REQUIRED_CLIENT_CAPABILITY
            ) =>
        {
            Era::Modern
        }

        // Everything else. `-32601 method not found` is the honest legacy
        // answer, an arbitrary application error is the sloppy one, and silence
        // is the common one. None of them is evidence of modernity.
        _ => Era::Legacy,
    }
}

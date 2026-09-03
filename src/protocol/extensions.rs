// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Protocol extensions, declared and negotiated (MCP 2026-07-28).
//!
//! The revision added an `extensions` field to client and server capabilities,
//! which gives a gateway's own additions a sanctioned home instead of a bespoke
//! field nobody else can read.
//!
//! The negotiation rule is the specification's: if one party supports an
//! extension and the other does not, the supporting party **MUST** either
//! revert to core behaviour or reject the request. This gateway reverts —
//! rejecting would refuse a conforming client for declining something optional.

use serde_json::Value;

/// An extension this gateway knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    /// `io.modelcontextprotocol/tasks` — long-running calls, polled rather than
    /// held open.
    Tasks,
}

impl Extension {
    /// The reverse-DNS identifier this extension is declared under.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Tasks => "io.modelcontextprotocol/tasks",
        }
    }

    /// The extension with this identifier, if it is one we know.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "io.modelcontextprotocol/tasks" => Some(Self::Tasks),
            _ => None,
        }
    }
}

/// A set of extensions one party supports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionSet {
    supported: Vec<Extension>,
}

impl ExtensionSet {
    /// What this gateway would declare once the tasks extension is implemented.
    ///
    /// Nothing calls this in 4.0.0, so `io.modelcontextprotocol/tasks` is never
    /// advertised and no client can negotiate it. That is deliberate: the task model
    /// in `super::tasks` is short of the extension specification by two statuses, two
    /// required fields and the shape of the failure payload, and advertising the
    /// identifier before that is fixed would break a client that trusted it. Wire this
    /// up as part of MIK-7311, not before.
    ///
    /// It is therefore uncalled *and* untested on purpose — a guard holding the
    /// identifier's shape until the behaviour behind it exists, not dead code
    /// left behind. The test that once called it went to MIK-7311 with the rest
    /// of the tasks extension.
    #[must_use]
    pub fn gateway_declares() -> Self {
        Self {
            supported: vec![Extension::Tasks],
        }
    }

    /// Read a peer's declared extensions from its capabilities.
    ///
    /// An identifier we do not know is skipped rather than kept: carrying it
    /// would let a peer's declaration decide what this gateway claims to do.
    #[must_use]
    pub fn from_capabilities(capabilities: &Value) -> Self {
        // The key names the extension; the value carries its settings and the
        // specification requires an object. Accepting a key whose value is a
        // null, a number or a string let a malformed declaration switch on
        // behaviour the peer never validly negotiated — presence is not
        // agreement.
        let supported = capabilities
            .get("extensions")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter(|(_, settings)| settings.is_object())
                    .filter_map(|(id, _)| Extension::from_id(id))
                    .collect()
            })
            .unwrap_or_default();
        Self { supported }
    }

    /// Whether this set contains an extension.
    #[must_use]
    pub fn contains(&self, extension: Extension) -> bool {
        self.supported.contains(&extension)
    }

    /// Whether it contains nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.supported.is_empty()
    }

    /// What both parties support.
    ///
    /// An intersection, never a union: a peer declaring something this gateway
    /// cannot do must not make the gateway behave as though it can.
    #[must_use]
    pub fn negotiate(&self, peer: &Self) -> Self {
        Self {
            supported: self
                .supported
                .iter()
                .copied()
                .filter(|extension| peer.contains(*extension))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These came from `tests/mik_7272_exploit_acs.rs`, where they sat under a
    // `MIK-7272.EXT.1` banner they could not honour: EXT.1 is about the
    // `extensions` field on serialised `ServerCapabilities`, which this module
    // never touches. They are unit tests of negotiation and always were. The
    // banner was the defect, not the assertions.
    //
    // EXT.1's own evidence is cases E1-E5 of
    // `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md`,
    // which are red on HEAD by design. Nothing here is expected to fail today.
    //
    // Both sides are built through `from_capabilities` on purpose. Using
    // `gateway_declares` for the gateway side would pin these to a static list
    // that MIK-7311 changes, and would test policy where the subject is
    // mechanism.

    fn peer(capabilities: Value) -> ExtensionSet {
        ExtensionSet::from_capabilities(&capabilities)
    }

    #[test]
    fn an_extension_the_peer_does_not_support_is_not_negotiated() {
        // The specification: if one party supports an extension and the other
        // does not, the supporting party MUST either revert to core behaviour
        // or reject the request. Reverting is the choice here — rejecting would
        // refuse a conforming client for declining something optional.
        let client = peer(json!({ "extensions": {} }));
        assert!(!client.contains(Extension::Tasks));

        let gateway = peer(json!({
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        }));
        assert!(
            gateway.negotiate(&client).is_empty(),
            "an extension the client does not support is not used on that request"
        );
    }

    #[test]
    fn a_shared_extension_is_negotiated() {
        let both = json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
        let negotiated = peer(both.clone()).negotiate(&peer(both));
        assert!(negotiated.contains(Extension::Tasks));
    }

    #[test]
    fn an_extension_only_the_peer_has_is_not_acquired() {
        // Negotiation is an intersection, not a union. A peer declaring
        // something this gateway cannot do must not make the gateway claim it,
        // and an identifier we do not know is dropped on the way in.
        let client = peer(json!({ "extensions": { "com.example/not-ours": {} } }));
        assert!(client.is_empty());

        let gateway = peer(json!({
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        }));
        assert!(gateway.negotiate(&client).is_empty());
    }
}

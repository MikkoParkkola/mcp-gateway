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
    /// What this gateway declares.
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
        let supported = capabilities
            .get("extensions")
            .and_then(Value::as_object)
            .map(|map| map.keys().filter_map(|id| Extension::from_id(id)).collect())
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

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One answer to "may this caller see this tool?" (MIK-8340).
//!
//! A tool is withheld from a caller for any of three reasons: the caller may
//! not invoke it (profile, authorizer, admin rule, grants), its input schema
//! is structurally invalid, or its description failed the tool-poisoning
//! check. Every listing walk and every decision about a surfaced name asks
//! here, so a withheld tool answers exactly as an absent one everywhere.

use crate::capability::validator::input_schema_is_structurally_valid;
use crate::protocol::Tool;

use super::{InvokeScope, MetaMcp};

/// Why a tool is withheld from a caller. Read only by the audit owner; every
/// decision reader treats a withheld tool exactly as an absent one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Withholding {
    /// The caller may not invoke it.
    Refused,
    /// Its input schema is structurally invalid.
    Schema,
    /// Its description failed the tool-poisoning check.
    Descriptor,
}

/// Whether a caller may be shown a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// Shown, callable by its name.
    Visible,
    /// Withheld for this reason.
    Withheld(Withholding),
}

/// What a name the client called means for this caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surfaced<'a> {
    /// A surfaced tool this caller may see, on this backend.
    Visible(&'a str),
    /// No surfaced tool has this name.
    Absent,
    /// A surfaced tool on this backend, withheld from this caller.
    Withheld(&'a str, Withholding),
}

impl<'a> Surfaced<'a> {
    /// The backend of a name this caller may see. `None` for an absent or a
    /// withheld name: every decision reader answers those the same way.
    pub(crate) fn visible_server(self) -> Option<&'a str> {
        match self {
            Self::Visible(server) => Some(server),
            Self::Absent | Self::Withheld(..) => None,
        }
    }
}

impl MetaMcp {
    /// Whether `caller` may be shown `tool`, the entry a listing walk holds
    /// from the caller's own catalogue slot (its schema is the one judged).
    pub(crate) fn visible_tool(
        &self,
        server: &str,
        tool: &Tool,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.descriptor_blocked(server, &tool.name) {
            return Visibility::Withheld(Withholding::Descriptor);
        }
        if !input_schema_is_structurally_valid(&tool.input_schema) {
            return Visibility::Withheld(Withholding::Schema);
        }
        self.invokable(server, &tool.name, scope, session_id)
    }

    /// Whether `caller` may be shown the tool named `tool` on `server`,
    /// judged from the shared catalogue. A cold cache is not a reason: a tool
    /// not yet listed is judged on the other two reasons only.
    pub(crate) fn tool_visible_to(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.descriptor_blocked(server, tool) {
            return Visibility::Withheld(Withholding::Descriptor);
        }
        if self.surfaced_schema_withheld(server, tool) {
            return Visibility::Withheld(Withholding::Schema);
        }
        self.invokable(server, tool, scope, session_id)
    }

    /// What the name `tool_name` means for this caller.
    pub(crate) fn surfaced_for<'s>(
        &'s self,
        tool_name: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Surfaced<'s> {
        let Some(server) = self.surfaced_tools_map.unscoped(tool_name) else {
            return Surfaced::Absent;
        };
        match self.tool_visible_to(server, tool_name, scope, session_id) {
            Visibility::Visible => Surfaced::Visible(server),
            Visibility::Withheld(reason) => Surfaced::Withheld(server, reason),
        }
    }

    /// Descriptor blocking applies whether or not the cache is warm (A6).
    fn descriptor_blocked(&self, server: &str, tool: &str) -> bool {
        self.backends
            .get(server)
            .is_some_and(|backend| backend.is_blocked_tool(tool))
    }

    fn invokable(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.may_invoke(server, tool, scope, session_id).is_err() {
            Visibility::Withheld(Withholding::Refused)
        } else {
            Visibility::Visible
        }
    }
}

/// The surfaced-name table, encapsulated (MIK-8340 A4). A decision about a
/// caller's call reads it only through [`MetaMcp::surfaced_for`]; the raw
/// lookup is [`SurfacedMap::unscoped`], kept for readers that name the server
/// of a call already authorized and dispatched (receipts, relay records,
/// audit attribution, recovery of an admitted task).
#[derive(Debug, Default, Clone)]
pub(crate) struct SurfacedMap(std::collections::HashMap<String, String>);

impl SurfacedMap {
    pub(super) fn new(map: std::collections::HashMap<String, String>) -> Self {
        Self(map)
    }

    /// The backend a surfaced name routes to, for every caller alike. Not a
    /// visibility decision: use [`MetaMcp::surfaced_for`] for one.
    pub(crate) fn unscoped(&self, tool_name: &str) -> Option<&str> {
        self.0.get(tool_name).map(String::as_str)
    }

    #[cfg(test)]
    pub(super) fn contains(&self, tool_name: &str) -> bool {
        self.0.contains_key(tool_name)
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl MetaMcp {
    /// [`SurfacedMap::unscoped`] for readers outside this module that name the
    /// server of a call already authorized and dispatched. Never a decision.
    pub(crate) fn surfaced_server_unscoped(&self, tool_name: &str) -> Option<&str> {
        self.surfaced_tools_map.unscoped(tool_name)
    }
}

/// Whose view a call's backend targets are resolved in.
#[derive(Clone, Copy)]
pub(crate) enum TargetView<'s> {
    /// A decision about this caller's call: a surfaced name withheld from it
    /// resolves to no target, as an absent name does.
    Caller(InvokeScope<'s>, Option<&'s str>),
    /// Attribution of a call already dispatched (its response's security).
    Dispatched,
}

impl MetaMcp {
    /// Whether a listing walk shows `tool` (the caller's own catalogue entry)
    /// to this caller: [`Self::visible_tool`] as a filter.
    pub(crate) fn shows_tool(
        &self,
        server: &str,
        tool: &Tool,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.visible_tool(server, tool, scope, session_id) == Visibility::Visible
    }

    /// Whether a name-only walk (suggestion pools, counts over names) shows the
    /// tool named `tool`: [`Self::tool_visible_to`] as a filter.
    pub(crate) fn shows_name(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.tool_visible_to(server, tool, scope, session_id) == Visibility::Visible
    }
}

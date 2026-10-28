// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the meta-tool dispatch decides from a tool's name alone: the refusal
//! for a name no meta-tool answers, and whether a result is one of the
//! discovery arms that inspected their own canonical value. Its own file to
//! keep `mod.rs` under the file-size ratchet.

use super::super::meta_mcp_helpers::did_you_mean;
use super::{MetaMcp, MetaMcpCallerContext};
use crate::Error;
use crate::error::rpc_codes::METHOD_NOT_FOUND;
use crate::gateway::router::CallerStanding;

macro_rules! meta_arms {
    ($($variant:ident => $name:literal,)*) => {
        #[doc = "One meta-tool the dispatch answers by name (MIK-8498 DISPATCH.3)."]
        #[doc = "The meta match dispatches on this, so the names it routes are data."]
        #[doc = "The `meta_arms!` table below is the only list: the enum, `ALL`,"]
        #[doc = "`name` and `parse` are generated from it, so a variant cannot"]
        #[doc = "exist outside `ALL`. The test compares `ALL` with"]
        #[doc = "`surfaced::META_TOOLS` and round-trips every name."]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum MetaArm { $($variant,)* }
        impl MetaArm {
            #[doc = "Every meta-tool, in the order a did-you-mean hint ranks them."]
            pub(super) const ALL: [Self; [$(stringify!($variant)),*].len()] = [$(Self::$variant,)*];
            #[doc = "The tool name a client calls this meta-tool by."]
            pub(super) const fn name(self) -> &'static str { match self { $(Self::$variant => $name,)* } }
            #[doc = "The meta-tool `tool_name` names, or `None` for any other name."]
            pub(super) fn parse(tool_name: &str) -> Option<Self> {
                Some(match tool_name { $($name => Self::$variant,)* _ => return None })
            }
        }
    };
}

meta_arms! {
    Search => "gateway_search",
    Execute => "gateway_execute",
    ListServers => "gateway_list_servers",
    ListTools => "gateway_list_tools",
    SearchTools => "gateway_search_tools",
    Invoke => "gateway_invoke",
    GetStats => "gateway_get_stats",
    CostReport => "gateway_cost_report",
    WebhookStatus => "gateway_webhook_status",
    RunPlaybook => "gateway_run_playbook",
    KillServer => "gateway_kill_server",
    ReviveServer => "gateway_revive_server",
    ListDisabledCapabilities => "gateway_list_disabled_capabilities",
    SetProfile => "gateway_set_profile",
    GetProfile => "gateway_get_profile",
    ListProfiles => "gateway_list_profiles",
    SetState => "gateway_set_state",
    ReloadConfig => "gateway_reload_config",
    ReloadCapabilities => "gateway_reload_capabilities",
}

impl MetaArm {
    /// Whether this meta-tool runs a composite: a plan whose steps each run
    /// in a cell of their own, with no single invocation for the whole.
    /// Exhaustive, so a new meta-tool does not compile until it is classed.
    pub(super) const fn is_composite(self) -> bool {
        match self {
            Self::Execute | Self::RunPlaybook => true,
            Self::Search
            | Self::ListServers
            | Self::ListTools
            | Self::SearchTools
            | Self::Invoke
            | Self::GetStats
            | Self::CostReport
            | Self::WebhookStatus
            | Self::KillServer
            | Self::ReviveServer
            | Self::ListDisabledCapabilities
            | Self::SetProfile
            | Self::GetProfile
            | Self::ListProfiles
            | Self::SetState
            | Self::ReloadConfig
            | Self::ReloadCapabilities => false,
        }
    }
}

/// Whether `tool_name` names a composite meta-tool (`gateway_execute`,
/// `gateway_run_playbook`); `false` for any other name.
pub(crate) fn is_composite_meta_tool(tool_name: &str) -> bool {
    MetaArm::parse(tool_name).is_some_and(MetaArm::is_composite)
}

impl MetaMcp {
    /// The refusal for a name no meta-tool answers, with a suggestion drawn
    /// only from the tools this caller may see.
    pub(super) fn no_such_meta_tool(
        &self,
        tool_name: &str,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Error {
        // The candidate pool is the EXPOSED set, not the static list.
        // The early return above keeps a hidden tool's exact name from
        // being confirmed; a near miss of that name reached here and
        // the suggester, drawing from every meta-tool that exists,
        // would answer with the name the allow-list is hiding. Filtering
        // the pool removes the route -- there is no longer a spelling
        // that makes this branch name an unexposed tool -- rather than
        // wording the hint more carefully and leaving the route open.
        let exposed: Vec<&str> = MetaArm::ALL
            .iter()
            .map(|arm| arm.name())
            .filter(|name| self.meta_tool_exposure.is_exposed(name))
            // Nor a tool this caller's standing withholds (A3).
            .filter(|name| CallerStanding::from(caller.scope()).permits(name))
            .collect();
        let suggestion = did_you_mean(tool_name, &exposed, 3, 3);
        let msg = match suggestion {
            Some(hint) => format!("Unknown tool: {tool_name}. {hint}"),
            None => format!("Unknown tool: {tool_name}"),
        };
        Error::json_rpc(METHOD_NOT_FOUND, msg)
    }

    /// Whether a meta-tool result is one of the three discovery arms, which
    /// inspected their canonical value (`inspect_discovery_value`): its
    /// response is marked so no later pass scans the serialised copy
    /// (MIK-7407.RESPONSE.3). Asked after the meta-tool match only, never on
    /// the direct-name routes above it.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn marks_discovery(&self, tool_name: &str, scanned: bool) -> bool {
        #[cfg(feature = "firewall")]
        let armed = self.firewall.is_some();
        #[cfg(not(feature = "firewall"))]
        let armed = false;
        armed
            && scanned
            && matches!(
                MetaArm::parse(tool_name),
                Some(MetaArm::Search | MetaArm::ListTools | MetaArm::SearchTools)
            )
    }
}

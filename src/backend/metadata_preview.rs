// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The start-once preview's tool listing (MIK-8838): the live fill's parse and
//! judgement, with nothing cached and no verdict committed.

use serde_json::Value;

use super::{ListFamily, drain_list_pages, prepare_tool_metadata};
use crate::Result;

/// What a start-once preview listed (MIK-8838): the tools as the gateway would
/// serve them, which of them declared `readOnlyHint` themselves, the names
/// withheld, and whether paging stopped short.
pub(crate) struct PreviewListing {
    pub(crate) tools: Vec<crate::protocol::Tool>,
    /// Names whose `readOnlyHint` the server set itself, before normalisation.
    pub(crate) hint_declared: std::collections::HashSet<String>,
    pub(crate) withheld: std::collections::BTreeSet<String>,
    pub(crate) truncated: bool,
}

/// List a preview transport's tools the way a live fill does: drain the pages,
/// parse entry by entry, normalise and judge with no pins, and then drop every
/// remaining tool whose name was withheld, so a clean duplicate of a withheld
/// name never shows. Nothing is cached and no verdict is committed.
pub(crate) async fn list_tools_for_preview(
    name: &str,
    transport: &dyn crate::transport::Transport,
) -> Result<PreviewListing> {
    let family = ListFamily {
        method: "tools/list",
        kind: "tools",
        list_key: "tools",
        truncated_flag: None,
        cooldown: false,
        stale_hit: false,
    };
    let (merged, truncated) = drain_list_pages(transport, name, &family, (&[], None), None).await?;
    let raw = merged
        .as_ref()
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let (mut tools, unparseable) = super::super::descriptor_gate::parse_listed(raw);
    let hint_declared = tools
        .iter()
        .filter(|tool| {
            tool.annotations
                .as_ref()
                .is_some_and(|a| a.read_only_hint.is_some())
        })
        .map(|tool| tool.name.clone())
        .collect();
    let mut prepared = prepare_tool_metadata(
        name,
        &std::collections::BTreeMap::new(),
        super::super::Judging::Judge,
        &mut tools,
    );
    prepared.verdicts.add_unparseable(unparseable);
    let withheld = prepared.verdicts.withheld_names();
    tools.retain(|tool| !withheld.contains(&tool.name));
    Ok(PreviewListing {
        tools,
        hint_declared,
        withheld,
        truncated,
    })
}

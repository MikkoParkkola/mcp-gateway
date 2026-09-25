// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tool-count type surfaced in meta-tool descriptions and discovery text.

use std::fmt;
use std::sync::Arc;

use crate::backend::Backend;

/// A bare `0` cannot distinguish "exposes no tools" from "not asked yet".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolTotal {
    Unknown,
    AtLeast(usize),
    Exact(usize),
}

impl ToolTotal {
    /// "42 tools", "at least 42 tools", or plain "tools".
    pub(crate) fn phrase(self) -> String {
        match self {
            Self::Unknown => "tools".to_string(),
            Self::AtLeast(count) => format!("at least {count} tools"),
            Self::Exact(count) => format!("{count} tools"),
        }
    }

    /// Widen by tools known independently of the cache. Never de-hedges.
    pub(crate) fn plus(self, extra: usize) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::AtLeast(count) => Self::AtLeast(count + extra),
            Self::Exact(count) => Self::Exact(count + extra),
        }
    }
}

impl fmt::Display for ToolTotal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

/// A floor over the backends enumerated so far; `Unknown` when none has been.
/// A truncated drain is enumerated but only a floor (MIK 7570 PAGING.1).
pub(crate) fn tool_total(backends: &[Arc<Backend>]) -> ToolTotal {
    let enumerated = backends.iter().filter(|b| b.cached_tools_known()).count();
    let mut truncated = false;
    let mut total: usize = 0;
    for b in backends {
        let (tools, cut) = b.cached_tools_snapshot_and_truncated();
        truncated |= cut;
        total += tools.len();
    }
    if enumerated == backends.len() && !truncated {
        ToolTotal::Exact(total)
    } else if enumerated == 0 {
        ToolTotal::Unknown
    } else {
        ToolTotal::AtLeast(total)
    }
}

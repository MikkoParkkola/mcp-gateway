// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The advertised tool total, as a floor over the backends enumerated so far.

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

pub(crate) fn tool_total(backends: &[Arc<Backend>]) -> ToolTotal {
    let enumerated = backends.iter().filter(|b| b.cached_tools_known()).count();
    let total: usize = backends.iter().map(|b| b.cached_tools_count()).sum();
    if enumerated == backends.len() {
        ToolTotal::Exact(total)
    } else if enumerated == 0 {
        ToolTotal::Unknown
    } else {
        ToolTotal::AtLeast(total)
    }
}

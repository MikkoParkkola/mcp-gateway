// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a queued notification copy carries about its audience, and the
//! refusal of a copy no stream took (MIK-7798).

use std::sync::Arc;

use crate::gateway::auth::live::Audience;

/// The owned twin of [`Audience`] a queued copy carries.
#[derive(Debug, Clone)]
pub(super) enum CopyAudience {
    Backend(Arc<str>),
    Any,
}

impl CopyAudience {
    pub(super) fn as_audience(&self) -> Audience<'_> {
        match self {
            Self::Backend(backend) => Audience::Backend(backend),
            Self::Any => Audience::Any,
        }
    }
}

/// A copy that was not queued: nobody listens, or its judgement failed closed.
#[derive(Debug)]
pub(super) struct Unsent;

impl std::fmt::Display for Unsent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no stream took the copy")
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The text log layer's one way in: every text layer is built by
//! [`escaping`], so no field value, message or metadata can write a control
//! character, and so a forged line, into the operator's log.

use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::format::{DefaultFields, Format, Full};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

/// The text layer `base`, with its output escaped.
pub(crate) fn escaping<S, T, W>(
    base: fmt::Layer<S, DefaultFields, Format<Full, T>, W>,
) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    T: FormatTime + Send + Sync + 'static,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    base
}

#[cfg(test)]
#[path = "log_escape_tests.rs"]
mod tests;

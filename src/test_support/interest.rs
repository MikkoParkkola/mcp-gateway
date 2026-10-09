// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one process-wide keeper of tracing callsite interest for test log
//! captures (MIK-8254). Shared by `#[path]`: the library's `test_log_capture`,
//! and `test_support/error_capture.rs` for the binary and its fresh-process row.
//!
//! A capture is a thread-scoped subscriber. While it is the only registered
//! dispatcher, tracing-core rebuilds a newly registered callsite's interest from
//! the registering thread's default alone, so a first hit on a thread with no
//! subscriber caches the callsite as `never` and the capture never sees it. A
//! global TRACE registry is a second dispatcher that wants every callsite, so
//! no callsite is ever cached off.

/// Install the global TRACE registry once; later calls do nothing.
pub(crate) fn keep_interest_open() {
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
}

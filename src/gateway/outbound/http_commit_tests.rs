// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A response's relay receipts commit on the first successful data chunk
//! the server takes, once.

use std::sync::Arc;

use futures::StreamExt as _;

use super::commit_at_first_chunk;
use crate::gateway::meta_mcp::invoke::relay::{
    DeferredReceipts, StagedReceipts, commit_capture_hook,
};

/// h5: an error item is not a delivered chunk: it commits nothing; the
/// next successful chunk commits, once.
/// Mutant killed: a commit on any first item, error included.
#[tokio::test(flavor = "current_thread")]
async fn h5_an_errored_chunk_commits_nothing() {
    let live = Arc::new(crate::config_reload::LiveConfig::new(
        crate::config::Config::default(),
    ));
    let receipts = DeferredReceipts::new(StagedReceipts::none(), true, Some(live));
    let chunks = futures::stream::iter(vec![
        Err(std::io::Error::other("the backend stream broke")),
        Ok(axum::body::Bytes::from_static(b"{\"a\":1}")),
        Ok(axum::body::Bytes::from_static(b"{\"b\":2}")),
    ]);
    let response =
        axum::response::IntoResponse::into_response(axum::body::Body::from_stream(chunks));
    let response = commit_at_first_chunk(response, receipts);
    let before = commit_capture_hook::reached();
    let mut body = response.into_body().into_data_stream();
    assert!(
        body.next().await.is_some_and(|c| c.is_err()),
        "base: the error item"
    );
    assert_eq!(
        commit_capture_hook::reached(),
        before,
        "an error item commits nothing"
    );
    assert!(
        body.next().await.is_some_and(|c| c.is_ok()),
        "base: a data chunk"
    );
    assert_eq!(
        commit_capture_hook::reached(),
        before + 1,
        "the first data chunk commits"
    );
    assert!(
        body.next().await.is_some_and(|c| c.is_ok()),
        "base: a second chunk"
    );
    assert_eq!(commit_capture_hook::reached(), before + 1, "committed once");
}

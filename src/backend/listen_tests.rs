// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener's reach into a backend that need no peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

fn backend() -> Backend {
    let cfg = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_owned(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    Backend::new(
        "mem",
        cfg,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// After a backend's tools notice the shared slot's cached tool list is
/// gone, so the re-read a `tools_changed` subscriber does reaches the
/// backend (I5b design section 14).
#[tokio::test]
async fn a_tools_notice_drops_the_cached_tool_list() {
    let backend = backend();
    let calls = Arc::new(AtomicU32::new(0));
    let read = || {
        let calls = Arc::clone(&calls);
        let entry = backend.shared_entry();
        async move {
            entry
                .tools_cache
                .get_or_fetch_shared(Duration::from_secs(300), || {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    }
                })
                .await
                .expect("fill");
        }
    };
    read().await;
    read().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the second read is cached");
    backend.invalidate_tools();
    read().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the notice forced a re-read"
    );
}

/// MIK-7894: the resend-permitted set is derived from the cached tool list, so
/// a notice that drops the list drops the set with it; a stale set would keep
/// letting a tool that is no longer read-only be sent again.
#[tokio::test]
async fn a_tools_notice_clears_the_resend_permitted_set() {
    let backend = backend();
    let entry = backend.shared_entry();
    entry
        .resend_permitted
        .write()
        .insert("was_read_only".to_owned());
    backend.invalidate_tools();
    assert!(
        entry.resend_permitted.read().is_empty(),
        "a stale resend set outlived the tool list"
    );
}

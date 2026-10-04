// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool annotation normalisation and cached tool metadata.

use super::*;

#[test]
fn normalize_tool_annotations_fills_missing_hints() {
    let mut tools = vec![sample_tool("search_messages"), sample_tool("send_message")];

    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    let search = tools[0].annotations.as_ref().unwrap();
    assert_eq!(search.read_only_hint, Some(true));
    assert_eq!(search.destructive_hint, Some(false));
    assert_eq!(search.idempotent_hint, Some(true));
    assert_eq!(search.open_world_hint, Some(true));

    let send = tools[1].annotations.as_ref().unwrap();
    assert_eq!(send.read_only_hint, Some(false));
    assert_eq!(send.destructive_hint, Some(true));
    assert_eq!(send.idempotent_hint, Some(false));
    assert_eq!(send.open_world_hint, Some(true));
}

#[test]
fn normalize_tool_annotations_preserves_existing_true_hints_and_adds_false_hints() {
    let mut tool = sample_tool("recall");
    tool.annotations = Some(ToolAnnotations {
        read_only_hint: Some(true),
        destructive_hint: None,
        idempotent_hint: None,
        open_world_hint: None,
        title: None,
    });
    let mut tools = vec![tool];

    prepare_tool_metadata(
        "hebb",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    let annotations = tools[0].annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[test]
fn normalize_tool_annotations_preserves_downstream_annotation_title_and_hints() {
    let mut tool = sample_tool("remote_write");
    tool.annotations = Some(ToolAnnotations {
        title: Some("Remote Write".to_string()),
        read_only_hint: Some(false),
        destructive_hint: Some(false),
        idempotent_hint: Some(false),
        open_world_hint: Some(false),
    });
    let mut tools = vec![tool];

    prepare_tool_metadata(
        "remote-api",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    let annotations = tools[0].annotations.as_ref().unwrap();
    assert_eq!(annotations.title.as_deref(), Some("Remote Write"));
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[tokio::test]
async fn cached_metadata_tracks_freshness() {
    let cache = CachedMetadata::new();
    assert!(!cache.is_fresh(Duration::from_secs(60)));

    let _ = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async { Ok(vec![1, 2, 3]) })
        .await;

    assert!(cache.is_fresh(Duration::from_secs(60)));
    let snapshot = cache.snapshot_shared().unwrap();
    assert_eq!(snapshot.as_ref(), &vec![1, 2, 3]);
    assert_eq!(snapshot.len(), 3);
}

#[tokio::test]
async fn cached_metadata_shared_reads_reuse_arc() {
    let cache = CachedMetadata::new();

    let first = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async { Ok(vec![1, 2, 3]) })
        .await
        .unwrap();
    let second = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            panic!("fresh cache hit should not refetch")
        })
        .await
        .unwrap();

    assert!(Arc::ptr_eq(&first, &second));
}

#[tokio::test]
async fn cached_metadata_retries_after_fetch_error() {
    let cache = CachedMetadata::new();
    let attempts = AtomicUsize::new(0);

    let first = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err(Error::BackendUnavailable("boom".to_string()))
            } else {
                Ok(vec![7])
            }
        })
        .await;
    assert!(first.is_err());

    let second = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err(Error::BackendUnavailable("boom".to_string()))
            } else {
                Ok(vec![7])
            }
        })
        .await;

    assert_eq!(second.unwrap().as_ref(), &vec![7]);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn get_tools_singleflight_coalesces_concurrent_requests() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: vec![sample_tool("echo")],
            next_cursor: None,
        },
    );
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(25)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let barrier = Arc::new(Barrier::new(6));
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let backend = Arc::clone(&backend);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            backend.get_tools().await.unwrap()
        }));
    }

    barrier.wait().await;

    for task in tasks {
        let tools = task.await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
    }

    assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    assert!(backend.has_cached_tools());
    assert_eq!(backend.cached_tools_count(), 1);
    assert!(backend.cached_tools_known());
    assert_eq!(
        backend.get_cached_tool("echo").map(|tool| tool.name),
        Some("echo".to_string())
    );
}

#[tokio::test]
async fn cached_tools_known_is_false_before_any_enumeration() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    assert_eq!(backend.cached_tools_count(), 0);
    assert!(!backend.cached_tools_known());
}

/// The other half of the pair: enumerated, and genuinely empty.
#[tokio::test]
async fn cached_tools_known_is_true_for_an_enumerated_backend_with_no_tools() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: Vec::new(),
            next_cursor: None,
        },
    );
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let tools = backend.get_tools().await.expect("enumeration succeeds");

    assert!(tools.is_empty());
    assert_eq!(backend.cached_tools_count(), 0);
    assert!(
        backend.cached_tools_known(),
        "an empty answer is still an answer — the backend has been enumerated"
    );

    // Discarding an empty list must not un-enumerate the backend.
    backend.invalidate_tools_cache();
    assert!(
        backend.cached_tools_known(),
        "discarding the cached answer must not claim the backend was never asked"
    );
}

#[tokio::test]
async fn get_tools_does_not_cache_json_rpc_error_response() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend down");
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let result = backend.get_tools().await;

    assert!(result.is_err());
    assert!(!backend.has_cached_tools());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
}

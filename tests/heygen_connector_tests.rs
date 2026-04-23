use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mcp_gateway::{
    capability::{CapabilityBackend, CapabilityExecutor},
    protocol::Content,
};
use serde_json::{Value, json};
use tempfile::tempdir;

fn capability_dir() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("capabilities")
        .join("media")
        .to_string_lossy()
        .into_owned()
}

fn extract_json(result: &mcp_gateway::protocol::ToolsCallResult) -> Value {
    match &result.content[0] {
        Content::Text { text, .. } => serde_json::from_str(text).expect("tool should return JSON"),
        other => panic!("unexpected tool content: {other:?}"),
    }
}

fn pick_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| value.get(key).and_then(Value::as_str))
}

fn pick_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| value.get(key).and_then(Value::as_u64))
}

#[tokio::test]
#[ignore = "requires HEYGEN_API_KEY and incurs a real HeyGen video generation call"]
async fn video_agent_create_to_download_round_trip_with_real_api() {
    if std::env::var("HEYGEN_API_KEY").is_err() {
        eprintln!("HEYGEN_API_KEY not set; skipping");
        return;
    }

    let backend = Arc::new(CapabilityBackend::new(
        "media",
        Arc::new(CapabilityExecutor::new()),
    ));
    backend
        .load_from_directory(&capability_dir())
        .await
        .expect("load media capabilities");

    for name in [
        "video_agent_create",
        "video_create",
        "video_get",
        "video_download",
        "voice_list",
        "avatar_list",
    ] {
        assert!(backend.has_capability(name), "missing capability {name}");
    }

    let prompt = std::env::var("HEYGEN_TEST_PROMPT").unwrap_or_else(|_| {
        "A presenter explaining our product launch in 30 seconds.".to_string()
    });

    let create = backend
        .call_tool("video_agent_create", json!({ "prompt": prompt }))
        .await
        .expect("video_agent_create call");
    let create_json = extract_json(&create);
    let create_data = create_json.get("data").unwrap_or(&create_json);
    let video_id = pick_string(create_data, &["video_id", "id"])
        .expect("create response should include video_id")
        .to_string();

    let mut last = Value::Null;
    for _ in 0..36 {
        let get = backend
            .call_tool("video_get", json!({ "video_id": video_id.clone() }))
            .await
            .expect("video_get call");
        last = extract_json(&get);
        let data = last.get("data").unwrap_or(&last);
        match pick_string(data, &["status"]) {
            Some("completed") => break,
            Some("failed") => {
                panic!(
                    "HeyGen video generation failed: {}",
                    pick_string(data, &["failure_message"]).unwrap_or("unknown failure")
                );
            }
            _ => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }

    let data = last.get("data").unwrap_or(&last);
    assert_eq!(pick_string(data, &["status"]), Some("completed"));
    let video_url = pick_string(data, &["video_url"])
        .expect("completed video should include video_url")
        .to_string();

    let download = backend
        .call_tool("video_download", json!({ "video_url": video_url }))
        .await
        .expect("video_download call");
    let download_json = extract_json(&download);
    let bytes = STANDARD
        .decode(
            pick_string(&download_json, &["data"]).expect("download response should contain data"),
        )
        .expect("download data should be valid base64");
    assert!(
        pick_string(&download_json, &["mime_type"]).unwrap_or_default().contains("mp4"),
        "expected mp4 mime type, got: {download_json:?}"
    );
    assert_eq!(
        pick_u64(&download_json, &["size"]),
        Some(bytes.len() as u64),
        "reported size should match decoded payload"
    );

    let dir = tempdir().expect("tempdir");
    let output = dir.path().join("heygen-test.mp4");
    std::fs::write(&output, &bytes).expect("write mp4");
    assert!(output.exists(), "downloaded mp4 should exist");
    assert!(!bytes.is_empty(), "downloaded mp4 should not be empty");
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::super::MetaMcp;
use crate::Error;
use crate::backend::BackendRegistry;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn gateway() -> MetaMcp {
    MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        None,
        Duration::from_secs(60),
    )
    .with_code_mode(true)
}

#[tokio::test]
async fn a_query_of_256_characters_is_accepted() {
    let meta = gateway();
    let q = "a".repeat(256);
    let result = meta.code_mode_search_anon(&json!({"query": q}), None).await;
    assert!(
        result.is_ok(),
        "256 'a' must be accepted: {:?}",
        result.err()
    );

    let q = "İ".repeat(256);
    let result = meta.code_mode_search_anon(&json!({"query": q}), None).await;
    assert!(
        result.is_ok(),
        "256 'İ' must be accepted: {:?}",
        result.err()
    );
}

fn assert_refused_with(result: crate::Result<serde_json::Value>, label: &str) {
    match result {
        Err(Error::JsonRpc { code, message, .. }) => {
            assert_eq!(code, -32602, "{label}: code must be -32602");
            assert!(
                message.contains("256"),
                "{label}: message must contain \"256\": {message}"
            );
            assert!(
                !message.contains("xxxxxxxx"),
                "{label}: message must not echo the query: {message}"
            );
        }
        other => panic!("{label}: expected JsonRpc -32602 refusal, got: {other:?}"),
    }
}

#[tokio::test]
async fn a_query_over_256_characters_is_refused_without_echoing_it() {
    let meta = gateway();
    let q = "x".repeat(257);
    let result = meta.code_mode_search_anon(&json!({"query": q}), None).await;
    assert_refused_with(result, "257 'x'");

    let q = "*".repeat(300);
    let result = meta.code_mode_search_anon(&json!({"query": q}), None).await;
    assert_refused_with(result, "300 '*'");
}

#[test]
fn every_bundled_capability_reference_is_under_the_cap() {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/capabilities"));
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("read_dir on capabilities tree");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    files.push(path);
                }
            }
        }
    }
    files.sort();

    let mut names: Vec<String> = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path).expect("read capability yaml");
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("name:") {
                let value = rest.trim().trim_matches('"').trim_matches('\'').trim();
                if !value.is_empty() {
                    names.push(value.to_string());
                }
                break;
            }
        }
    }

    assert!(
        names.len() >= 50,
        "expected at least 50 capability names, found {}",
        names.len()
    );

    let mut longest: String = String::new();
    for name in &names {
        let reference = format!("gateway:{name}");
        if reference.chars().count() > longest.chars().count() {
            longest = reference;
        }
    }
    let longest_len = longest.chars().count();

    assert!(
        longest_len < 256,
        "longest reference {longest:?} is {longest_len} chars, must be under 256"
    );
}

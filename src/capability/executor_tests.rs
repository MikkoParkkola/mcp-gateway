//! Tests for `CapabilityExecutor` and `ResponseCache`

use super::*;
use crate::capability::response_cache::ResponseCache;

#[test]
fn test_build_url() {
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/users/{id}/posts/{post_id}".to_string(),
        ..Default::default()
    };

    let params = serde_json::json!({
        "id": "123",
        "post_id": 456
    });

    let url = executor.build_url(&config, &params).unwrap();
    assert_eq!(url, "https://api.example.com/users/123/posts/456");
}

#[test]
fn test_substitute_string() {
    let executor = CapabilityExecutor::new();
    let template = "Hello {name}, your score is {score}";
    let params = serde_json::json!({
        "name": "World",
        "score": 100
    });

    let result = executor.substitute_string(template, &params).unwrap();
    assert_eq!(result, "Hello World, your score is 100");
}

#[test]
fn test_extract_path() {
    let executor = CapabilityExecutor::new();
    let value = serde_json::json!({
        "data": {
            "users": [
                {"name": "Alice"},
                {"name": "Bob"}
            ]
        }
    });

    let result = executor.extract_path(&value, "data.users").unwrap();
    assert!(result.is_array());
    assert_eq!(result.as_array().unwrap().len(), 2);

    let result = executor.extract_path(&value, "data.users.0.name").unwrap();
    assert_eq!(result, "Alice");
}

#[test]
fn test_cache() {
    let cache = ResponseCache::new();
    let value = serde_json::json!({"test": true});

    cache.set("key1", &value, 60);
    assert_eq!(cache.get("key1"), Some(value));

    assert_eq!(cache.get("nonexistent"), None);
}

#[test]
fn test_fetch_from_file_simple() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tokens.json");
    std::fs::write(
        &file,
        r#"{"access_token": "test-token-123", "refresh_token": "refresh-456"}"#,
    )
    .unwrap();

    let spec = format!("{}:access_token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "test-token-123");

    let spec = format!("{}:refresh_token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "refresh-456");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_nested() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred-nested");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.json");
    std::fs::write(
        &file,
        r#"{"auth": {"google": {"token": "nested-token"}, "count": 42}}"#,
    )
    .unwrap();

    let spec = format!("{}:auth.google.token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "nested-token");

    // Numeric values work too
    let spec = format!("{}:auth.count", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "42");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_missing_field() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred-missing");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tokens.json");
    std::fs::write(&file, r#"{"access_token": "value"}"#).unwrap();

    let spec = format!("{}:nonexistent", file.display());
    let result = executor.fetch_from_file(&spec);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_missing_file() {
    let executor = CapabilityExecutor::new();
    let result = executor.fetch_from_file("/nonexistent/path/tokens.json:field");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to read"));
}

#[test]
fn test_fetch_from_file_invalid_format() {
    let executor = CapabilityExecutor::new();
    // No colon separator for field
    let result = executor.fetch_from_file("/path/to/file.json");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid file credential format"));
}

#[test]
fn test_substitute_params_skips_unresolved_placeholders() {
    let executor = CapabilityExecutor::new();
    let mut template = std::collections::HashMap::new();
    template.insert("resolved".to_string(), "{name}".to_string());
    template.insert("unresolved".to_string(), "{missing_param}".to_string());
    template.insert("static_val".to_string(), "hello".to_string());

    let params = serde_json::json!({"name": "world"});
    let result = executor.substitute_params(&template, &params).unwrap();

    // resolved and static_val should be present, unresolved should be filtered
    let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"resolved"));
    assert!(keys.contains(&"static_val"));
    assert!(!keys.contains(&"unresolved"));
}

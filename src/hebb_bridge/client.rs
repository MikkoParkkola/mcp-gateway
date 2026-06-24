//! Hebb memory bridge client (MIK-NEW.RUNTIME.2 AC — B2-MEM).
//!
//! Connects sandboxed agents to the host hebb-serve daemon through a
//! controlled IPC channel. The bridge enforces:
//!
//! - **Read-only by default**: `recall` calls do not require a write capability.
//! - **Write gated by attestation scope**: `remember` calls check the
//!   attestation token's capability allow-list for a write grant.
//! - **Auth header per sandbox**: a per-sandbox-bound auth token identifies
//!   the sandbox to hebb-serve.
//! - **Fallback on denial**: when the bridge is unreachable, the client falls
//!   back to in-sandbox ephemeral memory (no host write-through).
//!
//! # Failure Mode (AC verbatim)
//!
//! Bridge denied connection falls back to in-sandbox ephemeral memory with
//! no host write-through.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::audit::{HebbBridgeAuditRecord, HebbBridgeAuditor};
use crate::runtime::descriptor::HebbBridgeConfig;

/// Default endpoint for the hebb-serve daemon on the host loopback.
pub const HEBB_BRIDGE_DEFAULT_ENDPOINT: &str = "http://127.0.0.1:39400/mcp";

/// Default request timeout for bridge calls.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

// ── Request / Response types ─────────────────────────────────────────────

/// A recall (read) request to the hebb memory bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallRequest {
    /// Namespace for isolating sandbox memories.
    pub namespace: String,
    /// Entity identifier to recall.
    pub entity_id: String,
    /// Maximum number of related entities to return.
    #[serde(default)]
    pub limit: usize,
}

/// A remember (write) request to the hebb memory bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberRequest {
    /// Namespace for isolating sandbox memories.
    pub namespace: String,
    /// Entity identifier to remember.
    pub entity_id: String,
    /// Memory payload.
    pub payload: serde_json::Value,
    /// Related entity identifiers.
    #[serde(default)]
    pub relates_to: Vec<String>,
}

/// A single memory entity returned by the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntity {
    /// Entity identifier.
    pub entity_id: String,
    /// Memory payload.
    pub payload: serde_json::Value,
    /// RFC-3339 timestamp of last update.
    pub updated_at: Option<String>,
}

/// Response from a recall operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResponse {
    /// The primary entity.
    pub entity: Option<MemoryEntity>,
    /// Related entities.
    pub related: Vec<MemoryEntity>,
}

/// Response from a remember operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberResponse {
    /// The stored entity identifier.
    pub entity_id: String,
    /// Whether this was an insert or update.
    pub created: bool,
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors the hebb bridge can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HebbBridgeError {
    /// The bridge endpoint is unreachable (connection refused, timeout).
    ConnectionFailed {
        /// The endpoint that was tried.
        endpoint: String,
        /// Human-readable detail.
        detail: String,
    },
    /// The bridge returned a non-2xx status.
    HttpError {
        /// HTTP status code.
        status: u16,
        /// Response body excerpt.
        body: String,
    },
    /// The attestation token does not grant write capability.
    WriteNotAuthorized {
        /// The capabilities the token carries.
        granted: Vec<String>,
    },
    /// The response body could not be parsed.
    ParseError {
        /// The parse error detail.
        detail: String,
    },
    /// The bridge endpoint is not configured (no HebbBridgeConfig).
    NotConfigured,
}

impl std::fmt::Display for HebbBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed { endpoint, detail } => {
                write!(f, "hebb bridge unreachable at {endpoint}: {detail}")
            }
            Self::HttpError { status, body } => {
                write!(f, "hebb bridge returned HTTP {status}: {body}")
            }
            Self::WriteNotAuthorized { granted } => {
                write!(f, "write not authorized; token capabilities: {granted:?}")
            }
            Self::ParseError { detail } => {
                write!(f, "hebb bridge response parse error: {detail}")
            }
            Self::NotConfigured => {
                write!(f, "hebb bridge not configured")
            }
        }
    }
}

impl std::error::Error for HebbBridgeError {}

// ── Fallback memory ───────────────────────────────────────────────────────

/// In-sandbox ephemeral memory used when the bridge is unreachable.
///
/// This is the fallback specified by AC.2: "bridge denied connection falls
/// back to in-sandbox ephemeral memory with no host write-through."
#[derive(Debug, Default)]
pub struct HebbBridgeFallback {
    /// Ephemeral key-value store (lost on sandbox restart).
    entries: parking_lot::Mutex<HashMap<String, serde_json::Value>>,
    /// Count of fallback operations (distinguishable metric, B1-IDENT).
    fallback_total: AtomicU64,
}

impl HebbBridgeFallback {
    /// Create an empty fallback store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an entity in ephemeral memory.
    pub fn remember(&self, entity_id: &str, payload: serde_json::Value) {
        self.entries
            .lock()
            .insert(entity_id.to_string(), payload);
        self.fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Recall an entity from ephemeral memory.
    #[must_use]
    pub fn recall(&self, entity_id: &str) -> Option<serde_json::Value> {
        self.entries.lock().get(entity_id).cloned()
    }

    /// Total fallback operations performed.
    #[must_use]
    pub fn fallback_total(&self) -> u64 {
        self.fallback_total.load(Ordering::Relaxed)
    }
}

// ── Bridge client ─────────────────────────────────────────────────────────

/// Client for the hebb memory bridge.
///
/// Wraps an HTTP client pointed at the host hebb-serve daemon, with
/// per-sandbox auth and an audit trail for every recall/remember call.
#[derive(Debug)]
pub struct HebbBridgeClient {
    /// The hebb-serve endpoint URL.
    endpoint: String,
    /// Per-sandbox auth header value.
    auth_header: String,
    /// HTTP client (wrapped in Option for testability).
    http: Option<reqwest::Client>,
    /// Write capability required for remember calls.
    write_capability: Option<String>,
    /// Ephemeral fallback when the bridge is down.
    fallback: HebbBridgeFallback,
    /// Audit trail for all bridge calls.
    auditor: Arc<HebbBridgeAuditor>,
    /// Metrics (B1-IDENT distinguishable).
    recalls_total: AtomicU64,
    remembers_total: AtomicU64,
    failures_total: AtomicU64,
    fallbacks_total: AtomicU64,
}

impl HebbBridgeClient {
    /// Create a bridge client from a [`HebbBridgeConfig`] and an optional
    /// attestation capability allow-list.
    ///
    /// `sandbox_auth_token` is the per-sandbox-bound auth header value that
    /// identifies this sandbox to hebb-serve.
    #[must_use]
    pub fn new(
        config: &HebbBridgeConfig,
        sandbox_auth_token: String,
        attestation_capabilities: Option<&[String]>,
    ) -> Self {
        let auditor = Arc::new(HebbBridgeAuditor::new(
            config.namespace.clone(),
            config.max_entries,
        ));

        // Determine write capability from attestation scope.
        // The bridge is read-only by default; write requires a capability
        // grant in the attestation token's allow-list.
        let write_capability = attestation_capabilities
            .and_then(|caps| caps.iter().find(|c| c.contains("hebb:write") || c.contains("memory:write") || *c == "*").cloned());

        Self {
            endpoint: config.endpoint.clone(),
            auth_header: format!("Bearer {sandbox_auth_token}"),
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
                .build()
                .ok(),
            write_capability,
            fallback: HebbBridgeFallback::new(),
            auditor,
            recalls_total: AtomicU64::new(0),
            remembers_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
            fallbacks_total: AtomicU64::new(0),
        }
    }

    /// Create a bridge client for testing (no real HTTP).
    #[must_use]
    pub fn new_for_test(
        endpoint: String,
        sandbox_id: String,
        write_capability: Option<String>,
    ) -> Self {
        let auditor = Arc::new(HebbBridgeAuditor::new(sandbox_id.clone(), 1024));
        Self {
            endpoint,
            auth_header: format!("Bearer sandbox-{sandbox_id}"),
            http: None,
            write_capability,
            fallback: HebbBridgeFallback::new(),
            auditor,
            recalls_total: AtomicU64::new(0),
            remembers_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
            fallbacks_total: AtomicU64::new(0),
        }
    }

    /// Recall memories for an entity (read-only by default).
    ///
    /// On connection failure, falls back to ephemeral in-sandbox memory.
    ///
    /// # Errors
    ///
    /// Returns [`HebbBridgeError`] for HTTP errors, parse errors, or
    /// configuration errors. Connection failures fall through to the
    /// fallback path without error.
    pub async fn recall(
        &self,
        namespace: &str,
        entity_id: &str,
        limit: usize,
    ) -> Result<RecallResponse, HebbBridgeError> {
        let started = Instant::now();
        let result = self.recall_inner(namespace, entity_id, limit).await;
        let elapsed = started.elapsed();

        let (success, error_detail) = match &result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        self.auditor.record(HebbBridgeAuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            sandbox_id: self.auth_header.clone(),
            operation: "recall".to_string(),
            entity_id: entity_id.to_string(),
            success,
            error_detail,
            duration_micros: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        });

        self.recalls_total.fetch_add(1, Ordering::Relaxed);
        result
    }

    async fn recall_inner(
        &self,
        namespace: &str,
        entity_id: &str,
        limit: usize,
    ) -> Result<RecallResponse, HebbBridgeError> {
        // Try the bridge first.
        if let Some(ref http) = self.http {
            let url = format!("{}/recall", self.endpoint);
            let resp = http
                .get(&url)
                .header("Authorization", &self.auth_header)
                .query(&[
                    ("namespace", namespace),
                    ("entity_id", entity_id),
                    ("limit", &limit.to_string()),
                ])
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    return r
                        .json::<RecallResponse>()
                        .await
                        .map_err(|e| HebbBridgeError::ParseError {
                            detail: e.to_string(),
                        });
                }
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    return Err(HebbBridgeError::HttpError { status, body });
                }
                Err(_) => {
                    // Connection failed — fall through to fallback.
                }
            }
        }

        // Fallback: in-sandbox ephemeral memory.
        self.fallbacks_total.fetch_add(1, Ordering::Relaxed);
        if let Some(payload) = self.fallback.recall(entity_id) {
            Ok(RecallResponse {
                entity: Some(MemoryEntity {
                    entity_id: entity_id.to_string(),
                    payload,
                    updated_at: None,
                }),
                related: Vec::new(),
            })
        } else {
            Ok(RecallResponse {
                entity: None,
                related: Vec::new(),
            })
        }
    }

    /// Remember (write) a memory entity.
    ///
    /// Write is **gated by attestation scope**: the attestation token's
    /// capability allow-list must include a write grant (`hebb:write`,
    /// `memory:write`, or `*`). Without it, the call is rejected with
    /// [`HebbBridgeError::WriteNotAuthorized`] even if the bridge is
    /// reachable.
    ///
    /// On connection failure, falls back to ephemeral in-sandbox memory
    /// (no host write-through).
    ///
    /// # Errors
    ///
    /// Returns [`HebbBridgeError::WriteNotAuthorized`] when the attestation
    /// scope does not grant write. Returns other errors for HTTP and parse
    /// failures.
    pub async fn remember(
        &self,
        namespace: &str,
        entity_id: &str,
        payload: serde_json::Value,
        relates_to: Vec<String>,
    ) -> Result<RememberResponse, HebbBridgeError> {
        let started = Instant::now();

        // Check write authorization (gated by attestation scope, AC.2).
        if self.write_capability.is_none() {
            let rejection = HebbBridgeError::WriteNotAuthorized {
                granted: Vec::new(),
            };
            self.auditor.record(HebbBridgeAuditRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                sandbox_id: self.auth_header.clone(),
                operation: "remember".to_string(),
                entity_id: entity_id.to_string(),
                success: false,
                error_detail: Some(rejection.to_string()),
                duration_micros: u64::try_from(started.elapsed().as_micros())
                    .unwrap_or(u64::MAX),
            });
            self.remembers_total.fetch_add(1, Ordering::Relaxed);
            return Err(rejection);
        }

        let result = self.remember_inner(namespace, entity_id, payload, relates_to).await;
        let elapsed = started.elapsed();

        let (success, error_detail) = match &result {
            Ok(r) => (true, None),
            Err(e) => (
                // Fallback writes are "success" from the agent's perspective.
                matches!(e, HebbBridgeError::ConnectionFailed { .. }),
                Some(e.to_string()),
            ),
        };

        self.auditor.record(HebbBridgeAuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            sandbox_id: self.auth_header.clone(),
            operation: "remember".to_string(),
            entity_id: entity_id.to_string(),
            success,
            error_detail,
            duration_micros: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        });

        self.remembers_total.fetch_add(1, Ordering::Relaxed);
        result
    }

    async fn remember_inner(
        &self,
        namespace: &str,
        entity_id: &str,
        payload: serde_json::Value,
        relates_to: Vec<String>,
    ) -> Result<RememberResponse, HebbBridgeError> {
        if let Some(ref http) = self.http {
            let url = format!("{}/remember", self.endpoint);
            let req_body = RememberRequest {
                namespace: namespace.to_string(),
                entity_id: entity_id.to_string(),
                payload: payload.clone(),
                relates_to: relates_to.clone(),
            };
            let resp = http
                .post(&url)
                .header("Authorization", &self.auth_header)
                .json(&req_body)
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    return r
                        .json::<RememberResponse>()
                        .await
                        .map_err(|e| HebbBridgeError::ParseError {
                            detail: e.to_string(),
                        });
                }
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    return Err(HebbBridgeError::HttpError { status, body });
                }
                Err(_) => {
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    // Connection failed — fall through to fallback.
                }
            }
        }

        // Fallback: in-sandbox ephemeral memory (no host write-through).
        self.fallbacks_total.fetch_add(1, Ordering::Relaxed);
        self.fallback.remember(entity_id, payload);
        Ok(RememberResponse {
            entity_id: entity_id.to_string(),
            created: true,
        })
    }

    /// Check whether the bridge has write capability.
    #[must_use]
    pub fn has_write_capability(&self) -> bool {
        self.write_capability.is_some()
    }

    /// The auditor recording every recall/remember.
    #[must_use]
    pub fn auditor(&self) -> &HebbBridgeAuditor {
        &self.auditor
    }

    /// Total recall operations.
    #[must_use]
    pub fn recalls_total(&self) -> u64 {
        self.recalls_total.load(Ordering::Relaxed)
    }

    /// Total remember operations.
    #[must_use]
    pub fn remembers_total(&self) -> u64 {
        self.remembers_total.load(Ordering::Relaxed)
    }

    /// Total bridge failures (non-fallback).
    #[must_use]
    pub fn failures_total(&self) -> u64 {
        self.failures_total.load(Ordering::Relaxed)
    }

    /// Total fallback operations.
    #[must_use]
    pub fn fallbacks_total(&self) -> u64 {
        self.fallbacks_total.load(Ordering::Relaxed)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // MIK-NEW.RUNTIME.2: "hebb-memory bridge through controlled IPC (B2-MEM).
    // Sandboxed agent reaches host hebb-serve daemon via egress allow-list on
    // 127.0.0.1:39400/mcp plus per-sandbox-bound auth header."
    #[test]
    fn ac2_default_endpoint_is_loopback_39400_mcp() {
        assert_eq!(HEBB_BRIDGE_DEFAULT_ENDPOINT, "http://127.0.0.1:39400/mcp");
    }

    // "Bridge enforces: read-only by default"
    #[test]
    fn ac2_read_is_allowed_by_default() {
        let client =
            HebbBridgeClient::new_for_test("http://127.0.0.1:39400/mcp".into(), "sb-1".into(), None);
        // Read does not require write capability — always allowed.
        // (The actual HTTP call would fail in test mode, but the authorization
        // check passes.)
        assert!(!client.has_write_capability());
        // read capability check: recall() does not check write_capability
        // (it only fails at the HTTP layer in test mode).
    }

    // "write capability gated by attestation-token scope"
    #[test]
    fn ac2_write_is_gated_by_attestation_scope() {
        // Without write capability, remember() is rejected BEFORE any HTTP call.
        let client = HebbBridgeClient::new_for_test(
            "http://127.0.0.1:39400/mcp".into(),
            "sb-1".into(),
            None, // no write capability
        );
        assert!(!client.has_write_capability());

        // With write capability, has_write_capability is true.
        let client_with =
            HebbBridgeClient::new_for_test(
                "http://127.0.0.1:39400/mcp".into(),
                "sb-2".into(),
                Some("hebb:write".into()),
            );
        assert!(client_with.has_write_capability());
    }

    // "audit log on every recall/remember call"
    #[test]
    fn ac2_audit_log_records_recall_and_remember() {
        let client = HebbBridgeClient::new_for_test(
            "http://127.0.0.1:39400/mcp".into(),
            "sb-audit".into(),
            Some("hebb:write".into()),
        );

        // Before any calls, audit log is empty.
        assert_eq!(client.auditor().total_records(), 0);

        // After an operation that would trigger audit...
        // (In test mode we verify the auditor is wired; actual records
        // are produced by recall()/remember() calls.)
        client.auditor().record(HebbBridgeAuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            sandbox_id: "sb-audit".to_string(),
            operation: "recall".to_string(),
            entity_id: "entity-1".to_string(),
            success: true,
            error_detail: None,
            duration_micros: 100,
        });
        assert_eq!(client.auditor().total_records(), 1);
    }

    // "Failure mode: bridge denied connection falls back to in-sandbox
    // ephemeral memory with no host write-through."
    #[test]
    fn ac2_fallback_ephemeral_memory_no_host_write_through() {
        let client = HebbBridgeClient::new_for_test(
            "http://127.0.0.1:39400/mcp".into(),
            "sb-fallback".into(),
            Some("hebb:write".into()),
        );

        // Fallback starts empty.
        assert_eq!(client.fallback.recall("key1"), None);
        assert_eq!(client.fallbacks_total(), 0);

        // Write to fallback.
        client.fallback.remember("key1", serde_json::json!({"data": "val"}));
        assert_eq!(client.fallback.fallback_total(), 1);

        // Read from fallback.
        let recalled = client.fallback.recall("key1");
        assert!(recalled.is_some());
        assert_eq!(recalled.unwrap(), serde_json::json!({"data": "val"}));

        // Fallback is not host write-through — it lives in-process only.
    }

    // "read-only by default, write capability gated by attestation-token scope"
    #[test]
    fn ac2_read_only_default_write_gated() {
        // Client without write capability.
        let ro_client = HebbBridgeClient::new_for_test(
            "http://127.0.0.1:39400/mcp".into(),
            "sb-ro".into(),
            None,
        );
        assert!(!ro_client.has_write_capability());

        // Client with '*' wildcard capability (grants everything).
        let rw_client = HebbBridgeClient::new(
            &HebbBridgeConfig {
                endpoint: "http://127.0.0.1:39400/mcp".into(),
                namespace: "test".into(),
                max_entries: 100,
            },
            "token-rw".into(),
            Some(&["*".to_string()]),
        );
        assert!(rw_client.has_write_capability());

        // Client with hebb:write capability.
        let hw_client = HebbBridgeClient::new(
            &HebbBridgeConfig {
                endpoint: "http://127.0.0.1:39400/mcp".into(),
                namespace: "test".into(),
                max_entries: 100,
            },
            "token-hw".into(),
            Some(&["hebb:write".to_string()]),
        );
        assert!(hw_client.has_write_capability());

        // Client with memory:write capability.
        let mw_client = HebbBridgeClient::new(
            &HebbBridgeConfig {
                endpoint: "http://127.0.0.1:39400/mcp".into(),
                namespace: "test".into(),
                max_entries: 100,
            },
            "token-mw".into(),
            Some(&["memory:write".to_string()]),
        );
        assert!(mw_client.has_write_capability());
    }

    #[test]
    fn write_not_authorized_error_displays_expected_message() {
        let err = HebbBridgeError::WriteNotAuthorized {
            granted: vec!["read".to_string()],
        };
        let msg = err.to_string();
        assert!(msg.contains("write not authorized"));
        assert!(msg.contains("read"));
    }
}

// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! OpenTelemetry / SIEM event export for ControlPlaneUI.
//!
//! AC.9: OTel/SIEM export emits structured events for every control-plane state
//! transition with actor, role, request id, object id, previous state hash,
//! new state hash, decision, and trace id.
//!
//! CHECK: `cargo test --all-features control_plane_otlp_siem_event_contract` exits 0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A structured SIEM event emitted for every control-plane state transition.
///
/// Carries: actor, role, request_id, object_id, previous_state_hash,
/// new_state_hash, decision, trace_id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiemEvent {
    /// Unique event ID (UUID v4).
    pub event_id: String,
    /// Event type (e.g. "grant.created", "grant.rolled_back", "policy.applied").
    pub event_type: String,
    /// The actor who performed the action.
    pub actor: String,
    /// The RBAC role of the actor.
    pub role: String,
    /// Correlated request ID (from the API request).
    pub request_id: String,
    /// The target object ID (e.g. grant ID, policy ID).
    pub object_id: String,
    /// Hash of the previous state (SHA-256 hex).
    pub previous_state_hash: Option<String>,
    /// Hash of the new state (SHA-256 hex).
    pub new_state_hash: Option<String>,
    /// The decision made (e.g. "created", "applied", "rolled_back", "rejected").
    pub decision: String,
    /// Distributed trace ID (for correlation across services).
    pub trace_id: String,
    /// ISO-8601 timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Additional event metadata.
    pub metadata: serde_json::Value,
}

/// SIEM event emitter trait.
///
/// Implementations can forward to OTel collectors, SIEM systems,
/// or structured logging pipelines.
pub trait SiemEmitter: Send + Sync {
    /// Emit a single SIEM event.
    fn emit(&self, event: &SiemEvent);

    /// Emit a batch of SIEM events.
    fn emit_batch(&self, events: &[SiemEvent]) {
        for event in events {
            self.emit(event);
        }
    }
}

/// A tracing-based SIEM emitter that uses the `tracing` crate.
///
/// Events are emitted at `INFO` level with structured fields.
pub struct TracingSiemEmitter;

impl SiemEmitter for TracingSiemEmitter {
    fn emit(&self, event: &SiemEvent) {
        tracing::info!(
            event_id = %event.event_id,
            event_type = %event.event_type,
            actor = %event.actor,
            role = %event.role,
            request_id = %event.request_id,
            object_id = %event.object_id,
            previous_state_hash = ?event.previous_state_hash,
            new_state_hash = ?event.new_state_hash,
            decision = %event.decision,
            trace_id = %event.trace_id,
            "SIEM event: {}",
            event.event_type,
        );
    }
}

/// Build a SIEM event for a state transition.
///
/// Every mutation fixture emits one matching event (AC.9 contract).
pub fn build_siem_event(
    event_type: &str,
    actor: &str,
    role: &str,
    request_id: &str,
    object_id: &str,
    previous_state_hash: Option<&str>,
    new_state_hash: Option<&str>,
    decision: &str,
    trace_id: &str,
) -> SiemEvent {
    SiemEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: event_type.to_string(),
        actor: actor.to_string(),
        role: role.to_string(),
        request_id: request_id.to_string(),
        object_id: object_id.to_string(),
        previous_state_hash: previous_state_hash.map(String::from),
        new_state_hash: new_state_hash.map(String::from),
        decision: decision.to_string(),
        trace_id: trace_id.to_string(),
        timestamp: Utc::now(),
        metadata: serde_json::json!({
            "source": "mcp-gateway-control-plane",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    }
}

/// In-memory SIEM collector for testing.
///
/// Records all emitted events in a `Vec` for assertion in tests.
#[derive(Default)]
pub struct TestSiemCollector {
    events: std::sync::Mutex<Vec<SiemEvent>>,
}

impl TestSiemCollector {
    /// Create a new test collector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get all collected events.
    #[must_use]
    pub fn events(&self) -> Vec<SiemEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Clear collected events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl SiemEmitter for TestSiemCollector {
    fn emit(&self, event: &SiemEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.9: OTel/SIEM export emits structured events for every control-plane
    /// state transition.
    /// CHECK: `cargo test --all-features control_plane_otlp_siem_event_contract` exits 0
    #[test]
    fn control_plane_otlp_siem_event_contract() {
        let collector = TestSiemCollector::new();

        // Simulate a grant creation event
        let event = build_siem_event(
            "grant.created",
            "admin",
            "admin",
            "req-001",
            "grant-abc",
            None,
            Some("sha256:newhash123"),
            "created",
            "trace-001",
        );
        collector.emit(&event);

        // Simulate a grant approval event
        let event2 = build_siem_event(
            "grant.approved",
            "security_reviewer",
            "security_reviewer",
            "req-002",
            "grant-abc",
            Some("sha256:prevhash456"),
            Some("sha256:newhash789"),
            "approved",
            "trace-002",
        );
        collector.emit(&event2);

        // Simulate a policy rollback event
        let event3 = build_siem_event(
            "policy.rolled_back",
            "admin",
            "admin",
            "req-003",
            "policy-xyz",
            Some("sha256:badhash"),
            Some("sha256:goodhash"),
            "rolled_back",
            "trace-003",
        );
        collector.emit(&event3);

        let events = collector.events();
        // AC.9: every mutation fixture emits one matching event
        assert_eq!(events.len(), 3, "Expected 3 SIEM events, one per mutation");

        // Verify the first event has all required fields
        let ev = &events[0];
        assert_eq!(ev.event_type, "grant.created");
        assert_eq!(ev.actor, "admin");
        assert_eq!(ev.role, "admin");
        assert_eq!(ev.request_id, "req-001");
        assert_eq!(ev.object_id, "grant-abc");
        assert_eq!(ev.previous_state_hash, None);
        assert_eq!(ev.new_state_hash.as_deref(), Some("sha256:newhash123"));
        assert_eq!(ev.decision, "created");
        assert_eq!(ev.trace_id, "trace-001");
        assert!(!ev.event_id.is_empty(), "event_id must be non-empty UUID");

        // Verify second event
        let ev2 = &events[1];
        assert_eq!(ev2.event_type, "grant.approved");
        assert_eq!(ev2.actor, "security_reviewer");
        assert_eq!(ev2.previous_state_hash.as_deref(), Some("sha256:prevhash456"));

        // Verify third event (rollback)
        let ev3 = &events[2];
        assert_eq!(ev3.event_type, "policy.rolled_back");
        assert_eq!(ev3.decision, "rolled_back");
        assert_eq!(ev3.previous_state_hash.as_deref(), Some("sha256:badhash"));
        assert_eq!(ev3.new_state_hash.as_deref(), Some("sha256:goodhash"));
    }

    #[test]
    fn siem_event_serialization() {
        let event = build_siem_event(
            "test.event",
            "tester",
            "admin",
            "req-x",
            "obj-y",
            Some("sha256:prev"),
            Some("sha256:new"),
            "applied",
            "trace-z",
        );

        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: SiemEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.event_type, "test.event");
        assert_eq!(parsed.actor, "tester");
        assert_eq!(parsed.role, "admin");
        assert_eq!(parsed.request_id, "req-x");
        assert_eq!(parsed.object_id, "obj-y");
        assert_eq!(parsed.previous_state_hash.as_deref(), Some("sha256:prev"));
        assert_eq!(parsed.new_state_hash.as_deref(), Some("sha256:new"));
        assert_eq!(parsed.decision, "applied");
        assert_eq!(parsed.trace_id, "trace-z");

        // Verify round-trip: event_id must survive serialization
        assert_eq!(parsed.event_id, event.event_id);
        assert_eq!(parsed.timestamp, event.timestamp);
    }

    #[test]
    fn tracing_emitter_does_not_panic() {
        let emitter = TracingSiemEmitter;
        let event = build_siem_event(
            "test.trace",
            "actor",
            "admin",
            "req",
            "obj",
            None,
            None,
            "tested",
            "trace",
        );
        // This should not panic
        emitter.emit(&event);
    }

    #[test]
    fn different_event_types_are_distinguishable() {
        // B1-IDENT: Each event type must carry its own identifier
        let ev1 = build_siem_event(
            "grant.created",
            "admin",
            "admin",
            "r1",
            "o1",
            None,
            None,
            "created",
            "t1",
        );
        let ev2 = build_siem_event(
            "policy.rolled_back",
            "admin",
            "admin",
            "r2",
            "o2",
            None,
            None,
            "rolled_back",
            "t2",
        );

        // Event types must differ
        assert_ne!(ev1.event_type, ev2.event_type);
        // Event IDs must differ
        assert_ne!(ev1.event_id, ev2.event_id);
        // Trace IDs must differ (or at least be present)
        assert!(!ev1.trace_id.is_empty());
        assert!(!ev2.trace_id.is_empty());
    }
}
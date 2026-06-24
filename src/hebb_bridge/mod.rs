//! Hebb memory bridge through controlled IPC (MIK-NEW.RUNTIME.2, B2-MEM).
//!
//! Sandboxed agents reach the host hebb-serve daemon via egress allow-list on
//! `127.0.0.1:39400/mcp` plus a per-sandbox-bound auth header. The bridge
//! enforces read-only by default, write capability gated by attestation-token
//! scope, and generates an audit log on every recall/remember call.
//!
//! Failure mode: bridge denied connection falls back to in-sandbox ephemeral
//! memory with no host write-through.
//!
//! # Design
//!
//! ```text
//! Sandboxed Agent
//!   │  recall/remember calls
//!   ▼
//! HebbBridgeClient  ──127.0.0.1:39400/mcp──▶  Host hebb-serve daemon
//!   │  (per-sandbox auth header)
//!   ├── recall()     read-only by default
//!   ├── remember()   write gated by attestation scope
//!   └── audit_log    every call recorded
//!
//! HebbBridgeAuditor   (records every recall/remember, B1-IDENT distinguishable)
//!   └── HebbBridgeAuditRecord  (timestamp, sandbox_id, operation, entity, success)
//! ```

pub mod audit;
pub mod client;

pub use audit::{HebbBridgeAuditRecord, HebbBridgeAuditor};
pub use client::{
    HebbBridgeClient, HebbBridgeError, HebbBridgeFallback, RecallRequest, RememberRequest,
    HEBB_BRIDGE_DEFAULT_ENDPOINT,
};

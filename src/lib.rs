//! MCP Gateway Library
//!
//! Universal Model Context Protocol (MCP) Gateway with Meta-MCP for ~95% token savings.
//!
//! # Features
//!
//! - **Meta-MCP Mode**: 4 meta-tools for dynamic tool discovery
//! - **Streaming**: Real-time notifications via SSE (MCP 2025-03-26 Streamable HTTP)
//! - **Notification Multiplexer**: Routes backend notifications to connected clients
//! - **Multi-Transport**: stdio, Streamable HTTP, SSE support
//! - **Failsafes**: Circuit breakers, retries, timeouts, rate limiting
//! - **Production Ready**: Health checks, metrics, graceful shutdown
//!
//! # Protocol Version
//!
//! Implements MCP protocol versions:
//! - 2025-11-25 (latest - tasks, elicitation, audio, tool annotations)
//! - 2025-06-18
//! - 2025-03-26 (Streamable HTTP)
//! - 2024-11-05
//! - 2024-10-07

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod cache;
pub mod capability;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod error;
pub mod failsafe;
pub mod gateway;
pub mod oauth;
pub mod playbook;
pub mod protocol;
pub mod ranking;
pub mod registry;
pub mod secrets;
pub mod stats;
pub mod transform;
pub mod transport;
pub mod validator;

pub use error::{Error, Result};

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// MCP Protocol version supported by this gateway (latest)
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Setup tracing/logging
///
/// # Errors
///
/// This function currently always succeeds but returns `Result` for
/// forward compatibility with fallible tracing configurations.
pub fn setup_tracing(level: &str, format: Option<&str>) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = tracing_subscriber::registry().with(filter);

    match format {
        Some("json") => {
            subscriber.with(fmt::layer().json()).init();
        }
        _ => {
            subscriber.with(fmt::layer()).init();
        }
    }

    Ok(())
}

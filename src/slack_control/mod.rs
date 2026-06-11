//! Slack-driven agent control plane (bidirectional) — MIK-5031.
//!
//! This module implements the inbound half of the Slack control plane:
//! the operator posts a task/question/instruction in Slack, the gateway
//! receives it via Socket Mode, authorizes it, executes (or answers),
//! and replies in-thread.
//!
//! # Architecture
//!
//! ```text
//! Slack Channel ──(Socket Mode WSS)──► SlackControlListener
//!                                            │
//!                                     AuthGate (user-ID allowlist)
//!                                            │
//!                                     ActionPolicy (allow/deny classifier)
//!                                            │
//!                                     AgentDispatch (claude-elite runtime)
//!                                            │
//!                                     slack_post_message (reply in-thread)
//!                                            │
//!                                     AuditLog (JSONL, every event)
//! ```
//!
//! # Threat model
//!
//! A Slack channel that can trigger agent actions is a remote command-execution
//! path. This module gates WHO may command, WHAT the agent will run, and
//! AUDITs every triggered action.

pub mod audit;
pub mod auth;
pub mod checkpoint;
pub mod config;
pub mod dispatch;
pub mod listener;
pub mod manifest;
pub mod policy;
pub mod session;

pub use config::SlackControlConfig;

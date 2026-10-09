// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The outbound A2A bridge: an MCP client delegates to an A2A agent through
//! the gateway (MIK-8063).
//!
//! A backend configured with `transport: a2a` and an `a2a_url` starts as an
//! [`transport::A2aTransport`] in `Backend::start`, so a delegation runs
//! through the same invoke funnel, pool, budgets, audit and firewall as any
//! tool call. The agent is exposed as one tool, `send_message`.
//!
//! Wire: A2A 1.0, JSON-RPC binding (specification tag v1.0.1). Outbound only;
//! the gateway does not serve A2A.
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`types`] | the A2A 1.0 wire shapes this bridge reads and writes |
//! | [`client`] | card fetch, endpoint choice (same origin), the JSON-RPC calls |
//! | [`delegation`] | who owns an agent task while the bridge waits on it |
//! | [`translator`] | card -> tool, reply -> MCP `CallToolResult` |
//! | [`transport`] | the backend `Transport` |

pub(crate) mod client;
pub(crate) mod delegation;
#[cfg(test)]
pub(crate) mod test_agent;
pub(crate) mod translator;
pub(crate) mod transport;
pub(crate) mod types;

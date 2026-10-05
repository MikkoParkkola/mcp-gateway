// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! OAuth 2.0 Client for MCP Gateway
//!
//! Implements OAuth Authorization Code flow with PKCE (RFC 7636) for
//! MCP backends that require authentication.
//!
//! Features:
//! - OAuth metadata discovery (RFC 8414)
//! - Authorization code flow with PKCE
//! - Token storage and automatic refresh
//! - Browser-based authorization
//! - Callback server for auth code reception

mod callback;
// The 3.x credential-file reader, shared by `accounts migrate-credentials` and
// `oauth migrate-legacy`: crate-private, owned by neither caller.
pub mod client;
pub mod legacy_migrate;
pub(crate) mod legacy_source;
mod metadata;
mod storage;
mod token_file;
#[cfg(test)]
mod upgrade_path_tests;

pub use client::{OAuthClient, OAuthClientConfig};
pub use metadata::{AuthorizationServerMetadata, IssuerSource, ProtectedResourceMetadata};
pub use storage::{TokenInfo, TokenStorage};

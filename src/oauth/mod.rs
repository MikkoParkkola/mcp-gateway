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
mod client;
mod metadata;
mod storage;

pub use client::OAuthClient;
pub use metadata::{AuthorizationServerMetadata, ProtectedResourceMetadata};
pub use storage::{TokenInfo, TokenStorage};

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Compile-time evidence for each case `scripts/release/check_identity_sources.py`
//! catches: each `evidence: ID` line below is followed by a
//! `compile_fail` block and a twin that differs from it in exactly one line.
//! Stable rustdoc does not check a `compile_fail` block's error code, so the
//! twin carries the cause: everything else in the block compiles, and only the
//! one changed line does not. `identity_evidence_tests` reads these pairs and
//! checks the shape. Compiled only when rustdoc collects doctests.
//!
//! evidence: LIT-VI
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn f(v: VerifiedIdentity) -> VerifiedIdentity {
//!     VerifiedIdentity { subject: String::new(), email: String::new(), name: None, groups: Vec::new(), issuer: String::new() }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn f(v: VerifiedIdentity) -> VerifiedIdentity {
//!     v
//! }
//! ```
//!
//! evidence: LIT-GS
//!
//! ```compile_fail
//! use mcp_gateway::identity_grants::GrantSubject;
//! fn f(v: GrantSubject) -> GrantSubject {
//!     GrantSubject { authority: String::new(), subject: String::new(), label: None }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::identity_grants::GrantSubject;
//! fn f(v: GrantSubject) -> GrantSubject {
//!     v
//! }
//! ```
//!
//! evidence: LIT-CI
//!
//! ```compile_fail
//! use mcp_gateway::mtls::CertIdentity;
//! fn f(v: CertIdentity) -> CertIdentity {
//!     CertIdentity { common_name: None, organizational_unit: None, san_uris: Vec::new(), san_dns_names: Vec::new(), display_name: String::new() }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::mtls::CertIdentity;
//! fn f(v: CertIdentity) -> CertIdentity {
//!     v
//! }
//! ```
//!
//! evidence: NEW-GS
//!
//! ```compile_fail
//! use mcp_gateway::identity_grants::GrantSubject;
//! fn f() -> GrantSubject {
//!     GrantSubject::new("api_key", "alice", None)
//! }
//! ```
//!
//! ```
//! use mcp_gateway::identity_grants::GrantSubject;
//! fn f() -> GrantSubject {
//!     GrantSubject::new("api_key", "alice", None).expect("names someone")
//! }
//! ```
//!
//! evidence: H1
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! use serde::Deserialize as D;
//! #[derive(D)]
//! struct W { v: VerifiedIdentity }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! use serde::Deserialize as D;
//! #[derive(Clone)]
//! struct W { v: VerifiedIdentity }
//! ```
//!
//! evidence: H2
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! #[derive(serde::Deserialize)]
//! struct W { v: [VerifiedIdentity; 1] }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! #[derive(Clone)]
//! struct W { v: [VerifiedIdentity; 1] }
//! ```
//!
//! evidence: H3
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity::{self as N};
//! fn f(v: N) -> N {
//!     N { subject: String::new(), email: String::new(), name: None, groups: Vec::new(), issuer: String::new() }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity::{self as N};
//! fn f(v: N) -> N {
//!     v
//! }
//! ```
//!
//! evidence: H4
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! use serde_json::from_str as f;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     f(s).ok()
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! use serde_json::from_str as f;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     f::<u8>(s).ok().and(None)
//! }
//! ```
//!
//! evidence: H4-SPACED
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     serde_json :: from_str(s).ok()
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     serde_json :: from_str::<u8>(s).ok().and(None)
//! }
//! ```
//!
//! evidence: H5
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! trait ReadBack { fn read_back(s: &str) -> Self; }
//! impl ReadBack for VerifiedIdentity {
//!     fn read_back(s: &str) -> Self { serde_json::from_str(s).expect("bytes") }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! trait ReadBack { fn read_back(s: &str) -> Self; }
//! impl ReadBack for VerifiedIdentity {
//!     fn read_back(s: &str) -> Self { unimplemented!("{s}") }
//! }
//! ```
//!
//! evidence: H6
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     let v: Option<VerifiedIdentity> = { serde_json::from_str(s).ok() };
//!     v
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn read(s: &str) -> Option<VerifiedIdentity> {
//!     let v: Option<VerifiedIdentity> = { serde_json::from_str::<u8>(s).ok().and(None) };
//!     v
//! }
//! ```
//!
//! evidence: H7
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn f(v: VerifiedIdentity) -> VerifiedIdentity {
//!     /* a /* nested */ comment */ VerifiedIdentity { subject: String::new(), email: String::new(), name: None, groups: Vec::new(), issuer: String::new() }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn f(v: VerifiedIdentity) -> VerifiedIdentity {
//!     /* a /* nested */ comment */ v
//! }
//! ```
//!
//! evidence: H8
//!
//! ```compile_fail
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn checked(v: VerifiedIdentity) -> VerifiedIdentity {
//!     VerifiedIdentity { subject: String::new(), email: String::new(), name: None, groups: Vec::new(), issuer: String::new() }
//! }
//! ```
//!
//! ```
//! use mcp_gateway::key_server::oidc::VerifiedIdentity;
//! fn checked(v: VerifiedIdentity) -> VerifiedIdentity {
//!     v
//! }
//! ```

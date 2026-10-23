// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record key integration tests pass to `ResolvedAuthConfig::from_config`
//! (MIK-8697). A self-describing test value: never a deployment's key.

pub const RECORD_KEY: &str = "test-record-key-not-a-secret-0123456789abcdef";

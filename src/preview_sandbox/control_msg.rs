// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The control socket's messages, one JSON object per line. The gateway
//! (`control.rs`) and the sandbox helper (`linux/control_client.rs`) both
//! encode and parse these, so the two sides cannot drift apart. Every
//! message refuses unknown keys, and every flag must be `true`.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the fetch step, a later part, drives it")
)]

use serde::{Deserialize, Serialize};

/// The longest control line, its newline included.
pub(crate) const MAX_LINE: usize = 1024;

/// The helper's request for a fetch: `{"fetch_start":true}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchStart {
    pub(crate) fetch_start: bool,
}

/// The helper's report that the fetch ended: `{"fetch_done":true}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchDone {
    pub(crate) fetch_done: bool,
}

/// The gateway's answer to `fetch_start`: the fetch's proxy credential and
/// the milliseconds left to the fetch's deadline.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Issued {
    pub(crate) credential: String,
    pub(crate) deadline_ms: u128,
}

/// The gateway's answer to `fetch_done`, sent only once every tunnel of the
/// credential is shut: `{"expired":true}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expired {
    pub(crate) expired: bool,
}

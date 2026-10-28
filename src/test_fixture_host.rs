// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability fixture's host: a NAME that is not a loopback name, so it
//! clears the capability destination checks without `allow_loopback_egress`
//! (which turns the response cache off), and that a test-only client resolves
//! to the fixture's listener on `127.0.0.1`.
//!
//! Fixtures used `localhost` for this until loopback names were refused
//! before any lookup. Test-only: production has no client that
//! resolves a name without pinning it.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// The fixture host. `.test` is reserved (RFC 2606), so it never resolves
/// anywhere but through [`fixture_client`].
pub(crate) const FIXTURE_HOST: &str = "capability-fixture.test";

/// `http://<FIXTURE_HOST>:<port>`, the base URL of a fixture listening on
/// `127.0.0.1:<port>`.
pub(crate) fn fixture_url(port: u16) -> String {
    format!("http://{FIXTURE_HOST}:{port}")
}

/// A client with a finite `timeout` that resolves [`FIXTURE_HOST`] to
/// `127.0.0.1` (the URL's port is kept) and pins nothing else.
pub(crate) fn fixture_client(timeout: Duration) -> reqwest::Client {
    fixture_client_builder()
        .timeout(timeout)
        .build()
        .expect("the fixture HTTP client builds")
}

/// [`fixture_client`]'s builder, for a fixture that sets more options.
pub(crate) fn fixture_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().resolve(FIXTURE_HOST, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

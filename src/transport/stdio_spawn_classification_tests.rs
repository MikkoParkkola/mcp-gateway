// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::StdioTransport;
use crate::Error;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::test]
async fn a_missing_command_is_reported_as_permanent() {
    // END TO END, not a synthetic classifier input: this really tries to
    // spawn, so it pins the actual io::ErrorKind the OS returns rather than
    // the one this code assumes it returns.
    let transport = StdioTransport::new(
        "/nonexistent/definitely-not-a-real-binary",
        HashMap::new(),
        None,
        Duration::from_secs(1),
        None,
    );

    let err = transport
        .start()
        .await
        .expect_err("spawning a missing binary must fail");

    assert!(
        matches!(err, Error::TransportPermanent(_)),
        "a missing command must be permanent, got {err:?}"
    );
}

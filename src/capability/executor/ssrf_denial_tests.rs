// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A destination the SSRF pin refuses is a policy answer, not a network fault:
//! one attempt, `-32600 SSRF blocked`, and the backend stays healthy. An
//! ordinary resolution failure keeps the retry.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::client::{MAX_SEND_ATTEMPTS, send_with_retry};
use crate::security::ssrf::{HostResolver, PinningResolver};
use crate::{Error, Result};

/// Counts lookups; answers `answer`, or an I/O-style failure when `None`.
struct Counting {
    lookups: Arc<AtomicUsize>,
    answer: Option<IpAddr>,
}

impl HostResolver for Counting {
    fn lookup(&self, host: &str) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let answer = self.answer;
        let host = host.to_owned();
        Box::pin(async move {
            answer
                .map(|ip| vec![ip])
                .ok_or_else(|| Error::Protocol(format!("DNS resolution failed for '{host}'")))
        })
    }
}

fn pinned_client(answer: Option<IpAddr>) -> (reqwest::Client, Arc<AtomicUsize>) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let resolver = Counting {
        lookups: Arc::clone(&lookups),
        answer,
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(PinningResolver::new(resolver))
        .build()
        .unwrap();
    (client, lookups)
}

#[tokio::test]
async fn capability_ssrf_denial_is_not_retried() {
    let (client, lookups) = pinned_client(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    let health = crate::failsafe::HealthTracker::new("test");
    // Three calls: enough consecutive transport failures to flip the tracker
    // (`send_with_retry_records_transport_failures`), so a denial counted as
    // one would show.
    for call in 1..=3 {
        let request = client.get("http://private.test/");
        let error = send_with_retry(request, "test", true, &health)
            .await
            .expect_err("a private destination is refused");
        assert_eq!(error.to_rpc_code(), -32600, "call {call}: {error}");
        assert!(
            error.to_string().contains("SSRF blocked"),
            "call {call}: {error}"
        );
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            call,
            "one attempt per call, not {MAX_SEND_ATTEMPTS}"
        );
    }
    assert!(
        health.is_healthy(),
        "a policy refusal is not a backend fault"
    );
}

#[tokio::test]
async fn capability_connect_error_still_retried() {
    let (client, lookups) = pinned_client(None);
    let health = crate::failsafe::HealthTracker::new("test");
    let request = client.get("http://unresolvable.test/");
    let error = send_with_retry(request, "test", true, &health)
        .await
        .expect_err("resolution fails");
    assert_eq!(error.to_rpc_code(), -32000, "{error}");
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        MAX_SEND_ATTEMPTS as usize,
        "an ordinary failure keeps the retry"
    );
}

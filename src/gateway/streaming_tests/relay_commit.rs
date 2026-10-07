// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7939: a bridged prompt's relay receipt commits only when a stream
//! writes the prompt, once per prompt.

use super::*;

/// MIK-7939 D6.RELAY.5/.11: a bridged prompt's relay receipt commits when the
/// SSE stream writes it past the audit gate, never while it is only queued,
/// and never for a prompt the gate withholds (a tenant read whose record fails
/// closed). A receipt exempts the caller later, so it must name only text the
/// caller was shown.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_bridged_prompt_commits_only_when_the_stream_writes_it() {
    use crate::gateway::input_bridge::{ClientChannel, DeliveryCommit, DeliveryError};
    use crate::gateway::proxy::ProxyManager;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (_dir, log, multiplexer, id, mut body) = judged_sse();
    log.set_append_failure_for_test(true);
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let ask = |rid: &'static str, params: serde_json::Value| {
        let (proxy, id) = (Arc::clone(&proxy), id.clone());
        let commits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&commits);
        let commit = DeliveryCommit::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let sent = tokio::spawn(async move {
            proxy
                .send_request_committing(&id, rid, "elicitation/create", Some(params), Some(commit))
                .await
        });
        (sent, commits)
    };
    let (withheld, withheld_commits) = ask("withheld-prompt", json!({"customer_id": "cust-b"}));
    let (written, written_commits) = ask("written-prompt", json!({"message": "Proceed?"}));

    let mut seen = String::new();
    let read = async {
        while let Some(chunk) = body.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        }
    };
    let ended = tokio::select! {
        ended = tokio::time::timeout(Duration::from_secs(5), withheld) => ended,
        () = read => panic!("the stream ended"),
    };
    assert!(
        matches!(ended, Ok(Ok(Err(DeliveryError::TimedOut)))),
        "the tenant prompt was not withheld: {ended:?}"
    );
    while !seen.contains("written-prompt") {
        let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .expect("the written prompt reaches the stream")
            .expect("the stream is open");
        seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
    }
    assert!(!seen.contains("withheld-prompt"), "{seen}");
    assert!(
        log.append_attempts_for_test() >= 1,
        "the withheld prompt tried no record"
    );
    assert_eq!(
        withheld_commits.load(Ordering::SeqCst),
        0,
        "a withheld prompt committed its receipt"
    );
    assert_eq!(
        written_commits.load(Ordering::SeqCst),
        1,
        "a written prompt commits its receipt once"
    );
    written.abort();
}

/// MIK-7939: a second copy written while the first is still recording the
/// receipt waits for it, so no stream shows the prompt before it is recorded.
/// The record holds until the second copy has stopped at the lock
/// (`D6.RELAY.14`), so a slow runner cannot let it finish first and pass.
#[test]
fn a_second_written_copy_waits_for_the_receipt() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (started, done) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let (on_start, on_done) = (Arc::clone(&started), Arc::clone(&done));
    let watch = Arc::new(DeliveryWatch::default());
    let (reached, release) = watch.contended.arm();
    *watch.commit.lock() = Some(crate::gateway::input_bridge::DeliveryCommit::new(
        move || {
            on_start.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut second = std::pin::pin!(reached.notified());
            while futures::FutureExt::now_or_never(second.as_mut()).is_none() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the second copy never waited on the receipt"
                );
                std::thread::yield_now();
            }
            release.notify_one();
            on_done.store(true, Ordering::SeqCst);
        },
    ));
    watch.sent(2);
    let first = std::thread::spawn({
        let watch = Arc::clone(&watch);
        move || watch.report(true)
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the first written copy never recorded its receipt"
        );
        std::thread::yield_now();
    }
    watch.report(true);
    assert!(
        done.load(Ordering::SeqCst),
        "the second copy was written before the receipt was recorded"
    );
    first.join().unwrap();
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A probe answer that classifies as [`Era::Modern`].
fn modern_document() -> ProbeOutcome {
    ProbeOutcome::Result(serde_json::json!({
        "capabilities": {},
        "supportedVersions": ["2026-07-28"],
    }))
}

/// A restart swaps the peer, so a verdict about the peer it replaced must never be
/// what the restart reports — however fresh that verdict looks.
///
/// This is the reachable half of the guarantee. The other half — that a detached probe
/// of the previous peer cannot land *between* a restart's discard and its own probe —
/// is not test-reachable: the two used to be separate lock acquisitions with no await
/// between them, so the window opens only under a multi-threaded scheduler and closing
/// it was a structural change (one acquisition, not two) rather than a behavioural one.
/// A race test was written for it and passed against the pre-fix code, which is why it
/// is not here. What this pins is the property that made the window harmful: a restart
/// that found a determination would return it instead of probing.
#[tokio::test]
async fn a_restart_probes_the_new_peer_rather_than_reporting_the_old_verdict() {
    let cache = Arc::new(EraCache::for_backend("swapped-peer"));
    cache.resolve_with(|| async { modern_document() }).await;
    assert_eq!(cache.cached().await, Some(Era::Modern));

    let probes = AtomicUsize::new(0);
    let era = cache
        .restart_with(|| async {
            probes.fetch_add(1, Ordering::SeqCst);
            ProbeOutcome::Error(METHOD_NOT_FOUND_CODE)
        })
        .await;

    assert_eq!(probes.load(Ordering::SeqCst), 1, "the restart must probe");
    assert_eq!(
        era,
        Era::Legacy,
        "the restart must report what the peer now on the wire answered, not the \
         determination made about the process it replaced"
    );
    assert_eq!(cache.cached().await, Some(Era::Legacy));
}

/// Exactly one caller may discard a given determination.
///
/// This is the property the re-probe path spends: it spawns a probe only when
/// `discard_if` returns `true`, so a second answer contradicting the same verdict
/// must be told `false` rather than be handed a second licence to probe. The
/// concurrent interleaving itself is not test-reachable here for the same reason as
/// the restart above — the fix was structural — so what is pinned is the invariant
/// that makes the interleaving harmless.
#[tokio::test]
async fn only_the_caller_that_discards_a_verdict_is_told_it_did() {
    let cache = Arc::new(EraCache::for_backend("contradicted-peer"));
    cache.resolve_with(|| async { modern_document() }).await;

    assert!(
        !cache.discard_if(|_| false).await,
        "a verdict its observer does not contradict must survive"
    );
    assert_eq!(cache.cached().await, Some(Era::Modern));

    assert!(cache.discard_if(|era| era == Era::Modern).await);
    assert_eq!(cache.cached().await, None);
    assert!(
        !cache.discard_if(|_| true).await,
        "the second observer of the same contradiction must not be told it discarded \
         a determination that was already gone"
    );
}

/// An `install` that declines writes nothing and says why: the observation is exactly
/// what the contradiction left, and one record carries the reason and the probe's own fields.
#[test]
fn a_declined_install_writes_nothing_and_reports_why() {
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(async {
                let cache = EraCache::for_backend("swapped-mid-probe");
                let before = cache.observation().await;
                cache
                    .reprobe_with(|| async { modern_document() }, |_store| false)
                    .await;
                assert_eq!(cache.observation().await, before);
                assert_eq!(cache.cached().await, None);
            });
    });
    let discarded: Vec<_> = records
        .iter()
        .filter(|r| r["fields"]["reason"] == "transport_replaced")
        .collect();
    assert_eq!(discarded.len(), 1, "{records:?}");
    let fields = &discarded[0]["fields"];
    assert_eq!(fields["backend"], "swapped-mid-probe");
    assert_eq!(fields["evidence"], "discover_modern");
    assert_eq!(fields["trigger"], "reprobe");
    assert!(fields.get("duration_ms").is_some(), "{fields}");
    assert!(fields.get("outcome").is_some(), "{fields}");
    assert!(fields.get("error_code").is_none(), "{fields}");
}

/// An `install` that accepts stores through the closure it is given.
#[tokio::test]
async fn an_accepting_install_stores_the_answer() {
    let cache = EraCache::for_backend("still-in-service");
    let era = cache
        .reprobe_with(
            || async { modern_document() },
            |store| {
                store();
                true
            },
        )
        .await;
    assert_eq!(era, Era::Modern);
    assert_eq!(cache.cached().await, Some(Era::Modern));
}

/// MIK-8218 ERASNAP.1 and ERASNAP.3: the outbound path's non-blocking read
/// (`cached_now`) sees a determined verdict even while another holder has the
/// lock, as a parked `observation()` reader does. Cold start, a discard and a
/// restart's own probe still read undetermined, held or not.
#[tokio::test]
async fn a_held_lock_still_reads_the_determined_verdict() {
    let cache = Arc::new(EraCache::for_backend("held-lock"));
    assert_eq!(cache.cached_now(), None, "a cold start reads undetermined");

    cache.resolve_with(|| async { modern_document() }).await;
    {
        let _held = cache.observation.lock().await;
        assert_eq!(
            cache.cached_now(),
            Some(Era::Modern),
            "a held lock hid the determined verdict from the outbound path"
        );
    }

    let during = Arc::clone(&cache);
    cache
        .restart_with(|| async move {
            assert_eq!(during.cached_now(), None, "a restart probes undetermined");
            modern_document()
        })
        .await;
    assert_eq!(cache.cached_now(), Some(Era::Modern));

    cache.invalidate().await;
    let _held = cache.observation.lock().await;
    assert_eq!(cache.cached_now(), None, "a discard reads undetermined");
}

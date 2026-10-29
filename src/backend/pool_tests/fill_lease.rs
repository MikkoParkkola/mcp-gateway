// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.12 guard rows: a catalogue verdict that must FETCH (a stale
//! or a cold tools slot) still holds the pool lease for the fetch, so the idle
//! reaper cannot close the transport under it. Only a fresh slot, which fetches
//! nothing, answers without the lease (`backend::fresh_slot_tests`).

use super::*;
use crate::backend::CatalogueVerdict;
use tokio::sync::oneshot;

/// A transport whose `tools/list` parks until released, so a verdict's fetch
/// is genuinely in flight while the reaper sweeps.
struct ParkingList {
    started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    closed: AtomicBool,
}

#[async_trait]
impl Transport for ParkingList {
    async fn request(&self, method: &str, _p: Option<Value>) -> Result<JsonRpcResponse> {
        if method != "tools/list" {
            return Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({}),
            ));
        }
        if let Some(tx) = self.started.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let rx = self.release.lock().unwrap().take();
        if let Some(rx) = rx {
            let _ = rx.await;
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"tools": [tool()]}),
        ))
    }
    async fn notify(&self, _m: &str, _p: Option<Value>) -> Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn tool() -> Value {
    json!({
        "name": "search",
        "description": "probe",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
    })
}

/// Start a verdict that must fetch, and check the reaper declines while the
/// fetch is parked. `prepare` leaves the slot stale or cold.
async fn reaper_declines_during_the_fetch(prepare: impl FnOnce(&Backend), what: &str) {
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let transport = Arc::new(ParkingList {
        started: std::sync::Mutex::new(Some(started_tx)),
        release: std::sync::Mutex::new(Some(release_rx)),
        closed: AtomicBool::new(false),
    });
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(transport.clone());
    prepare(&backend);
    // Idle past the limit: only work in flight may keep it running.
    tokio::time::advance(Duration::from_secs(2)).await;

    let checking = Arc::clone(&backend);
    let check = tokio::spawn(async move {
        checking
            .catalogue_verdict(None, crate::transport::LentCredential::default(), "search")
            .await
    });
    let fetched = tokio::time::timeout(Duration::from_secs(5), started_rx).await;
    assert!(
        matches!(fetched, Ok(Ok(()))),
        "a {what} slot's verdict must fetch the list (MIK-8014 PERF.12)"
    );

    assert!(
        !backend.stop_if_idle().await,
        "the reaper must not stop a backend while a {what} slot's list fetch is in flight"
    );
    assert!(
        !transport.closed.load(Ordering::SeqCst),
        "the transport was closed under a {what} slot's list fetch"
    );

    let _ = release_tx.send(());
    let verdict = check.await.expect("the verdict task");
    assert_eq!(verdict.expect("verdict"), CatalogueVerdict::Offers);
}

/// Mutant: the fresh-slot answer extended to a stale slot (no fetch, no lease).
#[tokio::test(start_paused = true)]
async fn a_stale_slot_check_still_holds_the_transport() {
    reaper_declines_during_the_fetch(
        |backend| {
            backend.remember_listed_tools(None, false, &[tool()]);
            backend.age_tools_cache_for_test(None, 3600);
        },
        "stale",
    )
    .await;
}

/// Mutant: the fresh-slot answer taken when nothing is held (no fetch).
#[tokio::test(start_paused = true)]
async fn a_cold_slot_check_still_holds_the_transport() {
    reaper_declines_during_the_fetch(|_| {}, "cold").await;
}

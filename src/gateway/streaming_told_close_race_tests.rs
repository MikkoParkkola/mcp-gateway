// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 C0: a CF view closed inside Dead resolution gets no copy,
//! while a still-open view with the same dead caller keeps its closing
//! copy. A private descendant of the custody fixture: it reaches that
//! fixture's private fields and helpers with no wider visibility.

use super::*;
use tokio::sync::broadcast::error::TryRecvError;

/// Delegates every judgement to the real `CfJudge`. When that judge
/// returns a genuine `Dead`, the wrapper drops the sole stream view it
/// owns in the same resolver poll, before returning the unchanged
/// verdict, so closure lands between resolution and enqueue.
struct ClosingJudge {
    inner: Arc<CfJudge>,
    view: parking_lot::Mutex<Option<StreamView>>,
    observed_dead: AtomicUsize,
}

impl ViewJudge for ClosingJudge {
    fn resolve<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(async move {
            let verdict = self.inner.resolve(auth, caller).await;
            if matches!(verdict, Judged::Dead(_)) {
                self.observed_dead.fetch_add(1, Ordering::SeqCst);
                let owned = self.view.lock().take();
                drop(owned);
            }
            verdict
        })
    }

    fn digest(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
        backend: &str,
    ) -> ViewDigest {
        self.inner.digest(caller, subject, session_id, backend)
    }

    fn baseline(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
    ) -> HashMap<String, ViewDigest> {
        self.inner.baseline(caller, subject, session_id)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_cf_view_closed_inside_dead_resolution_gets_no_copy() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (mut fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let wrapper = ClosingJudge {
        inner: Arc::clone(&fixture.judge),
        view: parking_lot::Mutex::new(Some(view)),
        observed_dead: AtomicUsize::new(0),
    };
    fixture.revoke_bearer();
    let reached = match tokio::time::timeout(
        WITHIN,
        fixture
            .mux
            .broadcast_to_backend_judged(&hint(), BACKEND, &wrapper),
    )
    .await
    {
        Ok(reached) => reached,
        Err(elapsed) => panic!("VOID: judged broadcast timed out after {WITHIN:?}: {elapsed}"),
    };
    std::assert_eq!(
        wrapper.observed_dead.load(Ordering::SeqCst),
        1,
        "VOID: the genuine Dead resolution must be observed exactly once"
    );
    std::assert_eq!(
        reached,
        0,
        "a CF view closed inside Dead resolution must get no copy"
    );
    let CustodyFixture { _bare: bare, .. } = &mut fixture;
    std::assert!(
        matches!(bare.try_recv(), Err(TryRecvError::Empty)),
        "the closed view's bare receiver must hold no copy"
    );
    std::assert!(
        fixture.primary.all_owners_dead(),
        "closing inside Dead resolution must drop every raw subject owner"
    );
    fixture.assert_session_retained();
}

#[tokio::test(flavor = "current_thread")]
async fn a_still_open_cf_view_with_a_dead_caller_gets_its_closing_copy() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (mut fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let mut body = fixture.body(view);
    body.expect_connected().await;
    let wrapper = ClosingJudge {
        inner: Arc::clone(&fixture.judge),
        view: parking_lot::Mutex::new(None),
        observed_dead: AtomicUsize::new(0),
    };
    fixture.revoke_bearer();
    let reached = match tokio::time::timeout(
        WITHIN,
        fixture
            .mux
            .broadcast_to_backend_judged(&hint(), BACKEND, &wrapper),
    )
    .await
    {
        Ok(reached) => reached,
        Err(elapsed) => panic!("VOID: judged broadcast timed out after {WITHIN:?}: {elapsed}"),
    };
    std::assert_eq!(
        wrapper.observed_dead.load(Ordering::SeqCst),
        1,
        "VOID: the genuine Dead resolution must be observed exactly once"
    );
    std::assert_eq!(
        reached,
        1,
        "a still-open CF view with a dead caller must get its closing copy"
    );
    let CustodyFixture { _bare: bare, .. } = &mut fixture;
    match bare.try_recv() {
        Ok(frame) => std::assert_eq!(
            frame.data["method"],
            serde_json::json!("notifications/tools/list_changed"),
            "the bare copy is not the tools/list_changed hint: {}",
            frame.data
        ),
        Err(error) => panic!("the bare receiver held no closing copy: {error:?}"),
    }
    fixture.primary.assert_original_live();
    match body.next().await {
        Frame::Eof => {}
        Frame::Message(frame) => {
            panic!("VOID: the dead caller's stream wrote a frame instead of closing: {frame}")
        }
    }
    std::assert!(
        fixture.primary.all_owners_dead(),
        "the write-time Dead close must drop every raw subject owner"
    );
    fixture.assert_session_retained();
}

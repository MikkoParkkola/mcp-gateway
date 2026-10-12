// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows on a stream's write-time decision (MIK-8350 D17).

use super::*;

fn auth() -> AuthState {
    AuthState {
        auth_config: Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
            &crate::config::AuthConfig::default(),
        )),
        key_server: None,
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
    }
}

/// A judge that answers with whatever it was last told to.
struct Fake(parking_lot::Mutex<Option<ViewDigest>>);

impl Fake {
    fn answering(served: &str, shown: &str) -> Arc<Self> {
        let judge = Arc::new(Self(parking_lot::Mutex::new(None)));
        judge.say(served, shown);
        judge
    }

    fn say(&self, served: &str, shown: &str) {
        *self.0.lock() = Some(ViewDigest {
            served: served.to_owned(),
            shown: shown.to_owned(),
        });
    }

    fn die(&self) {
        *self.0.lock() = None;
    }
}

impl ViewJudge for Fake {
    fn resolve<'a>(
        &'a self,
        _: &'a AuthState,
        _: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(async move {
            if self.0.lock().is_none() {
                return Judged::Dead(DeadReason::Bearer);
            }
            Judged::Live(ResolvedCaller {
                client: crate::gateway::auth::anonymous_client(),
                identity: None,
                agent: None,
            })
        })
    }

    fn digest(&self, _: &ResolvedCaller, _: &ViewSubject, _: &str, _: &str) -> ViewDigest {
        self.0.lock().clone().expect("a live fake answers")
    }

    fn baseline(
        &self,
        _: &ResolvedCaller,
        _: &ViewSubject,
        _: &str,
    ) -> HashMap<String, ViewDigest> {
        HashMap::new()
    }
}

fn view(judge: &Arc<Fake>) -> StreamView {
    let view = StreamView {
        subject: Arc::new(ViewSubject::default()),
        record: Arc::new(ViewRecord::default()),
        judge: Arc::clone(judge) as Arc<dyn ViewJudge>,
    };
    // Stamp 0: the record's own reads start at 1, as they do after an attach.
    view.record.state().baseline(
        0,
        HashMap::from([(
            "a".to_owned(),
            ViewDigest {
                served: "s0".to_owned(),
                shown: "x".to_owned(),
            },
        )]),
    );
    view
}

#[tokio::test]
async fn a_caller_that_no_longer_resolves_closes_the_stream() {
    let judge = Fake::answering("s0", "x");
    let view = view(&judge);
    judge.die();
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Close);
}

#[tokio::test]
async fn a_view_that_returned_to_what_it_was_told_is_not_written() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    // The fan-out saw a moved view; by the time the stream writes, it is
    // back where the caller was told.
    judge.say("s0", "x");
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Skip);
}

#[tokio::test]
async fn two_copies_of_one_moved_view_are_written_once() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Write);
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Skip);
}

#[tokio::test]
async fn a_commit_read_before_a_newer_write_is_refused() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    let auth = auth();
    let Judged::Live(Some(older)) = view.owed(&auth, None, "", "a").await else {
        panic!("the first read is owed");
    };
    judge.say("s2", "x3");
    let Judged::Live(Some(newer)) = view.owed(&auth, None, "", "a").await else {
        panic!("the second read is owed");
    };
    assert!(view.commit(&newer));
    assert!(!view.commit(&older), "the slow reader must not roll back");
}

#[tokio::test]
async fn a_read_gets_its_stamp_only_when_it_holds_the_gate() {
    let record = Arc::new(ViewRecord::default());
    let held = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let first = {
        let (record, held, release) =
            (Arc::clone(&record), Arc::clone(&held), Arc::clone(&release));
        tokio::spawn(async move {
            record
                .read(async {
                    held.notify_one();
                    release.notified().await;
                })
                .await
                .0
        })
    };
    held.notified().await;
    let second = {
        let record = Arc::clone(&record);
        tokio::spawn(async move { record.read(async {}).await.0 })
    };
    // The second read cannot start while the first is mid-capture.
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "the gate was not held across the capture"
    );
    release.notify_one();
    let (a, b) = (first.await.expect("first"), second.await.expect("second"));
    assert!(a < b, "stamp order is capture order: {a} then {b}");
}

/// R14 (D17h): a listing the caller never got is not recorded as told, so the
/// change it hid is still owed; a delivered one is recorded.
#[test]
fn a_withheld_listing_leaves_the_record_alone_and_a_delivered_one_moves_it() {
    let moved = ViewDigest {
        served: "s1".to_owned(),
        shown: "x2".to_owned(),
    };
    let held = |record: &Arc<ViewRecord>| {
        PendingRefresh(Some((
            Arc::clone(record),
            5,
            HashMap::from([("a".to_owned(), moved.clone())]),
        )))
    };
    let judge = Fake::answering("s0", "x");
    let withheld = view(&judge);
    held(&withheld.record).settle(false);
    assert_eq!(
        withheld.record.state().peek(6, "a", &moved),
        Peek::Owed,
        "the withheld listing must not have told the caller"
    );

    let delivered = view(&judge);
    held(&delivered.record).settle(true);
    assert_eq!(delivered.record.state().peek(6, "a", &moved), Peek::Quiet);
}

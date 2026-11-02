// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Hides the names it was given, counting its judgments.
struct Hides(&'static [&'static str], AtomicUsize);

impl CallerHiding for Hides {
    fn hides(&self, server: &str) -> bool {
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.contains(&server)
    }
}

fn hides(names: &'static [&'static str]) -> Arc<Hides> {
    Arc::new(Hides(names, AtomicUsize::new(0)))
}

/// A read with no caller installed hides nothing: it cannot judge with an
/// identity it does not have.
#[tokio::test]
async fn no_caller_hides_nothing() {
    assert!(!hidden("beta"));
    with_caller_slot(async { assert!(!hidden("beta")) }).await;
}

/// The intake's caller is judged on each lookup, live.
#[tokio::test]
async fn a_recorded_caller_is_judged_on_every_lookup() {
    let caller = hides(&["beta"]);
    let judged = Arc::clone(&caller);
    with_caller_slot(async move {
        record_caller(judged);
        assert!(hidden("beta"));
        assert!(hidden("beta"));
        assert!(!hidden("alpha"));
    })
    .await;
    assert_eq!(caller.1.load(Ordering::Relaxed), 3, "a judgment was cached");
}

/// A later record cannot replace the caller a request began with.
#[tokio::test]
async fn the_first_caller_wins() {
    with_caller_slot(async {
        record_caller(hides(&["beta"]));
        record_caller(hides(&[]));
        assert!(hidden("beta"));
    })
    .await;
}

/// A worker run judges as the caller it carries.
#[tokio::test]
async fn a_worker_run_judges_as_its_caller() {
    with_caller(hides(&["beta"]), async { assert!(hidden("beta")) }).await;
}

/// A judgment that looks a name up again is not judged a second time.
#[tokio::test]
#[cfg_attr(debug_assertions, should_panic(expected = "re-entered"))]
async fn a_judgment_cannot_re_enter_itself() {
    struct Reenters;
    impl CallerHiding for Reenters {
        fn hides(&self, server: &str) -> bool {
            hidden(server)
        }
    }
    with_caller(Arc::new(Reenters), async { assert!(!hidden("beta")) }).await;
}

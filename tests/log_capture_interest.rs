// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8254: a scoped ERROR capture must see a line whose callsite another
//! thread reached first with no subscriber.
//!
//! Its own binary on purpose: the defect needs a process in which the
//! capture is the only registered dispatcher. tracing-core then rebuilds a
//! newly registered callsite's interest from the registering thread's default
//! alone (`Rebuilder::JustOne`), so a first hit on a thread with no subscriber
//! caches the callsite as `never`, and the capture never sees it.

#[path = "../src/test_support/error_capture.rs"]
mod error_capture;

fn the_probe_line() {
    tracing::error!("mik-8254 probe line");
}

#[test]
fn a_capture_sees_a_callsite_another_thread_reached_first() {
    let logged = error_capture::errors_logged(|| {
        // The first hit of the callsite, on a thread with no subscriber.
        std::thread::spawn(the_probe_line)
            .join()
            .expect("the other thread");
        the_probe_line();
    });
    assert!(
        logged.contains("mik-8254 probe line"),
        "the capture lost a line another thread reached first: {logged:?}"
    );
}

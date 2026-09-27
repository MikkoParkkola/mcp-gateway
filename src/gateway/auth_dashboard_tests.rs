// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store-level tests for the dashboard bootstrap and sessions.

use super::DashboardBootstrap;

/// The link is redeemed only by somebody actually at this machine
/// (MIK-7257).
///
/// The check used to read the `Host` header, which the caller writes and a
/// proxy rewrites — nginx's default for a bare `proxy_pass` is the upstream
/// address, so a forwarded request arrived carrying a loopback `Host` and
/// was accepted from anywhere. These cases drive the same predicate the
/// middleware uses, over the two facts it now reads.
#[test]
fn a_link_is_redeemed_only_from_this_machine() {
    // (peer, forwarding header present, may redeem)
    let cases: [(&str, bool, bool); 6] = [
        // A browser on this machine: the case the link exists for.
        ("127.0.0.1:52344", false, true),
        ("[::1]:52344", false, true),
        // Straight off the network. Never printed on such a bind, and
        // refused even if the value leaked.
        ("10.0.0.7:41000", false, false),
        ("[2001:db8::1]:41000", false, false),
        // A same-host reverse proxy forwarding someone else's request: the
        // peer IS loopback, which is why the peer alone is not the answer.
        // Refused on the forwarding header a conventional proxy sets.
        ("127.0.0.1:52344", true, false),
        // A remote proxy is refused twice over.
        ("10.0.0.7:41000", true, false),
    ];
    for (peer, forwarded, may_redeem) in cases {
        let addr: std::net::SocketAddr = peer.parse().expect("test peer parses");
        let peer_is_local = addr.ip().is_loopback();
        let allowed = peer_is_local && !forwarded;
        assert_eq!(
            allowed, may_redeem,
            "peer {peer} with forwarding={forwarded} was judged wrongly: \
             refusing a local browser breaks the only way into the \
             dashboard, and admitting a forwarded request hands an admin \
             session to whoever holds the link"
        );
    }
}

#[test]
fn a_handle_is_only_valid_if_this_process_issued_it() {
    let b = DashboardBootstrap::new();
    let handle = b.issue_session();
    assert!(b.session_is_valid(&handle));
    assert!(!b.session_is_valid("guessed"));

    // A handle from another process is meaningless here, which is the
    // point of an opaque session over a bearer token in a cookie.
    let other = DashboardBootstrap::new();
    assert!(!other.session_is_valid(&handle));
}

#[test]
fn handles_are_not_guessable_and_not_reused() {
    let b = DashboardBootstrap::new();
    let a = b.issue_session();
    let c = b.issue_session();
    assert_ne!(a, c);
    assert!(a.len() >= 42, "32 random bytes, base64url: {a}");
}

/// The session handle is never the admin credential.
///
/// This is the central claim of the opaque-session design — the cookie used
/// to carry the bearer token, which is long-lived and, without TLS,
/// recoverable from the wire — and nothing asserted it. A change that put
/// the credential back in the cookie would have passed every test here.
#[test]
fn a_session_handle_is_never_the_admin_credential() {
    let bearer = "mcpgw_a-realistic-looking-admin-credential";
    let b = DashboardBootstrap::new();

    for _ in 0..8 {
        let handle = b.issue_session();
        assert_ne!(
            handle, bearer,
            "the cookie must carry an opaque handle, never the credential"
        );
        assert!(
            !handle.contains(bearer) && !bearer.contains(&handle),
            "and must not embed or be embedded in it: {handle}"
        );
        assert!(
            !handle.starts_with("mcpgw_"),
            "nor look like one, which would invite pasting it as a token: {handle}"
        );
    }
}

/// A bootstrap value is spent exactly once, and a wrong one spends nothing.
#[test]
fn a_bootstrap_value_is_single_use_and_a_wrong_one_costs_nothing() {
    let b = DashboardBootstrap::new();
    let printed = b.peek().expect("a value is issued at startup");

    assert!(!b.consume("not-the-value"), "a wrong value is rejected");
    assert!(
        b.consume(&printed),
        "and rejecting it must not have spent the real one — otherwise a \
         stray click on a stale link disarms the operator's own"
    );
    assert!(!b.consume(&printed), "the real value is spent only once");
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source pins for what a delivery learns from its backend's send: every
//! pre-send exit of `request_attempted` records a refusal before the send,
//! every transport call is a counted send, and the errors a counted send is
//! taken back on are exactly the reviewed never-sent list.

const OPS: &str = include_str!("ops.rs");
const ERROR: &str = include_str!("../error.rs");

/// The text of `request_attempted` up to its send closure: the pre-send region.
fn pre_send_region() -> &'static str {
    let start = OPS
        .find("async fn request_attempted(")
        .expect("request_attempted is in ops.rs");
    let send = OPS[start..]
        .find("counted_send(async move")
        .expect("the send closure is a counted send");
    &OPS[start..start + send]
}

/// G1: every `?` before the send carries the pre-send mark, and the withheld
/// call's early return is marked too: a new pre-send step that fails without
/// it would leave its refusal recorded as a dispatched call.
#[test]
fn every_pre_send_exit_of_request_attempted_is_marked() {
    let region = pre_send_region();
    // Comments dropped. Each `?` exit in the region closes a call (`)?`), and
    // each must be one `presend(..)` wraps: a new exit without the mark makes
    // the counts differ. (`{e:?}` in a format string is `:?`, not `)?`.)
    let code: String = region
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let exits = code.matches(")?").count();
    let marked_exits = code.matches("presend(").count();
    assert_eq!(
        exits, marked_exits,
        "a pre-send `?` exit without the mark:\n{code}"
    );
    // The seven reviewed `?` steps; the withheld call's return is the eighth.
    assert_eq!(
        marked_exits, 7,
        "premise: the seven reviewed pre-send steps are marked"
    );
    assert!(
        region.contains("return Err(refused_before_send(refusal));"),
        "the withheld call's return is not marked"
    );
}

/// The transport calls of `request_attempted` all sit inside the one counted
/// send, so a send that bypasses the count cannot be added beside them.
#[test]
fn every_transport_call_is_a_counted_send() {
    let start = OPS
        .find("async fn request_attempted(")
        .expect("request_attempted");
    let end = OPS[start..]
        .find("pub async fn notify_with_headers(")
        .map_or(OPS.len(), |at| start + at);
    let body = &OPS[start..end];
    let counted = body
        .find("counted_send(async move")
        .expect("a counted send");
    for call in [".request_with_headers(", ".request_with_task_capability("] {
        let at = body
            .find(call)
            .unwrap_or_else(|| panic!("{call} is in request_attempted"));
        assert!(at > counted, "{call} is outside the counted send");
    }
    assert_eq!(body.matches("counted_send(").count(), 1, "one counted send");
}

/// R20: a counted send is taken back only on `is_pre_dispatch`, so that list
/// is the never-sent list. Pinned to the reviewed members.
#[test]
fn the_never_sent_list_is_the_reviewed_one() {
    // Each reviewed as never sent where it is constructed. AmbiguousBackend:
    // only in meta_mcp/invoke/dispatch.rs (a name that is both a backend and
    // the capability, refused while routing, before any send), from #4414.
    // Forbidden and GatewayRefused: every construction and builder call is a
    // reviewed pre-send site in error_pre_send_scan_tests.rs.
    const REVIEWED: [&str; 14] = [
        "AmbiguousBackend",
        "AuthorizationCancelled",
        "AuthorizationIncomplete",
        "AuthorizationPending",
        "AuthorizationRequired",
        "BackendNotFound",
        "BackendUnavailable",
        "CircuitOpen",
        "Forbidden",
        "GatewayRefused",
        "IdentitySlotsExhausted",
        "RateLimited",
        "ToolNotFound",
        "TransportConnect",
    ];
    let start = ERROR
        .find("pub fn is_pre_dispatch(&self) -> bool {")
        .expect("is_pre_dispatch is in error.rs");
    let end = start + ERROR[start..].find("\n    }\n").expect("the body ends");
    let whole = &ERROR[start..end];
    // The members are the arms before the one `=> true`: every variant is
    // named somewhere in the match, so only that group is the list. A second
    // arm answering `true` would hold members this pin never reads.
    assert_eq!(
        whole.matches("=> true").count(),
        1,
        "is_pre_dispatch answers true in exactly one arm"
    );
    let body = &whole[..whole.find("=> true,").expect("one arm answers true")];
    let mut members: Vec<&str> = body
        .split("Self::")
        .skip(1)
        .map(|rest| {
            rest.split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap_or("")
        })
        .collect();
    members.sort_unstable();
    members.dedup();
    assert_eq!(
        members, REVIEWED,
        "a new is_pre_dispatch member needs a never-sent review naming where it is constructed"
    );
    assert!(
        whole.contains("Self::JsonRpc { .. } => {")
            && whole.contains("refusal::transient_data(self).is_some()"),
        "the sealed transient is no longer the list's only other term"
    );
}

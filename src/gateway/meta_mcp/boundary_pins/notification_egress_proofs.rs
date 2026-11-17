// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The notification egress pin's own proof: each rule, broken in turn,
//! fails the pin.

use super::*;

/// What a broken legacy SSE map proof reports.
const MAPBY: &str = "stored map unapplied, unscrubbed or built elsewhere: HttpTransport listen";

/// The pin's own proof: a new transport, a new sink anywhere it counts, and
/// a new channel send fail; an outbound HTTP `send()` does not.
#[test]
fn a_new_transport_sink_or_send_fails() {
    let mut scan = scanned();
    scan.transports.insert("FakeTransport".to_owned());
    assert!(
        fails_with(&scan, "unlisted transport: FakeTransport"),
        "a new transport passed"
    );
    let cases: [(&str, syn::Block, &str); 8] = [
        (
            "src/gateway/fake.rs",
            syn::parse_quote!({
                crate::transport::notification_sink::publish(vec![note]);
            }),
            "publish",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                publish(vec![note]);
            }),
            "bare publish",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                destination.deliver(note);
            }),
            "deliver",
        ),
        (
            "src/backend/fake.rs",
            syn::parse_quote!({
                tx.try_send(note);
            }),
            "send",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                DeliveryHandle::deliver(&destination, note);
            }),
            "deliver",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                tokio::sync::mpsc::Sender::try_send(&tx, note);
            }),
            "send",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                tokio::select! { _ = a => { DeliveryHandle::deliver(&destination, note); } }
            }),
            "deliver",
        ),
        (
            "src/transport/fake.rs",
            syn::parse_quote!({
                tokio::select! { _ = a => { Sender::try_send(&tx, note); } }
            }),
            "send",
        ),
    ];
    for (file, block, kind) in &cases {
        let scan = with(scanned(), file, "fake", block);
        assert!(
            fails_with(&scan, &format!("unlisted sink: {file}::fake ({kind})")),
            "a new {kind} in {file} passed"
        );
    }
    let hidden = with(
        scanned(),
        "src/transport/fake.rs",
        "fake",
        &syn::parse_quote!({
            tokio::select! {
                note = rx.recv() => { tx.send(note).await; }
            }
        }),
    );
    assert!(
        fails_with(&hidden, "unlisted sink: src/transport/fake.rs::fake (send)"),
        "a channel send inside a macro passed"
    );
    let outbound = with(
        scanned(),
        "src/transport/fake.rs",
        "fake",
        &syn::parse_quote!({
            client.get(url).send().await;
        }),
    );
    assert!(
        !fails_with(&outbound, "unlisted sink: src/transport/fake.rs::fake"),
        "an outbound request was read as a channel send"
    );
}

/// The pin's own proof: a scrub moved after its sink, a scrubber that no
/// longer scrubs, and a second caller of a scrubbed hop each fail.
#[test]
fn a_late_scrub_or_a_second_caller_fails() {
    let late = replaced(
        scanned(),
        "src/transport/http/sse_decoder.rs",
        "drain_events",
        &syn::parse_quote!({
            crate::transport::notification_sink::publish(vec![note]);
            let _ = withheld(needles, &mut message);
        }),
    );
    assert!(
        fails_with(&late, "scrub not before sink: HttpTransport http-stream"),
        "a scrub after its sink passed"
    );
    let unscrubbed = replaced(
        scanned(),
        "src/transport/stdio.rs",
        "handle_response",
        &syn::parse_quote!({
            self.capture_notification(notification, None);
        }),
    );
    let second = with(
        scanned(),
        "src/transport/stdio_fake.rs",
        "relay",
        &syn::parse_quote!({
            transport.capture_notification(notification, None);
        }),
    );
    for (scan, case) in [(unscrubbed, "a lost scrub"), (second, "a second caller")] {
        assert!(
            fails_with(
                &scan,
                "scrubber does not scrub first, or another function calls it: StdioTransport stdio"
            ),
            "{case} passed"
        );
    }
}

/// The pin's own proof: a helper that stops scrubbing, a literal `None`
/// needle set, and a stored map built outside its scrubber each fail.
#[test]
fn a_hollow_helper_a_none_needle_set_or_a_stray_map_fails() {
    let hollow = replaced(
        scanned(),
        "src/transport/upstream_tap.rs",
        "scrub_note",
        &syn::parse_quote!({ Some(note) }),
    );
    assert!(
        fails_with(&hollow, "helper reaches no needle scrub: scrub_note"),
        "a hollow helper passed"
    );
    for block in [
        syn::parse_quote!({
            taps.notification_keyed(method, keys, None);
        }),
        syn::parse_quote!({
            let _ = scrub_note(None, note);
        }),
        syn::parse_quote!({
            let _ = scrub_note(Option::None, note);
        }),
        syn::parse_quote!({
            tokio::select! { _ = a => { let _ = scrub_note(Option::None, note); } }
        }),
    ] {
        let scan = with(scanned(), "src/transport/fake.rs", "fake", &block);
        assert!(
            fails_with(&scan, "a None needle set: src/transport/fake.rs::fake"),
            "a None needle set passed"
        );
    }
    stray_map_cases();
}

/// The stored-map half of the test above, split out for length: a legacy
/// SSE route that bypasses its stored map, sends past its result, or whose
/// map is built elsewhere or scrubs outside the closure, fails.
fn stray_map_cases() {
    let stray = with(
        scanned(),
        "src/transport/http/fake.rs",
        "fake",
        &syn::parse_quote!({
            let sink = Sink {
                tx,
                map: Box::new(move |data| unsolicited_frame(data)),
            };
        }),
    );
    assert!(fails_with(&stray, MAPBY), "a map built elsewhere passed");
    let unscrubbed_map = replaced(
        scanned(),
        "src/transport/http/sse_listen.rs",
        "handshake",
        &syn::parse_quote!({
            let needles = t.needles.get().cloned();
            let _ = scrubbed(needles.as_deref(), probe);
            let sink = Sink {
                tx,
                map: Box::new(move |data| unsolicited_frame(data)),
            };
        }),
    );
    assert!(
        fails_with(&unscrubbed_map, MAPBY),
        "a scrub beside the map, not inside it, passed"
    );
    let bypassed = replaced(
        scanned(),
        "src/transport/http/sse_channel.rs",
        "route",
        &syn::parse_quote!({
            if let Some(note) = unsolicited_frame(&event.data) {
                let _ = open.tx.try_send(note);
            }
        }),
    );
    assert!(
        fails_with(&bypassed, MAPBY),
        "a route bypassing its map passed"
    );
    let discarded_result = replaced(
        scanned(),
        "src/transport/http/sse_channel.rs",
        "route",
        &syn::parse_quote!({
            let _ = (open.map)(&event.data);
            if let Some(note) = unsolicited_frame(&event.data) {
                let _ = open.tx.try_send(note);
            }
        }),
    );
    assert!(
        fails_with(&discarded_result, MAPBY),
        "a route sending past its map's result passed"
    );
    let scrub_outside_closure = replaced(
        scanned(),
        "src/transport/http/sse_listen.rs",
        "handshake",
        &syn::parse_quote!({
            let sink = Sink {
                tx,
                map: {
                    let _ = scrubbed(needles.as_deref(), probe);
                    Box::new(move |data| unsolicited_frame(data))
                },
            };
        }),
    );
    assert!(
        fails_with(&scrub_outside_closure, MAPBY),
        "a scrub in the initializer, outside the closure, passed"
    );
}

/// The pin's own proof: a per-backend route that keeps or reads its
/// notifications fails, while one that drops them to `_` passes.
#[test]
fn a_direct_route_that_keeps_its_notifications_fails() {
    let kept: [syn::Block; 3] = [
        syn::parse_quote!({
            let (response, notifications) =
                crate::transport::notification_sink::collect(None, call).await;
            forward(notifications);
        }),
        syn::parse_quote!({
            let (response, _) = crate::transport::notification_sink::collect(None, first).await;
            let kept = crate::transport::notification_sink::collect(None, second).await;
        }),
        syn::parse_quote!({
            let (response, _discarded) =
                crate::transport::notification_sink::collect(None, call).await;
            tracing::debug!(?_discarded);
        }),
    ];
    for block in &kept {
        let scan = replaced(scanned(), DIRECT.0, DIRECT.1, block);
        assert!(
            fails_with(&scan, "keeps its notifications"),
            "a kept notification passed"
        );
    }
    let dropped = replaced(
        scanned(),
        DIRECT.0,
        DIRECT.1,
        &syn::parse_quote!({
            let (response, _) = crate::transport::notification_sink::collect(None, call).await;
        }),
    );
    assert!(
        !fails_with(&dropped, "keeps its notifications"),
        "a dropped notification failed"
    );
}

/// The pin's own proof: a reviewed send row whose send is gone fails.
#[test]
fn a_stale_send_row_fails() {
    let rows = format!("{SENDS}src/transport/fake.rs\tgone\tinternal\tremoved since\n");
    assert!(
        differences(&scanned(), &rows)
            .iter()
            .any(|line| line == "stale send row: src/transport/fake.rs::gone"),
        "a stale send row passed"
    );
}

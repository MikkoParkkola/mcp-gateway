// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows of design §10 for the tap projection: the tag filter, the
//! 2 048-byte URI drop, the acknowledgement intersected with the request,
//! and the response-as-ack compatibility shape.

use serde_json::{Value, json};

use super::*;

fn requested() -> Requested {
    Requested {
        kinds: KindSet {
            resources_changed: true,
            prompts_changed: false,
            tools_changed: false,
        },
        uris: vec!["file:///a".into(), "file:///b".into()],
    }
}

fn tag(id: &Value, mut params: Value) -> Value {
    params["_meta"] = json!({ SUBSCRIPTION_ID: id });
    params
}

#[test]
fn modern_frames_need_the_listen_tag() {
    let id = json!(7);
    let r = requested();
    let listen = Some((&id, &r));
    let ok = tag(&id, json!({"uri": "file:///a"}));
    assert_eq!(
        project(UPDATED, Some(&ok), listen),
        Ok(UpstreamNote::Notice {
            kind: NoteKind::ResourceUpdated,
            uri: Some("file:///a".into())
        })
    );
    let other = tag(&json!(8), json!({"uri": "file:///a"}));
    assert_eq!(
        project(UPDATED, Some(&other), listen),
        Err(Dropped::Untagged)
    );
    let bare = json!({"uri": "file:///a"});
    assert_eq!(
        project(UPDATED, Some(&bare), listen),
        Err(Dropped::Untagged)
    );
    assert_eq!(
        project(PROMPTS_CHANGED, None, listen),
        Err(Dropped::Untagged)
    );
    // The string "7" is not the number 7.
    let stringly = tag(&json!("7"), json!({}));
    assert_eq!(
        project(RESOURCES_CHANGED, Some(&stringly), listen),
        Err(Dropped::Untagged)
    );
}

#[test]
fn legacy_frames_carry_no_tag_and_no_ack() {
    assert_eq!(
        project(RESOURCES_CHANGED, None, None),
        Ok(UpstreamNote::Notice {
            kind: NoteKind::ResourcesChanged,
            uri: None
        })
    );
    assert_eq!(project(ACKNOWLEDGED, None, None), Err(Dropped::Other));
    assert_eq!(
        project("notifications/message", None, None),
        Err(Dropped::Other)
    );
}

#[test]
fn an_oversize_or_missing_uri_is_dropped() {
    let long = format!("file:///{}", "x".repeat(MAX_URI_BYTES));
    assert_eq!(
        project(UPDATED, Some(&json!({"uri": long})), None),
        Err(Dropped::Oversize)
    );
    let edge = "x".repeat(MAX_URI_BYTES);
    assert!(project(UPDATED, Some(&json!({"uri": edge})), None).is_ok());
    assert_eq!(
        project(UPDATED, Some(&json!({})), None),
        Err(Dropped::Oversize)
    );
    assert_eq!(
        project(UPDATED, Some(&json!({"uri": 5})), None),
        Err(Dropped::Oversize)
    );
}

#[test]
fn the_ack_is_cut_to_what_was_asked() {
    let id = json!(7);
    let r = requested();
    let acked = tag(
        &id,
        json!({"notifications": {
            "resourcesListChanged": true,
            "promptsListChanged": true,
            "resourceSubscriptions": ["file:///a", "file:///zzz"],
        }}),
    );
    assert_eq!(
        project(ACKNOWLEDGED, Some(&acked), Some((&id, &r))),
        Ok(UpstreamNote::Ack {
            kinds: KindSet {
                resources_changed: true,
                prompts_changed: false,
                tools_changed: false,
            },
            uris: vec!["file:///a".into()],
        }),
        "prompts were not asked for, b was omitted, zzz was never asked"
    );
    let empty = tag(&id, json!({}));
    assert_eq!(
        project(ACKNOWLEDGED, Some(&empty), Some((&id, &r))),
        Ok(UpstreamNote::Ack {
            kinds: KindSet::default(),
            uris: vec![]
        })
    );
}

#[test]
fn only_the_exact_first_frame_response_is_an_ack() {
    let id = json!(7);
    let r = requested();
    let shape = json!({"_meta": { SUBSCRIPTION_ID: 7 }});
    assert_eq!(
        classify_response(true, &id, Some(&shape), None, &r),
        r.as_full_ack()
    );
    assert_eq!(
        classify_response(false, &id, Some(&shape), None, &r),
        UpstreamNote::End
    );
    for other in [
        json!({"_meta": { SUBSCRIPTION_ID: 8 }}),
        json!({"_meta": { SUBSCRIPTION_ID: 7 }, "resultType": "complete"}),
        json!({"_meta": { SUBSCRIPTION_ID: 7, "x": 1 }}),
        json!({}),
        json!(null),
    ] {
        assert_eq!(
            classify_response(true, &id, Some(&other), None, &r),
            UpstreamNote::End,
            "{other}"
        );
    }
    assert_eq!(
        classify_response(true, &id, None, None, &r),
        UpstreamNote::End
    );
}

#[test]
fn the_filter_names_what_is_needed() {
    let f = listen_filter(
        KindSet {
            resources_changed: false,
            prompts_changed: true,
            tools_changed: true,
        },
        &["file:///a".to_owned()],
    );
    assert_eq!(f["notifications"]["promptsListChanged"], true);
    assert_eq!(f["notifications"]["resourcesListChanged"], false);
    assert_eq!(f["notifications"]["toolsListChanged"], true);
    assert_eq!(
        f["notifications"]["resourceSubscriptions"],
        json!(["file:///a"])
    );
}

#[test]
fn a_tagged_frame_goes_to_its_listen_only() {
    let taps = Taps::default();
    let id = json!(7);
    let mut rx = taps.listen(&id, requested());
    let mut legacy = taps.unsolicited(Watched::default());
    let ack = tag(
        &id,
        json!({"notifications": {"resourcesListChanged": true}}),
    );
    assert!(taps.notification(ACKNOWLEDGED, Some(&ack)));
    assert!(matches!(rx.try_recv(), Ok(UpstreamNote::Ack { .. })));
    let p = tag(&id, json!({}));
    assert!(taps.notification(RESOURCES_CHANGED, Some(&p)));
    assert!(rx.try_recv().is_ok());
    assert!(
        legacy.try_recv().is_err(),
        "a tagged frame never reaches the legacy tap"
    );
    assert!(taps.notification(PROMPTS_CHANGED, None));
    assert!(legacy.try_recv().is_ok(), "untagged goes to the legacy tap");
    assert!(
        !taps.notification("notifications/progress", None),
        "other methods keep their existing route"
    );
}

#[test]
fn without_a_tap_nothing_is_consumed() {
    let taps = Taps::default();
    assert!(!taps.notification(RESOURCES_CHANGED, None));
    assert!(!taps.response(&json!(1), None, None));
}

#[test]
fn a_full_tap_drops_and_counts_without_blocking() {
    let taps = Taps::default();
    let _legacy = taps.unsolicited(Watched::default());
    for _ in 0..TAP_CAPACITY + 3 {
        assert!(taps.notification(RESOURCES_CHANGED, None));
    }
    assert_eq!(taps.drops.load(std::sync::atomic::Ordering::Relaxed), 3);
}

#[test]
fn an_end_on_a_full_channel_still_closes_it() {
    let taps = Taps::default();
    let id = json!(9);
    let mut rx = taps.listen(&id, requested());
    let p = tag(&id, json!({}));
    for _ in 0..TAP_CAPACITY {
        taps.notification(RESOURCES_CHANGED, Some(&p));
    }
    assert!(taps.response(&id, Some(&json!({"resultType": "complete"})), None));
    for _ in 0..TAP_CAPACITY {
        assert!(rx.try_recv().is_ok());
    }
    assert_eq!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected),
        "the end is reported as Closed"
    );
    assert!(!taps.response(&id, None, None), "the listen is gone");
}

#[test]
fn the_first_frame_compatible_response_acks_and_keeps_the_listen() {
    let taps = Taps::default();
    let id = json!(3);
    let r = requested();
    let mut rx = taps.listen(&id, r.clone());
    let shape = json!({"_meta": { SUBSCRIPTION_ID: 3 }});
    assert!(taps.response(&id, Some(&shape), None));
    assert_eq!(rx.try_recv(), Ok(r.as_full_ack()));
    assert!(
        taps.response(&id, Some(&shape), None),
        "a later one is the end"
    );
    assert_eq!(rx.try_recv(), Ok(UpstreamNote::End));
    assert!(rx.try_recv().is_err());
}

/// A backend's tools notice projects to a note (I5b); on a listen it must
/// carry the listen's tag like the others.
#[test]
fn a_tools_notice_projects_and_needs_its_tag() {
    let id = json!(7);
    let r = requested();
    assert_eq!(
        project("notifications/tools/list_changed", None, None),
        Ok(UpstreamNote::Notice {
            kind: NoteKind::ToolsChanged,
            uri: None
        })
    );
    assert_eq!(
        project("notifications/tools/list_changed", None, Some((&id, &r))),
        Err(Dropped::Untagged)
    );
}

/// MIK-7898 SESS.3: an acknowledgement counts only as a listen's first frame;
/// one after another frame is dropped, not routed.
#[test]
fn an_acknowledgement_after_the_first_frame_is_dropped() {
    let taps = Taps::default();
    let id = json!(7);
    let mut rx = taps.listen(&id, requested());
    assert!(taps.notification(RESOURCES_CHANGED, Some(&tag(&id, json!({})))));
    assert!(matches!(rx.try_recv(), Ok(UpstreamNote::Notice { .. })));
    let ack = tag(
        &id,
        json!({"notifications": {"resourcesListChanged": true}}),
    );
    assert!(taps.notification(ACKNOWLEDGED, Some(&ack)));
    assert!(rx.try_recv().is_err(), "a late acknowledgement was routed");
}

/// MIK-7899 CLASS.1: a `-32601` answer is `Unsupported` at any position, and
/// ends the listen like the graceful end.
#[test]
fn a_method_not_found_answer_is_unsupported() {
    let (id, r) = (json!(7), requested());
    for first in [true, false] {
        assert_eq!(
            classify_response(first, &id, None, Some(-32601), &r),
            UpstreamNote::Unsupported
        );
    }
    assert_eq!(
        classify_response(true, &id, None, Some(-32600), &r),
        UpstreamNote::End,
        "another error is the end"
    );
    let taps = Taps::default();
    let mut rx = taps.listen(&id, r);
    assert!(taps.response(&id, None, Some(-32601)));
    assert_eq!(rx.try_recv(), Ok(UpstreamNote::Unsupported));
    assert!(!taps.response(&id, None, None), "the listen is gone");
}

/// MIK-7899 CLASS.1: a tap whose notices filled it still reports a `-32601`
/// answer as `Unsupported`; the last slot is kept for the listen's end.
#[test]
fn a_full_tap_still_reports_unsupported() {
    let taps = Taps::default();
    let id = json!(7);
    let mut rx = taps.listen(&id, requested());
    for _ in 0..TAP_CAPACITY + 4 {
        taps.notification(RESOURCES_CHANGED, Some(&tag(&id, json!({}))));
    }
    assert!(taps.response(&id, None, Some(-32601)));
    let mut last = None;
    while let Ok(note) = rx.try_recv() {
        last = Some(note);
    }
    assert_eq!(last, Some(UpstreamNote::Unsupported));
}

/// MIK-7898 SESS.2b (D5): a full tap's worth of updates for a URI nobody
/// watches any more takes no slot, so a wanted update after them arrives.
#[test]
fn unwatched_legacy_updates_never_displace_a_wanted_one() {
    let taps = Taps::default();
    let mut legacy = taps.unsolicited(Watched::by(|uri| uri == "file:///wanted"));
    for _ in 0..TAP_CAPACITY + 3 {
        assert!(taps.notification(UPDATED, Some(&json!({"uri": "file:///stale"}))));
    }
    assert!(taps.notification(UPDATED, Some(&json!({"uri": "file:///wanted"}))));
    assert_eq!(
        legacy.try_recv(),
        Ok(UpstreamNote::Notice {
            kind: NoteKind::ResourceUpdated,
            uri: Some("file:///wanted".to_owned()),
        })
    );
    assert!(
        legacy.try_recv().is_err(),
        "the stale updates were not queued"
    );
}

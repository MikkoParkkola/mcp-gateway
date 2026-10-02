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
        project("notifications/tools/list_changed", None, None),
        Err(Dropped::Other)
    );
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
                prompts_changed: false
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
        classify_response(true, &id, Some(&shape), &r),
        r.as_full_ack()
    );
    assert_eq!(
        classify_response(false, &id, Some(&shape), &r),
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
            classify_response(true, &id, Some(&other), &r),
            UpstreamNote::End,
            "{other}"
        );
    }
    assert_eq!(classify_response(true, &id, None, &r), UpstreamNote::End);
}

#[test]
fn the_filter_names_what_is_needed() {
    let f = listen_filter(
        KindSet {
            resources_changed: false,
            prompts_changed: true,
        },
        &["file:///a".to_owned()],
    );
    assert_eq!(f["notifications"]["promptsListChanged"], true);
    assert_eq!(f["notifications"]["resourcesListChanged"], false);
    assert_eq!(
        f["notifications"]["resourceSubscriptions"],
        json!(["file:///a"])
    );
}

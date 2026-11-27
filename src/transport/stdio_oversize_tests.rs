// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who an over-limit stdio frame belongs to, from its first bytes alone
//! (U1, U2). Only leading keys `jsonrpc`?, `id`, then `result` or `error`
//! name an owner; anything else names nobody.

use super::oversize_owner;

fn owner(frame: &str) -> Option<String> {
    oversize_owner(frame.as_bytes())
}

/// The frame as a big answer arrives: its value runs past what was kept.
fn cut(head: &str) -> String {
    format!("{head}\"{}", "x".repeat(64))
}

#[test]
fn u1_an_answer_leading_with_its_id_names_the_owner() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":7,"result":{"text":"#)),
        Some("7".into())
    );
    assert_eq!(owner(&cut(r#"{"id":7,"result":"#)), Some("7".into()));
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":"req-4","error":{"message":"#)),
        Some("req-4".into())
    );
    assert_eq!(
        owner(&cut(r#" { "jsonrpc" : "2.0" , "id" : 12 , "result" : "#)),
        Some("12".into())
    );
}

#[test]
fn u1_a_frame_leading_with_method_names_nobody() {
    // A peer request and a notification: their method comes before anything else.
    assert_eq!(
        owner(&cut(
            r#"{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{"x":"#
        )),
        None
    );
    assert_eq!(
        owner(&cut(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"#
        )),
        None
    );
    assert_eq!(owner(&cut(r#"{"method":"ping","id":7,"result":"#)), None);
}

#[test]
fn u1_an_id_after_the_result_names_nobody() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","result":{"id":7,"text":"#)),
        None
    );
}

#[test]
fn u1_an_id_past_the_kept_head_names_nobody() {
    let far = format!(
        r#"{{"jsonrpc":"{}","id":7,"result":"x"}}"#,
        "2".repeat(5000)
    );
    assert_eq!(owner(&far), None);
}

/// Review r1 (kimi): the kept head is exactly 4 KiB. A deciding key whose
/// closing quote is the last kept byte names the owner; one byte later, the
/// cut falls inside the key and nobody is named.
#[test]
fn u2_the_head_bound_is_exact() {
    let tail = r#"","id":7,"result""#;
    let pad = 4096 - r#"{"jsonrpc":""#.len() - tail.len();
    let head = |pad: usize| format!(r#"{{"jsonrpc":"{}{tail}:{{}}"#, "x".repeat(pad));
    // The colon after `"result"` is byte 4097: the kept head ends at its quote.
    assert_eq!(head(pad).rfind(":{}"), Some(4096));
    assert_eq!(owner(&head(pad)), Some("7".into()));
    assert_eq!(owner(&head(pad + 1)), None);
}

#[test]
fn u1_a_frame_cut_inside_its_id_names_nobody() {
    assert_eq!(owner(r#"{"jsonrpc":"2.0","id":"req-"#), None);
    assert_eq!(owner(r#"{"jsonrpc":"2.0","id":7"#), None);
    assert_eq!(owner(r#"{"jsonrpc":"2.0","id":7,"#), None);
    assert_eq!(owner(r#"{"jsonrpc":"2.0","id":7,"res"#), None);
}

#[test]
fn u2_a_nested_id_is_not_the_frames_id() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","params":{"id":7},"result":"#)),
        None
    );
    assert_eq!(owner(&cut(r#"{"jsonrpc":{"id":7},"result":"#)), None);
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","error":{"id":7,"message":"#)),
        None
    );
    // The id's own value is read whole: an object or array there is no id.
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":{"id":7},"result":"#)),
        None
    );
    assert_eq!(owner(&cut(r#"{"jsonrpc":"2.0","id":[7],"result":"#)), None);
}

/// The kept head is cut: a nested value before `id` that runs past it names
/// nobody, whether the visitor stops at its key or serde tries to skip it.
#[test]
fn u2_a_leading_nested_value_cut_off_names_nobody() {
    let pad = "x".repeat(5000);
    let params_first =
        format!(r#"{{"jsonrpc":"2.0","params":{{"pad":"{pad}"}},"id":7,"result":1}}"#);
    assert_eq!(owner(&params_first), None);
    let nested_jsonrpc = format!(r#"{{"jsonrpc":{{"pad":"{pad}"}},"id":7,"result":1}}"#);
    assert_eq!(owner(&nested_jsonrpc), None);
    assert_eq!(owner(r#"{"jsonrpc":{"pad":["x","#), None);
}

#[test]
fn u2_id_text_inside_a_string_is_not_a_key() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"\",\"id\":7,\"result\":","result":"#)),
        None
    );
}

#[test]
fn u2_escaped_keys_and_ids_are_read_unescaped() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","\u0069d":7,"result":"#)),
        Some("7".into())
    );
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":"a\"b\u0041","\u0072esult":"#)),
        Some("a\"bA".into())
    );
}

#[test]
fn u2_numeric_ids_name_the_key_the_pending_map_uses() {
    assert_eq!(owner(&cut(r#"{"id":0,"result":"#)), Some("0".into()));
    assert_eq!(owner(&cut(r#"{"id":-3,"result":"#)), Some("-3".into()));
    assert_eq!(
        owner(&cut(r#"{"id":9223372036854775807,"result":"#)),
        Some("9223372036854775807".into())
    );
    // No i64 key matches these, so they name nobody.
    assert_eq!(owner(&cut(r#"{"id":9223372036854775808,"result":"#)), None);
    assert_eq!(owner(&cut(r#"{"id":1.5,"result":"#)), None);
    assert_eq!(owner(&cut(r#"{"id":1e3,"result":"#)), None);
    assert_eq!(owner(&cut(r#"{"id":null,"result":"#)), None);
}

#[test]
fn u2_malformed_bytes_around_the_keys_name_nobody() {
    assert_eq!(owner(&cut(r#"{"jsonrpc":"2.0" "id":7,"result":"#)), None);
    assert_eq!(owner(&cut(r#"["jsonrpc","2.0","id",7,"result","#)), None);
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":7,"id":8,"result":"#)),
        None
    );
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":7,"result":"#)),
        None
    );
    assert_eq!(owner("\u{feff}{\"id\":7,\"result\":\"x"), None);
    assert_eq!(oversize_owner(b"{\"id\":7,\"res\xffult\":\"x"), None);
}

/// Named limit (lead ruling, gpt r2): a peer request that puts a result
/// member before its method cannot be told from an answer once cut, and is
/// attributed. Its reach is the one call waiting on that same backend.
#[test]
fn u2_named_limit_a_result_before_method_is_attributed() {
    assert_eq!(
        owner(&cut(r#"{"jsonrpc":"2.0","id":7,"result":{"padding":"#)),
        Some("7".into())
    );
}

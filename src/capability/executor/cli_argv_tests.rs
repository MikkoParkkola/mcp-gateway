// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 CLI.1: argv is built only from the template and typed parameters;
//! a parameter value is always exactly the bytes of one element (or stdin) and
//! can never add, remove or split an element.

use serde_json::{Value, json};

use super::{MAX_EACH_ITEMS, build_cli_invocation};
use crate::capability::definition::CliConfig;

fn cfg(yaml: &str) -> CliConfig {
    serde_yaml::from_str(yaml).expect("test config parses")
}

fn argv(config: &CliConfig, params: &Value) -> Vec<String> {
    build_cli_invocation(config, params, &json!({}))
        .expect("builds")
        .args
}

fn send_config() -> CliConfig {
    cfg(r#"
command: gws
args:
  - gmail
  - +send
  - "--to={to}"
  - "--subject={subject}"
  - { arg: "--cc={cc}", if: cc }
  - "--"
  - "{file}"
"#)
}

const HOSTILE: &[&str] = &[
    "--attach=/etc/passwd",
    "-a",
    "--draft",
    "; rm -rf ~",
    "$(id)",
    "`id`",
    "%PATH%",
    "\"quoted\" and 'single'",
    "@/etc/passwd",
    "setup",
    "a b\tc",
    "naïve ✓",
];

#[test]
fn a_typical_call_builds_the_golden_argv() {
    let got = argv(
        &send_config(),
        &json!({"to": "a@x.test", "subject": "Hi", "file": "report.pdf"}),
    );
    assert_eq!(
        got,
        [
            "gmail",
            "+send",
            "--to=a@x.test",
            "--subject=Hi",
            "--",
            "report.pdf"
        ]
    );
}

#[test]
fn a_hostile_value_is_exactly_one_element_wherever_it_goes() {
    let golden_len = argv(
        &send_config(),
        &json!({"to": "t", "subject": "s", "cc": "c", "file": "f"}),
    )
    .len();
    for hostile in HOSTILE {
        let got = argv(
            &send_config(),
            &json!({"to": hostile, "subject": hostile, "cc": hostile, "file": hostile}),
        );
        assert_eq!(
            got.len(),
            golden_len,
            "{hostile:?} changed the argv shape: {got:?}"
        );
        assert_eq!(got[2], format!("--to={hostile}"));
        assert_eq!(got[4], format!("--cc={hostile}"));
        assert_eq!(got[5], "--", "end of options must stay in place");
        assert_eq!(got[6], *hostile, "operand after -- is the raw value");
    }
}

#[test]
fn an_absent_optional_element_is_left_out_not_emitted_empty() {
    let got = argv(
        &send_config(),
        &json!({"to": "t", "subject": "s", "file": "f"}),
    );
    assert!(!got.iter().any(|a| a.starts_with("--cc")), "{got:?}");
    assert!(!got.iter().any(String::is_empty), "{got:?}");
}

#[test]
fn a_missing_required_parameter_is_refused() {
    let err = build_cli_invocation(&send_config(), &json!({"to": "t"}), &json!({}))
        .unwrap_err()
        .to_string();
    assert!(err.contains("subject"), "{err}");
}

#[test]
fn a_parameter_may_not_start_an_element_before_end_of_options() {
    let config = cfg(r#"
command: tool
args: ["{target}"]
"#);
    let err = build_cli_invocation(&config, &json!({"target": "--evil"}), &json!({}))
        .unwrap_err()
        .to_string();
    assert!(err.contains("before \"--\""), "{err}");
}

#[test]
fn nul_and_line_breaks_are_refused_unless_multiline() {
    let config = cfg(r#"
command: tool
args: ["--body={body}"]
"#);
    for bad in ["a\0b", "line1\nline2", "a\rb"] {
        assert!(
            build_cli_invocation(&config, &json!({"body": bad}), &json!({})).is_err(),
            "{bad:?} accepted"
        );
    }
    let schema = json!({"properties": {"body": {"type": "string", "format": "multiline"}}});
    let ok = build_cli_invocation(&config, &json!({"body": "line1\nline2"}), &schema).unwrap();
    assert_eq!(ok.args, ["--body=line1\nline2"]);
    assert!(build_cli_invocation(&config, &json!({"body": "a\0b"}), &schema).is_err());
}

#[test]
fn json_arguments_keep_types_and_cannot_break_out_of_a_string() {
    let config = cfg(r#"
command: gws
args:
  - { json: "--params=", value: { userId: me, q: "{query}", maxResults: "{maxResults}", pageToken: "{pageToken}" } }
"#);
    let got = argv(
        &config,
        &json!({"query": "x\", \"userId\": \"evil", "maxResults": 5}),
    );
    assert_eq!(got.len(), 1);
    let body: Value = serde_json::from_str(got[0].strip_prefix("--params=").unwrap()).unwrap();
    assert_eq!(body["userId"], "me", "{body}");
    assert_eq!(body["q"], "x\", \"userId\": \"evil");
    assert_eq!(body["maxResults"], 5, "number stays a number");
    assert!(
        body.get("pageToken").is_none(),
        "absent key dropped: {body}"
    );
}

#[test]
fn each_emits_one_bound_element_per_item_and_is_capped() {
    let config = cfg(r#"
command: gws
args:
  - "+insert"
  - { each: attendees, arg: "--attendee={item}" }
"#);
    let got = argv(&config, &json!({"attendees": ["a@x.test", "--meet"]}));
    assert_eq!(got, ["+insert", "--attendee=a@x.test", "--attendee=--meet"]);
    assert_eq!(argv(&config, &json!({})), ["+insert"]);
    let many: Vec<String> = (0..=MAX_EACH_ITEMS)
        .map(|i| format!("p{i}@x.test"))
        .collect();
    assert!(build_cli_invocation(&config, &json!({"attendees": many}), &json!({})).is_err());
    assert!(
        build_cli_invocation(
            &config,
            &json!({"attendees": "a@x.test,b@x.test"}),
            &json!({})
        )
        .is_err(),
        "a string is never split into items"
    );
}

#[test]
fn an_unbound_each_template_is_refused() {
    let config = cfg(r#"
command: tool
args: [{ each: xs, arg: "{item}" }]
"#);
    assert!(build_cli_invocation(&config, &json!({"xs": ["-x"]}), &json!({})).is_err());
}

#[test]
fn stdin_carries_text_that_must_not_reach_argv() {
    let config = cfg(r#"
command: metacognition
args: ["--json", "-"]
stdin: "{text}"
"#);
    for text in ["@/etc/passwd", "setup", "--help"] {
        let inv = build_cli_invocation(&config, &json!({"text": text}), &json!({})).unwrap();
        assert_eq!(inv.args, ["--json", "-"]);
        assert_eq!(inv.stdin.as_deref(), Some(text));
    }
}

#[test]
fn two_placeholders_in_one_element_are_a_config_error() {
    let config = cfg(r#"
command: gws
args: ["{\"calendarId\": \"{calendarId}\", \"q\": \"{q}\"}"]
"#);
    let err = build_cli_invocation(&config, &json!({"calendarId": "c", "q": "x"}), &json!({}))
        .unwrap_err()
        .to_string();
    assert!(err.contains("more than one placeholder"), "{err}");
}

#[test]
fn an_unknown_config_key_does_not_parse() {
    let parsed: Result<CliConfig, _> = serde_yaml::from_str(
        r#"
command: trawl
args_template: "{{ url }}"
"#,
    );
    assert!(
        parsed.is_err(),
        "args_template must be refused, not ignored"
    );
}

#[test]
fn a_parameter_cannot_name_an_option_or_a_subcommand_before_end_of_options() {
    for template in ["--{opt}=x", "-{opt}", "get{what}", "{what}x"] {
        let config = cfg(&format!("command: tool\nargs: ['{template}']\n"));
        let err =
            build_cli_invocation(&config, &json!({"opt": "draft", "what": "all"}), &json!({}))
                .unwrap_err()
                .to_string();
        assert!(err.contains("outside an option value"), "{template}: {err}");
    }
    let after = cfg("command: tool\nargs: ['--', 'get{what}']\n");
    assert_eq!(argv(&after, &json!({"what": "--x"})), ["--", "get--x"]);
}

#[test]
fn stdin_is_capped_at_exactly_one_mebibyte() {
    let config = cfg("command: tool\nstdin: '{text}'\n");
    let at_limit = "é".repeat(super::MAX_STDIN_BYTES / 2);
    assert!(build_cli_invocation(&config, &json!({"text": at_limit}), &json!({})).is_ok());
    let over = format!("{at_limit}x");
    assert!(build_cli_invocation(&config, &json!({"text": over}), &json!({})).is_err());
}

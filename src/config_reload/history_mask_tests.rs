// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the masked rendering of kept config versions. Every secret in a
//! fixture is a distinct sentinel; a rendering is asserted as a literal, and
//! a sentinel that must not show is checked by every 3-byte window too.

use super::{Withheld, mark_changed, rendered_env, rendered_yaml, slot_path};
use crate::config_reload::ui_fields::{FIELDS, Seg};
use crate::yaml::{Step, renderable};

/// The `n`th sentinel. Its 3-byte windows appear in no rendered path or token.
fn sentinel(n: usize) -> String {
    format!("QZ7XJ9WK{n}V")
}

/// `text` with each `@n` (n below 10) replaced by `sentinel(n)`.
fn fill(text: &str) -> String {
    (0..10).fold(text.to_owned(), |t, n| {
        t.replace(&format!("@{n}"), &sentinel(n))
    })
}

/// A literal written from its second line on: the raw string's first line
/// break is layout, not content.
fn literal(text: &str) -> &str {
    text.strip_prefix('\n').expect("literal starts on its own line")
}

/// No 3-byte window of `secret` appears anywhere in `shown`.
fn assert_no_part(shown: &str, secret: &str) {
    for part in secret.as_bytes().windows(3) {
        assert!(
            !shown.as_bytes().windows(3).any(|w| w == part),
            "{:?} of a secret shows in {shown:?}",
            String::from_utf8_lossy(part)
        );
    }
}

fn rendered(text: &str) -> String {
    rendered_yaml(text).expect("renders").text()
}

/// Every slot the masker knows, each holding `@0`..`@9` in turn. Env and
/// header names are innocent on purpose, so only the path masks them; the
/// second server's name holds a dot and its env name a quote.
const SLOTS: &str = r##"
auth:
  bearer_token: @0
  api_keys:
    - name: ops
      key: @1
      key_sha256: @2
agent_auth:
  agents:
    - client_id: bot
      hs256_secret: @3
key_server:
  admin_token: @4
backends:
  github:
    command: gh
    env:
      REGION: @5
    headers:
      X-Trace: @6
    oauth:
      client_secret: @7
  a.b:
    env:
      Q"K: @8
custom:
  password: @9
"##;

#[test]
fn m1_every_slot_form_is_masked_and_a_reference_shows_as_written() {
    let text = fill(literal(SLOTS));
    let shown = rendered(&text);
    assert_eq!(
        shown,
        literal(
            r##"
auth.bearer_token: <set>
auth.api_keys[0].name: ops
auth.api_keys[0].key: <set>
auth.api_keys[0].key_sha256: <set>
agent_auth.agents[0].client_id: bot
agent_auth.agents[0].hs256_secret: <set>
key_server.admin_token: <set>
backends.github.command: gh
backends.github.env.REGION: <set>
backends.github.headers.X-Trace: <set>
backends.github.oauth.client_secret: <set>
backends."a.b".env."Q\"K": <set>
custom.password: <set>
"##
        )
    );
    for n in 0..10 {
        assert_no_part(&shown, &sentinel(n));
    }

    let references = (0..10).fold(literal(SLOTS).to_owned(), |t, n| {
        t.replace(&format!("@{n}"), &format!("keychain:slot-{n}"))
    });
    assert_eq!(
        rendered(&references),
        literal(
            r##"
auth.bearer_token: keychain:slot-0
auth.api_keys[0].name: ops
auth.api_keys[0].key: keychain:slot-1
auth.api_keys[0].key_sha256: keychain:slot-2
agent_auth.agents[0].client_id: bot
agent_auth.agents[0].hs256_secret: keychain:slot-3
key_server.admin_token: keychain:slot-4
backends.github.command: gh
backends.github.env.REGION: keychain:slot-5
backends.github.headers.X-Trace: keychain:slot-6
backends.github.oauth.client_secret: keychain:slot-7
backends."a.b".env."Q\"K": keychain:slot-8
custom.password: keychain:slot-9
"##
        )
    );
}

#[test]
fn m2_one_node_is_one_line() {
    let text = fill(literal(
        r##"
notes:
  block: |
    line one
    line two
  folded: >
    folded
    text
creds:
  api_secret:
    password: @1
    token: @2
custom:
  "pass\x77ord": @3
  "line\nbreak": v
  hash: a#b
  dq: "x\ny"
  sq: 'x\ny'
  "a.b": one
  a:
    b: two
  "": empty-key
  empty_map: {}
  empty_list: []
backends:
  x:
    args: [--stdio, -v]
    env: {A: @4, B: @5}
    headers:
      REF: "env:A\nB"
"##,
    ));
    let shown = rendered(&text);
    assert_eq!(
        shown,
        literal(
            r##"
notes.block: line one\nline two\n
notes.folded: folded text\n
creds.api_secret: <set>
custom.password: <set>
custom."line\nbreak": v
custom.hash: a#b
custom.dq: x\ny
custom.sq: x\\ny
custom."a.b": one
custom.a.b: two
custom."": empty-key
custom.empty_map: {}
custom.empty_list: []
backends.x.args[0]: --stdio
backends.x.args[1]: -v
backends.x.env.A: <set>
backends.x.env.B: <set>
backends.x.headers.REF: env:A\nB
"##
        )
    );
    for n in 1..=5 {
        assert_no_part(&shown, &sentinel(n));
    }
    // The two pairs that an escaping mutant makes equal: a backslash written
    // unescaped joins dq and sq; a dot written unquoted joins the two a.b.
    let line = |path: &str| {
        shown
            .lines()
            .find_map(|l| l.strip_prefix(path))
            .expect("line present")
            .to_owned()
    };
    assert_ne!(line("custom.dq: "), line("custom.sq: "));
    assert_eq!(shown.matches(".a.b: ").count(), 1);
}

#[test]
fn m2b_anchors_aliases_tags_merge_keys_and_two_documents_are_withheld() {
    for (name, text) in [
        (
            "anchored scalar aliased under env",
            "plain: &v @1\nbackends:\n  x:\n    env:\n      A: *v\n",
        ),
        (
            "anchored mapping aliased into env",
            "plain: &m\n  A: @1\nbackends:\n  x:\n    env: *m\n",
        ),
        ("tagged collection", "custom: !!map {a: @1}\n"),
        ("merge key", "custom:\n  <<: {a: @1}\n"),
        ("two documents", "a: @1\n---\nb: two\n"),
        ("does not parse", "a: [@1\n"),
    ] {
        assert_eq!(rendered_yaml(&fill(text)), Err(Withheld), "{name}");
    }
}

/// The key-side shapes no `decorated` flag marks: each must be refused by
/// the allow-list pass, never rendered.
const KEY_SHAPES: [(&str, &str); 7] = [
    ("a: anchored key reused as an alias key", "&k password: one\n*k : @1\n"),
    ("b: anchored key alone", "&k password: @1\n"),
    ("c: tagged key", "!!str password: @1\n"),
    ("d: sequence as a key", "? [a, b]\n: x\npassword: @1\nmore: y\n"),
    ("e: mapping as a key", "? {a: b}\n: x\npassword: @1\nmore: y\n"),
    ("f: bare tag on a value", "note: ! @1\n"),
    ("f: bare tag on a key", "! note: @1\n"),
];

#[test]
fn m2c_only_allowed_shapes_are_rendered() {
    for (name, text) in KEY_SHAPES {
        let text = fill(text);
        assert_eq!(rendered_yaml(&text), Err(Withheld), "{name}");
        assert!(!renderable(&text), "{name}");
    }
    for (name, text) in [
        ("alias as a value", "a: &x one\nb: *x\n"),
        ("two documents", "a: 1\n---\nb: 2\n"),
        ("does not parse", "a: [1\n"),
    ] {
        assert!(!renderable(text), "{name}");
    }
    for (name, text) in [
        (
            "block collections of plain, quoted and block scalars",
            "a:\n  - plain\n  - \"double\"\n  - 'single'\nb:\n  c: |\n    text\n  d: >\n    text\n",
        ),
        ("flow collections", "a: {b: [1, \"two\", 'three'], c: {}}\nd: []\n"),
        ("empty text", ""),
    ] {
        assert!(renderable(text), "{name}");
    }
}

#[test]
fn m3_the_slot_table_covers_the_loaders_list() {
    let mut config: crate::config::Config = crate::yaml::from_str(literal(
        r##"
auth:
  bearer_token: x
  api_keys:
    - name: k
      key_sha256: x
      previous_key_sha256: x
agent_auth:
  agents:
    - client_id: a
      name: a
      hs256_secret: x
key_server:
  enabled: true
  admin_token: x
"##,
    ))
    .expect("config parses");
    let mut filled = 0;
    for (n, slot) in config.secret_slots_mut().enumerate() {
        *slot = sentinel(n);
        filled += 1;
    }
    assert!(filled >= 5, "the fixture fills every slot the loader lists");
    let text = crate::yaml::to_string(&config).expect("config writes");
    let shown = rendered(&text);
    for n in 0..filled {
        assert_no_part(&shown, &sentinel(n));
    }

    // Every secret field of the settings table is a slot path, whatever
    // backend name or position it is reached through.
    for field in FIELDS.iter().filter(|f| f.secret()) {
        let path: Vec<Step> = field
            .path
            .iter()
            .map(|seg| match seg {
                Seg::Key(k) => Step::Key((*k).to_owned()),
                Seg::Backend => Step::Key("sample".to_owned()),
                Seg::Index => Step::Index(0),
            })
            .collect();
        assert!(slot_path(&path), "{}", field.id);
    }
}

#[test]
fn m4_nothing_but_keys_and_values_is_written() {
    let commented = fill(literal(
        r##"
# top @1
server:
  # between @2

  port: 8443 # after @3
  host:      a
notes:
  lit: | # header @4
    body
  fold: > # header @5
    body
list:
  - a
  # between items @6
  - b
flow: {a: 1, # inside @7
  b: 2}
seq_flow: [x, # inside @8
  y]
"##,
    ));
    let bare = literal(
        r##"
server:
  port: 8443
  host: a
notes:
  lit: |
    body
  fold: >
    body
list:
  - a
  - b
flow: {a: 1, b: 2}
seq_flow: [x, y]
"##,
    );
    let shown = rendered(&commented);
    assert_eq!(
        shown,
        literal(
            r##"
server.port: 8443
server.host: a
notes.lit: body\n
notes.fold: body\n
list[0]: a
list[1]: b
flow.a: 1
flow.b: 2
seq_flow[0]: x
seq_flow[1]: y
"##
        )
    );
    assert_eq!(shown, rendered(bare));
    for n in 1..=8 {
        assert_no_part(&shown, &sentinel(n));
    }
}

#[test]
fn m5_an_unparseable_text_is_withheld() {
    for text in [
        "a: \"unterminated\n",
        "a:\n  - b\n c: d\n",
        "a: [1, 2\nb: @1\n",
    ] {
        assert_eq!(rendered_yaml(&fill(text)), Err(Withheld), "{text:?}");
    }
}

#[test]
fn m6_env_files_show_names_only() {
    let text = fill("B_FIRST=@1\nA_SECOND=\"@2\nLEAKED=tail\"\nEMPTY=\nREF=$NOT_SET_ANYWHERE_9617\nHOME_REF=$HOME\n");
    let shown = rendered_env(&text).expect("renders").text();
    assert_eq!(
        shown,
        "B_FIRST=<set>\nA_SECOND=<set>\nEMPTY=<set>\nREF=<set>\nHOME_REF=<set>\n"
    );
    assert!(!shown.contains("LEAKED"));
    assert_no_part(&shown, "tail");
    for n in 1..=2 {
        assert_no_part(&shown, &sentinel(n));
    }
    assert_eq!(rendered_env("NOT AN ASSIGNMENT\n"), Err(Withheld));
}

#[test]
fn m7_the_stated_limit() {
    // A secret under an innocent key, in a section no table names, with no
    // reference syntax, is shown. Changing this is a decision, not a fix.
    let text = fill("notes:\n  note: @1\n");
    assert_eq!(rendered(&text), format!("notes.note: {}\n", sentinel(1)));
}

#[test]
fn m8_a_rotated_secret_reads_changed_and_nothing_else() {
    let older = rendered_yaml(&fill("auth:\n  bearer_token: @1\n  other: x\n")).expect("older");
    let mut newer = rendered_yaml(&fill("auth:\n  bearer_token: @2\n  other: x\n")).expect("newer");
    mark_changed(&older.lines, &mut newer.lines);
    assert_eq!(older.text(), "auth.bearer_token: <set>\nauth.other: x\n");
    assert_eq!(
        newer.text(),
        "auth.bearer_token: <set> (changed)\nauth.other: x\n"
    );

    // The same secret on both sides, and a literal replaced by a reference
    // (the token itself shows the change), read no mark.
    let mut same = rendered_yaml(&fill("auth:\n  bearer_token: @1\n  other: x\n")).expect("same");
    mark_changed(&older.lines, &mut same.lines);
    assert_eq!(same.text(), older.text());
    let mut referenced =
        rendered_yaml("auth:\n  bearer_token: env:T\n  other: x\n").expect("reference");
    mark_changed(&older.lines, &mut referenced.lines);
    assert_eq!(
        referenced.text(),
        "auth.bearer_token: env:T\nauth.other: x\n"
    );

    // An env file: a value edit under the same name reads changed.
    let older = rendered_env(&fill("A=@1\nB=same\n")).expect("older env");
    let mut newer = rendered_env(&fill("A=@2\nB=same\n")).expect("newer env");
    mark_changed(&older.lines, &mut newer.lines);
    assert_eq!(newer.text(), "A=<set> (changed)\nB=<set>\n");
}

#[test]
fn m9_no_part_of_a_secret_survives() {
    // Lengths 1 to 40: a mutant keeping the first byte, the last two bytes or
    // the length (as stars) changes at least one of these literals.
    for secret in ["Q", "QZ", "QZ7", "QZ7XJ9WK", &"QZ7XJ9WK".repeat(5)] {
        let text = format!("auth:\n  bearer_token: {secret}\n");
        assert_eq!(rendered(&text), "auth.bearer_token: <set>\n", "{secret}");
        let env = format!("A={secret}\n");
        assert_eq!(
            rendered_env(&env).expect("env").text(),
            "A=<set>\n",
            "{secret}"
        );
    }
}

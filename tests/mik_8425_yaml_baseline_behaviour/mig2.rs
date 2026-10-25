// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2 step 2: rows recorded with the guarded adapter over the
//! old backend before the swap, so the swap's parity suite keeps an oracle once
//! the old parser leaves the build. Each row is a case the K0 spikes or the
//! design reviews named and the MIG.0 recording lacked.

use super::{Shape, ok_json, ok_tree, row, yaml};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Deserialize, Serialize)]
struct Keep {
    keep: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Untagged {
    A { a: u8 },
    S(String),
}

#[derive(Debug, Deserialize, Serialize)]
struct Flat {
    name: String,
    #[serde(flatten)]
    t: Untagged,
}

#[derive(Debug, Deserialize, Serialize)]
struct Flag {
    c: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Text {
    s: String,
}

/// A level-3 alias fan-out (loads under the old parser's repetition limit).
fn fanout3() -> String {
    let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
    for level in 1..=3 {
        let prev = level - 1;
        let refs = vec![format!("*a{prev}"); 10].join(", ");
        let _ = writeln!(doc, "a{level}: &a{level} [{refs}]");
    }
    doc
}

fn duplicates(out: &mut String) {
    let invalid_first = "a: 300\na: 2\n";
    row(
        out,
        "mig2/dup/invalid-earlier-map",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>(invalid_first)),
    );
    row(
        out,
        "mig2/dup/invalid-earlier-dict",
        &ok_json(yaml::from_str_loose(invalid_first)),
    );
    let ident = "1: 1\n'1': 2\n";
    row(
        out,
        "mig2/dup/key-identity-map",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>(ident)),
    );
    row(
        out,
        "mig2/dup/key-identity-tree",
        &ok_tree(yaml::from_str::<yaml::Value>(ident)),
    );
    row(
        out,
        "mig2/dup/flatten-untagged",
        &ok_json(yaml::from_str::<Flat>("name: n\na: 1\na: 2\n")),
    );
    row(
        out,
        "mig2/dup/flatten-named",
        &ok_json(yaml::from_str::<Flat>("name: n\nname: m\na: 1\n")),
    );
    row(
        out,
        "mig2/dup/flatten-ok",
        &ok_json(yaml::from_str::<Flat>("name: n\na: 1\n")),
    );
}

fn scalars(out: &mut String) {
    for (case, doc) in [
        ("mig2/bool/yes", "c: yes\n"),
        ("mig2/bool/True", "c: True\n"),
    ] {
        row(out, case, &ok_json(yaml::from_str::<Flag>(doc)));
    }
    for (case, doc) in [
        ("mig2/string/empty", "s:\n"),
        ("mig2/string/tilde", "s: ~\n"),
        ("mig2/string/quoted-empty", "s: ''\n"),
    ] {
        row(out, case, &ok_json(yaml::from_str::<Text>(doc)));
    }
}

/// D17: standard tags resolve, local tags stay tagged, a URI tag is dropped.
fn tags(out: &mut String) {
    for (case, doc) in [
        ("mig2/tag/str", "v: !!str 5\n"),
        ("mig2/tag/int", "v: !!int 5\n"),
        ("mig2/tag/float", "v: !!float 1\n"),
        ("mig2/tag/bool", "v: !!bool true\n"),
        ("mig2/tag/null", "v: !!null ~\n"),
        ("mig2/tag/map", "v: !!map {a: 1}\n"),
        ("mig2/tag/seq", "v: !!seq [1]\n"),
        ("mig2/tag/local", "v: !custom x\n"),
        ("mig2/tag/uri-core", "v: !<tag:yaml.org,2002:str> 5\n"),
        (
            "mig2/tag/uri-other",
            "v: !<tag:mcp-gateway.test,2026:kind> x\n",
        ),
    ] {
        row(
            out,
            &format!("{case}/tree"),
            &ok_tree(yaml::from_str::<yaml::Value>(doc)),
        );
        row(
            out,
            &format!("{case}/text"),
            &ok_json(yaml::from_str::<BTreeMap<String, String>>(doc)),
        );
    }
}

fn streams(out: &mut String) {
    let later_dup = "a: 1\n---\nb: 1\nb: 2\n---\nc: 1\n";
    let readings: Vec<String> = yaml::documents(later_dup).map(ok_tree).collect();
    row(
        out,
        "mig2/stream/later-duplicate",
        &format!("{} docs: {}", readings.len(), readings.join(" ; ")),
    );
}

/// D16: the old parser's repetition rule counts every alias visit, including in
/// a field the target ignores, and resets per document.
fn aliases(out: &mut String) {
    let mut ignored = String::from("keep: 1\nskip:\n");
    for line in fanout3().lines() {
        let _ = writeln!(ignored, "  {line}");
    }
    row(
        out,
        "mig2/alias/ignored-field",
        &ok_json(yaml::from_str::<Keep>(&ignored)),
    );
    let self_ref = "a: &a [1, *a]\n";
    row(
        out,
        "mig2/alias/self-reference",
        &ok_tree(yaml::from_str::<yaml::Value>(self_ref)),
    );
    let two = format!("{}---\n{}", fanout3(), fanout3());
    let readings: Vec<String> = yaml::documents(&two).map(ok_tree).collect();
    row(
        out,
        "mig2/alias/per-document",
        &format!("{} docs: {}", readings.len(), readings.join(" ; ")),
    );
}

/// `from_value` on the same enum shapes `from_str` reads.
fn from_value(out: &mut String) {
    for (case, doc) in [
        ("mig2/from-value/unit", "unit"),
        ("mig2/from-value/newtype-tag", "!newtype hi"),
        ("mig2/from-value/newtype-map", "{newtype: hi}"),
        ("mig2/from-value/struct-tag", "!pair {x: 1, y: 2}"),
        ("mig2/from-value/struct-map", "{pair: {x: 1, y: 2}}"),
    ] {
        let reading = match yaml::from_str::<yaml::Value>(doc) {
            Ok(tree) => ok_json(yaml::from_value::<Shape>(tree)),
            Err(error) => format!("ERR tree {error}"),
        };
        row(out, case, &reading);
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Egress {
    egress: mcp_gateway::runtime::provider::RuntimeNetworkEgress,
}

#[derive(Debug, Deserialize, Serialize)]
struct Policy {
    policy: mcp_gateway::runtime::NetworkEgressPolicy,
}

/// G3 on the product enums a YAML read reaches (census, section 3a):
/// `RuntimeNetworkEgress` through `Config`, `NetworkEgressPolicy` through
/// `SandboxDescriptor`. The second has an `#[serde(untagged)]` variant, so a
/// bare list must still read as its allowlist.
fn product_enums(out: &mut String) {
    for (case, doc) in [
        ("mig2/g3/egress/unit", "egress: loopback\n"),
        ("mig2/g3/egress/tag", "egress: !allowlist [a.test]\n"),
        ("mig2/g3/egress/map", "egress: {allowlist: [a.test]}\n"),
        ("mig2/g3/egress/bare-list", "egress: [a.test]\n"),
    ] {
        row(out, case, &ok_json(yaml::from_str::<Egress>(doc)));
    }
    for (case, doc) in [
        ("mig2/g3/policy/unit", "policy: none\n"),
        ("mig2/g3/policy/quoted-unit", "policy: 'full'\n"),
        ("mig2/g3/policy/tag", "policy: !allowlist [10.0.0.0/8]\n"),
        ("mig2/g3/policy/map", "policy: {allowlist: [10.0.0.0/8]}\n"),
        ("mig2/g3/policy/bare-list", "policy: [10.0.0.0/8]\n"),
    ] {
        row(out, case, &ok_json(yaml::from_str::<Policy>(doc)));
    }
}

/// P7: what the figment provider hands `Config::load`, before any merge.
fn figment_data(out: &mut String) {
    for (case, doc) in [
        ("mig2/figment/plain", "a: 1\nb: [x, y]\n"),
        ("mig2/figment/dup-nested", "a:\n  b: 1\n  b: 2\na: {c: 3}\n"),
        ("mig2/figment/syntax-error", "a: [1\n"),
        ("mig2/figment/second-document", "a: 1\n---\nb: 2\n"),
    ] {
        row(out, case, &ok_json(yaml::figment_data(doc)));
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outer {
    Inner(Shape),
}

/// Writes `bytes` through `serialize_bytes`, which YAML has no form for.
struct Bytes;

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(b"ab")
    }
}

fn written<T: Serialize + ?Sized>(value: &T) -> String {
    match yaml::to_string(value) {
        Ok(text) => format!("OK {text:?}"),
        Err(error) => format!("ERR {error}"),
    }
}

/// The code seats' r1 cases (gpt and grok, 2026-10-25), recorded with the
/// current backend before the replacement's fixes.
fn seat_r1(out: &mut String) {
    // Writer: a tag that needs escaping, keep-chomped text, f32, wide
    // integers, chars, bytes.
    for (case, doc) in [
        ("mig2/r1/write/escaped-tag", "v: !foo%20bar x\n"),
        ("mig2/r1/write/escaped-tag-map", "v: !a%2Fb {k: 1}\n"),
    ] {
        let reading = match yaml::from_str::<yaml::Value>(doc) {
            Ok(tree) => written(&tree),
            Err(error) => format!("ERR read {error}"),
        };
        row(out, case, &reading);
    }
    row(out, "mig2/r1/write/keep-root", &written("a\n\n"));
    row(out, "mig2/r1/write/clip-root", &written("a\n"));
    let mut keep = BTreeMap::new();
    keep.insert("k".to_owned(), "a\n\n".to_owned());
    row(out, "mig2/r1/write/keep-in-map", &written(&keep));
    let mut floats = BTreeMap::new();
    floats.insert("f32".to_owned(), 0.7_f32);
    floats.insert("tiny".to_owned(), 1.0e-7_f32);
    row(out, "mig2/r1/write/f32", &written(&floats));
    let mut wide = BTreeMap::new();
    wide.insert("max".to_owned(), u128::MAX);
    row(out, "mig2/r1/write/u128", &written(&wide));
    let mut negative = BTreeMap::new();
    negative.insert("min".to_owned(), i128::MIN);
    row(out, "mig2/r1/write/i128", &written(&negative));
    let mut chars = BTreeMap::new();
    for (k, c) in [("a", 'y'), ("b", '0'), ("c", ':'), ("d", '\''), ("e", '~')] {
        chars.insert(k.to_owned(), c);
    }
    row(out, "mig2/r1/write/chars", &written(&chars));
    row(out, "mig2/r1/write/bytes", &written(&Bytes));
    // Reader: core-tagged literal blocks into typed targets.
    row(
        out,
        "mig2/r1/read/int-literal",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: !!int |-\n  5\n")),
    );
    row(
        out,
        "mig2/r1/read/bool-literal",
        &ok_json(yaml::from_str::<BTreeMap<String, bool>>(
            "v: !!bool |-\n  true\n",
        )),
    );
    row(
        out,
        "mig2/r1/read/float-literal",
        &ok_json(yaml::from_str::<BTreeMap<String, f64>>(
            "v: !!float |-\n  1.5\n",
        )),
    );
    row(
        out,
        "mig2/r1/read/untagged-literal",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: |-\n  5\n")),
    );
    // Places: a tag on the line above its collection, and CR line breaks.
    row(
        out,
        "mig2/r1/place/tag-above-map",
        &ok_json(yaml::from_str::<BTreeMap<String, String>>(
            "v: !t\n  a: 1\n",
        )),
    );
    row(
        out,
        "mig2/r1/place/anchor-and-tag",
        &ok_json(yaml::from_str::<BTreeMap<String, String>>(
            "v: &x !t\n  a: 1\n",
        )),
    );
    row(
        out,
        "mig2/r1/place/cr",
        &ok_json(yaml::from_str::<BTreeMap<String, String>>(
            "a: x\rb: !t {x: 1}\r",
        )),
    );
    row(
        out,
        "mig2/r1/place/crlf",
        &ok_json(yaml::from_str::<BTreeMap<String, String>>(
            "a: x\r\nb: !t {x: 1}\r\n",
        )),
    );
    // A nested enum under a tag names its path and place.
    row(
        out,
        "mig2/r1/nested-enum",
        &ok_json(yaml::from_str::<BTreeMap<String, Outer>>(
            "v: !inner {x: 1}\n",
        )),
    );
}

/// A map that writes the same key twice, as a hand-written `Serialize` can.
struct Repeated;

impl Serialize for Repeated {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("a", &1)?;
        map.serialize_entry("a", &2)?;
        map.end()
    }
}

/// The code seats' r2 cases (gpt and grok, 2026-10-25), recorded with the
/// current backend.
fn seat_r2(out: &mut String) {
    row(out, "mig2/r2/write/repeated-key", &written(&Repeated));
    let floats: Vec<f32> = vec![1.0e-6, 1.0e-5, 0.1, 123_456_790.0, 3.0e38, 1.5];
    row(out, "mig2/r2/write/f32-forms", &written(&floats));
    let reading = match yaml::from_str::<yaml::Value>("v: ! x\n") {
        Ok(tree) => written(&tree),
        Err(error) => format!("ERR read {error}"),
    };
    row(out, "mig2/r2/write/bang-tag", &reading);
    row(
        out,
        "mig2/r2/place/tag-only-empty",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: !t\n")),
    );
    row(
        out,
        "mig2/r2/place/block-comment",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: |- # c\n  5\n")),
    );
    row(
        out,
        "mig2/r2/place/block-pipe-content",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: |-\n  |x\n")),
    );
    row(
        out,
        "mig2/r2/place/folded",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>("v: >-\n  5\n")),
    );
}

pub(super) fn rows(out: &mut String) {
    product_enums(out);
    duplicates(out);
    scalars(out);
    tags(out);
    streams(out);
    aliases(out);
    from_value(out);
    figment_data(out);
    seat_r1(out);
    seat_r2(out);
}

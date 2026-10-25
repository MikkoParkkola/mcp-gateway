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

pub(super) fn rows(out: &mut String) {
    product_enums(out);
    duplicates(out);
    scalars(out);
    tags(out);
    streams(out);
    aliases(out);
    from_value(out);
    figment_data(out);
}

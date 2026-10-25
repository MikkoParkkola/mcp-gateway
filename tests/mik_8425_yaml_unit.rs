// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2: unit-level checks on the YAML adapter's own backend
//! (`src/yaml/`), through its crate-visible surface.
//!
//! They live here, not in `#[cfg(test)]` modules inside `src/yaml/`,
//! because 55 integration crates compile `src/yaml/mod.rs` themselves
//! (`tests/common/yaml.rs`), and every `#[cfg(test)]` module in it would run
//! again in each of them.

#[path = "common/yaml.rs"]
mod yaml;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use yaml::{Mapping, Number, Tag, TaggedValue, Value};

#[test]
fn numbers_print_as_the_replaced_backend_printed_them() {
    for (number, text) in [
        (Number::from(1000.0), "1000.0"),
        (Number::from(1e100), "1e100"),
        (Number::from(0.5), "0.5"),
        (Number::from(f64::NAN), ".nan"),
        (Number::from(f64::INFINITY), ".inf"),
        (Number::from(f64::NEG_INFINITY), "-.inf"),
        (Number::from(-3_i64), "-3"),
        (Number::from(u64::MAX), "18446744073709551615"),
    ] {
        assert_eq!(number.to_string(), text);
    }
}

#[test]
fn there_is_one_nan_and_number_kinds_stay_apart() {
    assert_eq!(Number::from(f64::NAN), Number::from(-f64::NAN));
    assert_ne!(Number::from(1_u8), Number::from(1.0));
    assert!(Number::from(-1_i8).is_i64() && !Number::from(-1_i8).is_u64());
    assert_eq!(Number::from(u64::MAX).as_i64(), None);
}

#[test]
fn a_tag_is_one_tag_with_or_without_its_bang() {
    assert_eq!(Tag::new("!exact"), Tag::new("exact"));
    assert_eq!(Tag::new("exact").to_string(), "!exact");
    assert_eq!(Tag::new("!exact").to_string(), "!exact");
    // A lone `!` keeps its bang: the name after the handle is `!` itself.
    assert_eq!(Tag::new("!").to_string(), "!!");
    assert_eq!(Tag::new("!!str").to_string(), "!!str");
}

#[test]
fn a_tagged_value_serializes_back_to_itself_and_a_bang_key_does_not() {
    let tagged = Value::Tagged(Box::new(TaggedValue {
        tag: Tag::new("pair"),
        value: Value::from(1_u8),
    }));
    assert_eq!(yaml::to_value(&tagged).expect("serializes"), tagged);
    let mut map = Mapping::new();
    map.insert(Value::from("!x"), Value::from(1_u8));
    assert_eq!(
        yaml::to_value(Value::Mapping(map.clone())).expect("serializes"),
        Value::Mapping(map)
    );
}

/// A type error names its key path and place, as the replaced backend's
/// did, and neither `Display` nor `Debug` carries the value (B3).
#[test]
fn a_type_error_prints_its_path_and_place_and_never_the_value() {
    let error = yaml::from_str::<BTreeMap<String, u16>>("port: \"MIK8425-SENTINEL-7f3a\"\n")
        .expect_err("a string is not a u16");
    let shown = error.to_string();
    let debug = format!("{error:?}");
    assert!(shown.starts_with("port: invalid type: "), "{shown}");
    assert!(shown.ends_with(" at line 1 column 7"), "{shown}");
    assert!(!shown.contains("SENTINEL") && !debug.contains("SENTINEL"));
    let place = error.location().expect("a place");
    assert_eq!((place.line(), place.column()), (1, 7));
    assert!(error.limit().is_none());
}

/// A place at the very start is kept in `location()` but left out of the
/// text, and a fixed wording that names no node has no place at all.
#[test]
fn a_start_place_is_silent_and_a_budget_refusal_has_none() {
    let start = yaml::from_str::<Value>("a: 1\na: 2\n").expect_err("a repeated key");
    assert_eq!(start.to_string(), "duplicate entry with key \"a\"");
    let place = start.location().expect("a place");
    assert_eq!((place.line(), place.column()), (1, 1));

    let mut fanout = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
    for level in 1..=4 {
        let items = [format!("*l{}", level - 1).as_str(); 10].join(", ");
        let _ = writeln!(fanout, "l{level}: &l{level} [{items}]");
    }
    let budget = yaml::from_str::<Value>(&fanout).expect_err("over the alias budget");
    assert_eq!(budget.to_string(), "repetition limit exceeded");
    assert!(budget.location().is_none());
}

/// Nodes are placed where the replaced backend placed them: a tagged value
/// at its tag, an empty value just after its `:`, any other value at its
/// first character.
#[test]
fn nodes_are_placed_as_the_replaced_backend_placed_them() {
    let column = |doc: &str| {
        let error = yaml::from_str::<BTreeMap<String, u8>>(doc).expect_err("not a u8");
        error.location().expect("a place").column()
    };
    assert_eq!(column("v: !!map {a: 1}\n"), 4);
    assert_eq!(column("v: \n"), 3);
    assert_eq!(column("v:\n"), 3);
    assert_eq!(column("v: x\n"), 4);
}

/// Placing a tagged node costs a lookup, not a scan of the text before it:
/// 200,000 tagged items read well inside a 10 s budget, and the last is still
/// placed at its tag. A scan per node would take hours here.
#[test]
fn placing_many_tagged_nodes_stays_linear() {
    const ITEMS: usize = 200_000;
    let mut text = "- !t 1\n".repeat(ITEMS - 1);
    text.push_str("- !t x\n");
    let started = std::time::Instant::now();
    let error = yaml::from_str::<Vec<u8>>(&text).expect_err("the last item is not a u8");
    let elapsed = started.elapsed();
    let place = error.location().expect("a place");
    assert_eq!((place.line(), place.column()), (ITEMS, 3));
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "took {elapsed:?}"
    );
}

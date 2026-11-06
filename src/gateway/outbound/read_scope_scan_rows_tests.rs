// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The judge checkers' own rows.

use super::*;

/// The checker accepts the real gate, bare `judging` (raw or not) on a
/// `firewall` parameter, and refuses each other shape: an inverted or a
/// narrowing gate (by path, through a `use` alias, raw), another path to a
/// `judging`, a `firewall` that is not a parameter, a parameter or a body
/// item that shadows `judging`, a gate under an attribute. Any item kind
/// other than `use`, `const` with a literal or path value and `fn`, any
/// attribute but `doc`, and any macro is reported unsupported; one inline
/// `#[cfg(test)]` module is skipped.
#[test]
fn the_gate_check_refuses_each_ungated_shape() {
    let source = r"
        pub(crate) fn gated(firewall: &Firewall) {
            let Some((guard, mode)) = judging(firewall) else { return; };
        }
        pub(crate) fn gated_raw(firewall: &Firewall) {
            let Some((guard, mode)) = r#judging(firewall) else { return; };
        }
        pub(crate) fn inverted(firewall: &Firewall) {
            let None = judging(firewall) else { return; };
        }
        pub(crate) fn narrowing(firewall: &Firewall) {
            let Some((guard, CrossTenantReads::Off)) = judging(firewall) else { return; };
        }
        use CrossTenantReads::Off as off;
        pub(crate) fn aliased(firewall: &Firewall) {
            let Some((guard, off)) = judging(firewall) else { return; };
        }
        pub(crate) fn raw_alias(firewall: &Firewall) {
            let Some((guard, r#off)) = judging(firewall) else { return; };
        }
        pub(crate) fn generic<F: AsRef<Firewall>>(firewall: &F) {}
        pub(crate) fn foreign(firewall: &Firewall) {
            let Some(both) = bypass::judging(firewall) else { return; };
        }
        pub(crate) fn crate_path(firewall: &Firewall) {
            let Some(both) = crate::gateway::outbound::judge::judging(firewall) else { return; };
        }
        const firewall: &Firewall = FW;
        pub(crate) fn param_less() {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn shadowed_param(judging: Pick, firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn local_item(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
            fn judging(_: &Firewall) -> Option<()> { Some(()) }
        }
        pub(crate) fn disabled(firewall: &Firewall) {
            #[cfg(any())]
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn attribute(firewall: &Firewall) {}
        fn private(firewall: &Firewall) {}
        impl Judge {
            pub(crate) fn method(&self, firewall: &Firewall) {}
        }
        pub(crate) trait Made {}
        #[derive(Default)]
        struct Generated;
        const _: () = {};
        static FW2: u8 = 0;
        some_macro! {}
        mod elsewhere;
        mod nested {
            pub(crate) fn inner(firewall: &Firewall) {}
        }
        #[cfg(test)]
        mod tests {
            pub(crate) fn ungated_test(firewall: &Firewall) {}
        }
        #[inline]
        pub(crate) fn hinted(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn with_macro(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
            debug_assert!(true);
        }
        pub(crate) use inner::hidden;
        pub(crate) const UNCHECKED: fn(&Firewall, Payload) -> OutboundFrame = unchecked;
        fn unchecked(_: &Firewall, payload: Payload) -> OutboundFrame {
            OutboundFrame::unjudged(payload)
        }
        pub(crate) const LIMIT: usize = 3;
        pub(crate) const TEXT: &str = FIXED_TEXT;
    ";
    let file = syn::parse_file(source).expect("the fixture parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file, &mut found);
    found.gated.sort();
    found.ungated.sort();
    found.unsupported.sort();
    assert_eq!(found.gated, ["gated", "gated_raw"]);
    assert_eq!(
        found.ungated,
        [
            "aliased",
            "crate_path",
            "disabled",
            "foreign",
            "generic",
            "inverted",
            "local_item",
            "narrowing",
            "param_less",
            "raw_alias",
            "shadowed_param",
        ],
        "each exposed ungated shape is caught; the top-level `attribute` is exempt"
    );
    assert_eq!(
        found.unsupported,
        [
            "a macro in with_macro",
            "an attribute on hinted",
            "an exposed `use`",
            "const UNCHECKED",
            "const _",
            "impl Judge",
            "item macro some_macro",
            "mod elsewhere;",
            "mod nested",
            "static FW2",
            "struct Generated",
            "trait Made",
        ],
        "each item the check does not accept is reported; the cfg(test) module is skipped"
    );
    let disguised = syn::parse_file(
        r"
        use crate::elsewhere::Ptr as usize;
        pub(crate) const SNEAK: usize = unchecked;
        fn helper(_: ty!()) {}
        const WIDE: [u8; len!()] = BYTES;
        const NESTED: [u8; { const N: usize = len!(); N }] = BYTES;
    ",
    )
    .expect("the fixture parses");
    let mut found = Entries {
        taken: taken_names(&disguised.items),
        ..Entries::default()
    };
    entries(&disguised, &mut found);
    found.unsupported.sort();
    assert_eq!(
        found.unsupported,
        [
            "a macro in helper",
            "const NESTED",
            "const SNEAK",
            "const WIDE"
        ],
        "a primitive name the file imports is not plain; a macro outside a body is still a macro"
    );
    for (source, want) in [
        (
            "use crate::elsewhere::Other as str; pub(crate) const S: &str = T;",
            "const S",
        ),
        (
            "use crate::elsewhere::*; pub(crate) const G: u8 = ONE;",
            "const G",
        ),
    ] {
        let file = syn::parse_file(source).expect("the fixture parses");
        let mut found = Entries {
            taken: taken_names(&file.items),
            ..Entries::default()
        };
        entries(&file, &mut found);
        assert_eq!(found.unsupported, [want], "{source}");
    }
}

const REAL_JUDGES: &str = r#"
/// Whether `guard` judges frames at all.
pub(crate) fn judges(guard: Option<&Guard>) -> bool {
    #[cfg(feature = "firewall")]
    {
        guard.is_some_and(|g| judge::judging(g).is_some())
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = guard;
        false
    }
}
"#;

/// `judges()` is accepted only in its one real shape, signature and whole
/// body: a comment naming the gate, a dead call, another path or argument,
/// a missing or extra attribute, an early return, a local module, a generic
/// parameter or a cfg'd parameter are each refused. A module declaration on
/// the way to the judge carrying a non-cfg attribute is refused too.
#[test]
fn the_judges_check_refuses_each_other_shape() {
    assert_eq!(
        judges_check(REAL_JUDGES),
        Ok(()),
        "the real shape is accepted"
    );
    let tail = "guard.is_some_and(|g| judge::judging(g).is_some())";
    let open = "-> bool {\n";
    let fw = "#[cfg(feature = \"firewall\")]\n";
    for (name, from, to) in [
        (
            "comment_only",
            tail,
            "// judge::judging(g)\n        guard.is_some()",
        ),
        (
            "dead_call",
            tail,
            "let _ = guard.map(judge::judging);\n        true",
        ),
        (
            "self_path",
            tail,
            "guard.is_some_and(|g| self::judge::judging(g).is_some())",
        ),
        (
            "other_arg",
            tail,
            "guard.is_some_and(|g| judge::judging(other).is_some())",
        ),
        (
            "is_none",
            tail,
            "guard.is_some_and(|g| judge::judging(g).is_none())",
        ),
        ("no_cfg_block", fw, ""),
        (
            "extra_attr",
            fw,
            "#[cfg(feature = \"firewall\")]\n    #[allow(unused)]\n",
        ),
        ("early_return", open, "-> bool {\n    return false;\n"),
        (
            "local_mod",
            open,
            "-> bool {\n    mod judge { pub fn judging<T>(_: T) -> Option<()> { Some(()) } }\n",
        ),
        ("generic_judge", "fn judges(", "fn judges<judge: Pick>("),
        (
            "cfg_param",
            "fn judges(guard",
            "fn judges(#[cfg(test)] guard",
        ),
        (
            "guard_type",
            "guard: Option<&Guard>",
            "guard: Option<&Custom>",
        ),
        (
            "guard_owned",
            "guard: Option<&Guard>",
            "guard: Option<Guard>",
        ),
        (
            "guard_mut",
            "guard: Option<&Guard>",
            "guard: Option<&mut Guard>",
        ),
        (
            "guard_lifetime",
            "guard: Option<&Guard>",
            "guard: Option<&'static Guard>",
        ),
        (
            "guard_path",
            "guard: Option<&Guard>",
            "guard: std::option::Option<&Guard>",
        ),
    ] {
        assert_eq!(
            REAL_JUDGES.matches(from).count(),
            1,
            "{name}: one site to change"
        );
        let mutated = REAL_JUDGES.replacen(from, to, 1);
        assert!(
            judges_check(&mutated).is_err(),
            "{name} is refused:\n{mutated}"
        );
    }
    let chain = [
        ("#[doc(hidden)]\npub mod gateway;\n", "gateway"),
        ("pub(crate) mod outbound;\n", "outbound"),
        ("#[cfg(feature = \"firewall\")]\nmod judge;\n", "judge"),
    ];
    assert_eq!(chain_check(&chain), Ok(()), "the real chain is accepted");
    let mut swapped = chain;
    swapped[2].0 = "#[cfg(feature = \"firewall\")]\n#[some_macro]\nmod judge;\n";
    assert!(
        chain_check(&swapped).is_err(),
        "an attribute macro on `mod judge;` is refused"
    );
    swapped[2].0 = "#[cfg(feature = \"firewall\")]\n#[path = \"judge.rs\"]\nmod checked_judge;\n\
        #[cfg(feature = \"firewall\")]\nmod judge { pub(crate) use super::checked_judge::delivered; }\n";
    assert!(
        chain_check(&swapped).is_err(),
        "an inline `mod judge` standing in for the checked file is refused"
    );
    swapped[2].0 = "#[cfg(any())]\nmod judge;\n";
    assert!(
        chain_check(&swapped).is_err(),
        "a cfg other than the firewall feature is refused"
    );
}

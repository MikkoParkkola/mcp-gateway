// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Mutant switches for one-build mutation proofs (mutant schemata).
//!
//! A lane proving that its test rows catch a bug wraps the mutated code on a
//! scratch commit in `mutant!("ID", mutated, original)`. One build with
//! `--cfg mutants` then carries every mutant, and each test process switches
//! on at most one, named by `MCP_GATEWAY_MUTANT`. Without `--cfg mutants`
//! the macro expands to `original` alone: no runtime check, no symbol and
//! no environment read, so a normal build is unchanged.
//!
//! This module is declared in every build; only its runtime items are gated
//! on `cfg(mutants)`. It is the one file a `mutant!` call may appear in
//! (its self-tests); the scan in `mutant_scan` refuses one anywhere else, so
//! no mutant site reaches the release line.

/// Whether mutant `id` is the one switched on for this process, from
/// `MCP_GATEWAY_MUTANT`, read once.
#[cfg(mutants)]
pub(crate) fn on(id: &'static str) -> bool {
    static SWITCH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    SWITCH
        .get_or_init(|| std::env::var("MCP_GATEWAY_MUTANT").ok())
        .as_deref()
        == Some(id)
}

/// Runs one test of this binary in a fresh process, with the switch set to
/// `switch` or removed, and returns its stdout. The child test runs
/// only when `MCP_GATEWAY_MUTANT_CHILD` is set, and prints a marker after its
/// assertions, so a child that never reached them cannot pass for one that did.
#[cfg(test)]
fn run_child(test: &str, switch: Option<&str>) -> String {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("test binary"));
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("MCP_GATEWAY_MUTANT_CHILD", "1");
    match switch {
        Some(id) => cmd.env("MCP_GATEWAY_MUTANT", id),
        None => cmd.env_remove("MCP_GATEWAY_MUTANT"),
    };
    let out = cmd.output().expect("run the child test");
    assert!(out.status.success(), "child {test} failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf-8 output")
}

#[cfg(test)]
fn is_child() -> bool {
    std::env::var_os("MCP_GATEWAY_MUTANT_CHILD").is_some()
}

#[cfg(all(test, not(mutants)))]
mod normal_build {
    /// SCH.2: without the cfg the macro is the original expression.
    #[test]
    fn a_normal_build_takes_the_original() {
        assert_eq!(mutant!("T1", 1, 2), 2);
    }

    /// SCH.2: a normal build never runs mutated code: a mutated arm that
    /// would panic is never reached.
    #[test]
    fn a_normal_build_never_runs_the_mutated_arm() {
        let original: u8 = mutant!("T3", unreachable!("a normal build ran the mutated arm"), 3);
        assert_eq!(original, 3);
    }

    /// SCH.2: the mutated tokens are dropped unchecked. The crate has exactly
    /// one normal-build definition of `mutant!`, with one rule whose
    /// expansion is `$original` alone, so the mutated tokens never reach the
    /// compiler. Read from the source: the macro is crate-private, so no
    /// doctest can name it.
    #[test]
    fn a_normal_build_drops_the_mutated_tokens() {
        use proc_macro2::{Delimiter, TokenTree};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mutant_macro.rs");
        let file =
            syn::parse_file(&std::fs::read_to_string(path).expect("read src/mutant_macro.rs"))
                .expect("parse src/mutant_macro.rs");
        let defs: Vec<&syn::ItemMacro> = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Macro(m) if m.ident.as_ref().is_some_and(|i| i == "mutant") => Some(m),
                _ => None,
            })
            .collect();
        // Each definition's cfg, as written without spaces.
        let cfg_of = |m: &syn::ItemMacro| -> Vec<String> {
            m.attrs
                .iter()
                .filter_map(|a| match &a.meta {
                    syn::Meta::List(l) if l.path.is_ident("cfg") => {
                        Some(l.tokens.to_string().replace(' ', ""))
                    }
                    _ => None,
                })
                .collect()
        };
        let mut cfgs: Vec<Vec<String>> = defs.iter().map(|m| cfg_of(m)).collect();
        cfgs.sort();
        assert_eq!(
            cfgs,
            vec![vec!["mutants".to_owned()], vec!["not(mutants)".to_owned()]],
            "exactly two definitions of mutant!, one per cfg"
        );
        let normal: Vec<&syn::ItemMacro> = defs
            .into_iter()
            .filter(|m| cfg_of(m) == ["not(mutants)"])
            .collect();
        assert_eq!(
            normal.len(),
            1,
            "one #[cfg(not(mutants))] definition of mutant!"
        );
        let groups: Vec<proc_macro2::Group> = normal[0]
            .mac
            .tokens
            .clone()
            .into_iter()
            .filter_map(|t| match t {
                TokenTree::Group(g) => Some(g),
                _ => None,
            })
            .collect();
        assert_eq!(groups.len(), 2, "one rule: a pattern and an expansion");
        assert_eq!(groups[1].delimiter(), Delimiter::Brace);
        let expansion = groups[1].stream().to_string().replace(' ', "");
        assert_eq!(expansion, "$original", "the normal-build expansion");
    }

    /// SCH.2: a normal build reads no switch: with the switch set to this
    /// site's ID, a fresh process still takes the original.
    #[test]
    fn a_normal_build_ignores_the_switch_env() {
        let out = super::run_child(
            "mutant::normal_build::child_takes_the_original_with_the_switch_set",
            Some("T2"),
        );
        assert!(out.contains("MUTANT-CHILD-DONE T2"), "child output: {out}");
    }

    #[test]
    fn child_takes_the_original_with_the_switch_set() {
        if !super::is_child() {
            return;
        }
        assert_eq!(mutant!("T2", 1, 2), 2);
        println!("MUTANT-CHILD-DONE T2");
    }

    /// SCH.2: the switch function exists only under `cfg(mutants)`.
    #[test]
    fn a_normal_build_has_no_switch_function() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mutant.rs");
        let file = syn::parse_file(&std::fs::read_to_string(path).expect("read src/mutant.rs"))
            .expect("parse src/mutant.rs");
        let on = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(f) if f.sig.ident == "on" => Some(f),
                _ => None,
            })
            .expect("fn on in src/mutant.rs");
        let gated = on.attrs.iter().any(|a| {
            a.path().is_ident("cfg") && a.parse_args::<syn::Ident>().is_ok_and(|i| i == "mutants")
        });
        assert!(gated, "fn on must carry #[cfg(mutants)]");
    }
}

#[cfg(all(test, mutants))]
mod mutants_build {
    fn sites() -> (u8, u8) {
        (mutant!("PA", 1, 0), mutant!("PB", 1, 0))
    }

    /// Only the site whose ID is switched on takes its mutated arm; an ID no
    /// site carries, or no switch, leaves every site original.
    #[test]
    fn only_the_named_site_switches_on() {
        for (switch, want) in [
            (Some("PA"), "1 0"),
            (Some("PB"), "0 1"),
            (Some("PZ"), "0 0"),
            (None, "0 0"),
        ] {
            let out = super::run_child("mutant::mutants_build::child_reports_its_sites", switch);
            assert!(
                out.contains(&format!("MUTANT-SITES {want}")),
                "switch {switch:?}: child output: {out}"
            );
        }
    }

    #[test]
    fn child_reports_its_sites() {
        if !super::is_child() {
            return;
        }
        let (a, b) = sites();
        println!("MUTANT-SITES {a} {b}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the clap-derived CLI inventory walker (MIK-8170).
//!
//! Ungated, so a default `cargo test` runs them: each pins one clap feature
//! the walker must report, so a regression there fails here, not in review.

#[path = "common/cli_inventory_walker.rs"]
mod walker;

use clap::{Arg, ArgAction, Command};

fn ids(cmd: &Command) -> Vec<String> {
    let w = walker::walk(cmd);
    assert!(w.errors.is_empty(), "{:?}", w.errors);
    w.items.keys().cloned().collect()
}

fn has(cmd: &Command, id: &str) -> bool {
    ids(cmd).iter().any(|i| i == id)
}

fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}

#[test]
fn long_short_and_hidden_flags_are_items() {
    let cmd = Command::new("x")
        .arg(flag("force").short('f'))
        .arg(flag("quiet").hide(true));
    let got = ids(&cmd);
    for want in ["x", "x --force", "x -f", "x --quiet", "x --help", "x -h"] {
        assert!(got.iter().any(|i| i == want), "{want} missing from {got:?}");
    }
}

#[test]
fn arg_aliases_and_short_aliases_point_at_their_long_form() {
    let cmd = Command::new("x").arg(flag("config").alias("cfg").short_alias('k'));
    let w = walker::walk(&cmd);
    assert_eq!(w.items.get("x --cfg"), Some(&Some("x --config".to_owned())));
    assert_eq!(w.items.get("x -k"), Some(&Some("x --config".to_owned())));
}

#[test]
fn a_short_only_arg_is_its_own_canonical_row() {
    let cmd = Command::new("x").arg(
        Arg::new("v")
            .short('v')
            .short_alias('V')
            .action(ArgAction::Count),
    );
    let w = walker::walk(&cmd);
    assert_eq!(w.items.get("x -v"), Some(&None));
    assert_eq!(w.items.get("x -V"), Some(&Some("x -v".to_owned())));
}

#[test]
fn subcommands_their_aliases_and_flag_forms_are_items() {
    let cmd = Command::new("x").subcommand(
        Command::new("serve")
            .alias("run")
            .visible_alias("start")
            .short_flag('S')
            .long_flag("serve-now"),
    );
    let w = walker::walk(&cmd);
    for (id, target) in [
        ("x run", "x serve"),
        ("x start", "x serve"),
        ("x -S", "x serve"),
        ("x --serve-now", "x serve"),
    ] {
        assert_eq!(w.items.get(id), Some(&Some(target.to_owned())), "{id}");
    }
    assert!(w.items.contains_key("x serve"));
}

#[test]
fn a_hidden_subcommand_is_an_item() {
    assert!(has(
        &Command::new("x").subcommand(Command::new("debug").hide(true)),
        "x debug"
    ));
}

#[test]
fn an_external_subcommand_command_needs_a_wildcard_row() {
    let cmd = Command::new("x").allow_external_subcommands(true);
    assert!(has(&cmd, "x <external>"));
}

#[test]
fn generated_help_and_version_follow_the_command_settings() {
    let on = Command::new("x").version("1");
    for want in ["x --help", "x -h", "x --version", "x -V"] {
        assert!(has(&on, want), "{want}");
    }
    let off = Command::new("x")
        .version("1")
        .disable_help_flag(true)
        .disable_version_flag(true);
    assert!(
        !has(&off, "x --help") && !has(&off, "x --version"),
        "{:?}",
        ids(&off)
    );
    let propagated = Command::new("x")
        .version("1")
        .propagate_version(true)
        .subcommand(Command::new("a"));
    assert!(has(&propagated, "x a --version"), "{:?}", ids(&propagated));
}

#[test]
fn a_generated_help_subcommand_is_one_item_per_level_and_not_walked() {
    let cmd = Command::new("x").subcommand(Command::new("cap").subcommand(Command::new("list")));
    let got = ids(&cmd);
    assert!(got.iter().any(|i| i == "x help"), "{got:?}");
    assert!(got.iter().any(|i| i == "x cap help"), "{got:?}");
    assert!(
        !got.iter().any(|i| i.starts_with("x help ")),
        "help subtree walked: {got:?}"
    );
}

#[test]
fn a_global_arg_is_listed_where_it_is_defined_and_a_local_redefinition_too() {
    let cmd = Command::new("x")
        .arg(Arg::new("config").long("config").global(true))
        .subcommand(Command::new("a"))
        .subcommand(Command::new("b").arg(Arg::new("config").long("config")));
    let got = ids(&cmd);
    assert!(got.iter().any(|i| i == "x --config"), "{got:?}");
    assert!(
        !got.iter().any(|i| i == "x a --config"),
        "inherited copy listed: {got:?}"
    );
    assert!(
        got.iter().any(|i| i == "x b --config"),
        "local redefinition missing: {got:?}"
    );
}

#[test]
fn an_arg_added_at_build_time_is_a_walk_error() {
    let cmd = Command::new("x").subcommand(Command::new("a").defer(|c| c.arg(flag("late"))));
    let w = walker::walk(&cmd);
    assert!(
        w.errors.iter().any(|e| e.contains("`late`")),
        "{:?}",
        w.errors
    );
}

#[test]
fn two_positionals_with_one_value_name_collide() {
    let cmd = Command::new("x")
        .arg(Arg::new("src").value_name("PATH"))
        .arg(Arg::new("dst").value_name("PATH"));
    let w = walker::walk(&cmd);
    assert!(
        w.errors
            .iter()
            .any(|e| e.contains("collision") && e.contains("<PATH>")),
        "{:?}",
        w.errors
    );
}

#[test]
fn a_positional_uses_its_value_name_else_its_id_as_written() {
    let cmd = Command::new("x")
        .arg(Arg::new("DESCRIPTOR").value_name("DESCRIPTOR"))
        .arg(Arg::new("target"));
    let got = ids(&cmd);
    assert!(
        got.iter().any(|i| i == "x <DESCRIPTOR>") && got.iter().any(|i| i == "x <target>"),
        "{got:?}"
    );
}

#[test]
fn a_derived_positional_is_named_as_clap_displays_it() {
    #[derive(clap::Parser)]
    #[command(name = "x")]
    struct Cli {
        target: String,
        #[arg(value_name = "KEY=VALUE")]
        pairs: Vec<String>,
    }
    let got = ids(&<Cli as clap::CommandFactory>::command());
    assert!(got.iter().any(|i| i == "x <TARGET>"), "{got:?}");
    assert!(got.iter().any(|i| i == "x <KEY=VALUE>"), "{got:?}");
}

const DOC: &str =
    "## Surface: cli\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n";

fn row(item: &str, class: &str) -> String {
    format!("| `{item}` | {class} | r | - | src/cli/mod.rs:1 |\n")
}

#[test]
fn compare_reports_missing_stale_and_alias_class() {
    let cmd = Command::new("x")
        .disable_help_flag(true)
        .arg(flag("config").short('c'));
    let w = walker::walk(&cmd);
    let full = format!(
        "{DOC}{}{}{}",
        row("x", "KEEP"),
        row("x --config", "KEEP"),
        row("x -c", "KEEP")
    );
    assert_eq!(
        walker::compare(&w, &walker::doc_rows(&full)),
        Vec::<String>::new()
    );
    let missing = format!("{DOC}{}{}", row("x", "KEEP"), row("x --config", "KEEP"));
    assert!(
        walker::compare(&w, &walker::doc_rows(&missing))
            .iter()
            .any(|e| e == "missing row: `x -c`")
    );
    let stale = format!("{full}{}", row("x --gone", "KEEP"));
    assert!(
        walker::compare(&w, &walker::doc_rows(&stale))
            .iter()
            .any(|e| e.starts_with("stale row: `x --gone`"))
    );
    let differs = full.replace("| `x -c` | KEEP |", "| `x -c` | REMOVE |");
    assert!(
        walker::compare(&w, &walker::doc_rows(&differs))
            .iter()
            .any(|e| e.contains("alias `x -c` is REMOVE"))
    );
}

#[test]
fn doc_rows_reads_only_the_cli_table() {
    let md = format!(
        "## Surface: env\n| Item | Class |\n|---|---|\n| `A` | KEEP |\n{DOC}{}## Next\n| `B` | KEEP |\n",
        row("x", "KEEP")
    );
    let rows = walker::doc_rows(&md);
    assert_eq!(rows.keys().collect::<Vec<_>>(), vec!["x"]);
}

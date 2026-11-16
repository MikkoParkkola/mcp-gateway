// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI side of web UI parity (the approved remote-administration
//! design, Part A): every change the web UI can make has a CLI form, and
//! every CLI subcommand and every config write site in the CLI is classified
//! for remote use. Each table is checked against its source of truth: the
//! access table (which the router agreement test keeps equal to the mounted
//! routes), clap's command tree, and the CLI's own source.

use std::collections::BTreeSet;

use clap::CommandFactory;

use super::access_table::plain_rows;
use crate::gateway::routes;

/// What a change the web UI can make is about.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    /// A config change, by area (backends, discovery, capabilities, import,
    /// previews, settings, reload).
    Config(&'static str),
    /// Not a config change, with the reason.
    Other(&'static str),
}

/// The CLI command that sends a change. The typed remote commands of the
/// later slices join as variants; until then every form is the generic
/// `mcp-gateway api METHOD PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliForm {
    /// `mcp-gateway api METHOD PATH`.
    Api,
}

/// One change the web UI can make: its route, what it is, and its CLI form.
pub(crate) struct UiChange {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) kind: Kind,
    pub(crate) cli: CliForm,
}

const fn change(method: &'static str, path: &'static str, kind: Kind) -> UiChange {
    UiChange {
        method,
        path,
        kind,
        cli: CliForm::Api,
    }
}

use Kind::{Config, Other};

/// Every non-GET route of the access table, once.
pub(crate) const UI_CHANGES: &[UiChange] = &[
    change(
        "POST",
        routes::UI_TOOLS_CALL,
        Other("calls a tool; changes no config"),
    ),
    change(
        "POST",
        routes::UI_DECISIONS_RESOLVE,
        Other("resolves a pending decision"),
    ),
    change(
        "POST",
        routes::UI_KEYS,
        Other("creates an API key (key lifecycle)"),
    ),
    change(
        "POST",
        routes::UI_KEY_SERVER_LOOKUP_EMAIL,
        Other("looks up an email at the key server"),
    ),
    change(
        "DELETE",
        routes::UI_KEYS_NAME,
        Other("revokes an API key (key lifecycle)"),
    ),
    change(
        "POST",
        routes::UI_DEAD_LETTERS_REPLAY,
        Other("replays failed event deliveries"),
    ),
    change(
        "POST",
        routes::UI_DEAD_LETTER_REPLAY,
        Other("replays one failed event delivery"),
    ),
    change("POST", routes::UI_CAPABILITIES, Config("capabilities")),
    change("PUT", routes::UI_CAPABILITY, Config("capabilities")),
    change("DELETE", routes::UI_CAPABILITY, Config("capabilities")),
    change(
        "POST",
        routes::UI_CAPABILITY_VALIDATE,
        Config("capabilities"),
    ),
    change("POST", routes::UI_BACKENDS, Config("backends")),
    change("DELETE", routes::UI_BACKEND, Config("backends")),
    change("PATCH", routes::UI_BACKEND, Config("backends")),
    change("POST", routes::UI_BACKEND_REVIVE, Config("backends")),
    change(
        "POST",
        routes::UI_BACKEND_SIGNIN,
        Other("starts a backend sign-in in the browser"),
    ),
    change(
        "POST",
        routes::UI_BACKEND_SIGNIN_CONFIRM,
        Other("confirms a backend sign-in"),
    ),
    change("POST", routes::UI_SETTINGS_DIFF, Config("settings")),
    change("POST", routes::UI_SETTINGS, Config("settings")),
    change(
        "DELETE",
        routes::UI_SETTINGS_UNUSED_ENTRY,
        Config("settings"),
    ),
    change("POST", routes::UI_DISCOVERY_ADOPT, Config("discovery")),
    change("POST", routes::UI_IMPORT_PREVIEW, Config("import")),
    change("POST", routes::UI_IMPORT, Config("import")),
    change("POST", routes::UI_PREVIEWS, Config("previews")),
    change(
        "POST",
        routes::UI_CONTROL_PLANE_GRANTS,
        Other("asks for a control-plane grant"),
    ),
    change(
        "POST",
        routes::UI_CONTROL_PLANE_POLICIES,
        Other("proposes a control-plane policy"),
    ),
    change(
        "POST",
        routes::UI_CONTROL_PLANE_DECISIONS,
        Other("records a control-plane decision"),
    ),
    change("POST", routes::UI_RELOAD, Config("reload")),
    change(
        "POST",
        routes::UI_GATEWAY_RESTART,
        Other("restarts the gateway (off in this release)"),
    ),
    change(
        "POST",
        routes::UI_DASHBOARD_LINK,
        Other("mints a dashboard sign-in link"),
    ),
];

/// What a CLI subcommand does about writes on the CLI's machine.
#[derive(Debug, Clone, Copy)]
enum Class {
    /// Writes nothing locally, with what it does instead.
    NoLocalWrite(&'static str),
    /// Sends, or gets in a later slice, the web UI change named here.
    Remote {
        method: &'static str,
        path: &'static str,
        note: &'static str,
    },
    /// Writes on this host and stays local, with the reason.
    LocalOnly(&'static str),
    /// A follow-up in the design's Part B (G1 to G9), with the reason.
    PartB(u8, &'static str),
}

/// One leaf subcommand of the CLI (`help` excluded), whether this build has
/// it, and its class.
struct CliCommand {
    path: &'static str,
    built: bool,
    class: Class,
}

const fn cmd(path: &'static str, class: Class) -> CliCommand {
    CliCommand {
        path,
        built: true,
        class,
    }
}

use Class::{LocalOnly, NoLocalWrite, PartB, Remote};

const HOST_STORE: &str = "the credential store is bound to this host";
const LOCAL_READ: &str = "reads local files; refuses a gateway destination";
const SKILLS: &str = "writes local skills artifacts and their registry";
const TLS: &str = "writes private keys on this host";

/// Every leaf subcommand clap builds, in the design's local-writer classes.
const CLI_COMMANDS: &[CliCommand] = &[
    cmd("accounts init-store", LocalOnly(HOST_STORE)),
    cmd("accounts migrate-credentials", LocalOnly(HOST_STORE)),
    cmd(
        "add",
        Remote {
            method: "POST",
            path: routes::UI_BACKENDS,
            note: "remote form in slice 2; bootstrap without a config stays local",
        },
    ),
    cmd("api", NoLocalWrite("sends one UI API request")),
    cmd(
        "audit lookup-email",
        NoLocalWrite("asks the gateway; writes nothing"),
    ),
    cmd("audit show", NoLocalWrite("reads the local audit log")),
    cmd("audit verify", NoLocalWrite("verifies the local audit log")),
    cmd(
        "cap discover",
        PartB(1, "--write-config adds discovered servers to the config"),
    ),
    cmd(
        "cap import",
        Remote {
            method: "POST",
            path: routes::UI_IMPORT,
            note: "remote form in slice 3; local generation options stay local (G3)",
        },
    ),
    CliCommand {
        path: "cap import-url",
        built: cfg!(feature = "discovery"),
        class: PartB(3, "the local discovery engine writes capability files"),
    },
    cmd(
        "cap install",
        PartB(5, "installs capability files from GitHub"),
    ),
    cmd("cap list", NoLocalWrite(LOCAL_READ)),
    cmd("cap pin", PartB(6, "repins a capability file")),
    cmd("cap registry-list", NoLocalWrite("lists the registry")),
    cmd("cap search", NoLocalWrite("searches the registry")),
    cmd("cap test", NoLocalWrite("runs one capability")),
    cmd("cap validate", NoLocalWrite(LOCAL_READ)),
    cmd(
        "dashboard-link",
        Remote {
            method: "POST",
            path: routes::UI_DASHBOARD_LINK,
            note: "already remote",
        },
    ),
    cmd("doctor", NoLocalWrite("checks; its --fix writes nothing")),
    cmd(
        "events dead-letters",
        Remote {
            method: "POST",
            path: routes::UI_DEAD_LETTER_REPLAY,
            note: "already remote",
        },
    ),
    cmd("get", NoLocalWrite(LOCAL_READ)),
    cmd("hash-key", NoLocalWrite("prints or checks a digest")),
    cmd(
        "identity grants grant",
        PartB(7, "edits the local identity grants file"),
    ),
    cmd("identity grants list", NoLocalWrite(LOCAL_READ)),
    cmd(
        "identity grants revoke",
        PartB(7, "edits the local identity grants file"),
    ),
    cmd("import apply", PartB(4, "writes protocol-import drafts")),
    cmd(
        "import preview",
        NoLocalWrite("prints a protocol-import preview"),
    ),
    cmd("init", LocalOnly("writes a starter config on this host")),
    cmd(
        "kubernetes apply-plan",
        LocalOnly("runs a cluster command, not a gateway change"),
    ),
    cmd(
        "kubernetes controller",
        NoLocalWrite("reconciles a resources file and prints it"),
    ),
    cmd("kubernetes plan", NoLocalWrite("prints a plan")),
    cmd("list", NoLocalWrite(LOCAL_READ)),
    cmd("provenance public-key", NoLocalWrite("prints a public key")),
    cmd("provenance verify", NoLocalWrite("verifies a signature")),
    cmd("ranking eval", NoLocalWrite("prints an evaluation")),
    cmd(
        "remove",
        Remote {
            method: "DELETE",
            path: routes::UI_BACKEND,
            note: "remote form in slice 2",
        },
    ),
    CliCommand {
        path: "runtime compile",
        built: cfg!(feature = "runtime-substrate"),
        class: NoLocalWrite("prints the compiled bundle"),
    },
    cmd("serve", LocalOnly("runs the gateway on this host")),
    CliCommand {
        path: "setup export",
        built: cfg!(feature = "config-export"),
        class: LocalOnly("writes an AI client's own config and its backup"),
    },
    cmd("setup wizard", LocalOnly("first-time setup on this host")),
    cmd("skills generate", LocalOnly(SKILLS)),
    cmd("skills import", LocalOnly(SKILLS)),
    cmd("skills list", NoLocalWrite("lists local skills")),
    cmd("skills remove", LocalOnly(SKILLS)),
    cmd("skills search", NoLocalWrite("searches skills")),
    cmd("skills show", NoLocalWrite("prints a skill")),
    cmd("stats", NoLocalWrite("reads gateway statistics")),
    cmd("tls init-ca", LocalOnly(TLS)),
    cmd("tls issue-client", LocalOnly(TLS)),
    cmd("tls issue-server", LocalOnly(TLS)),
    cmd("tool completions", NoLocalWrite("prints shell completions")),
    cmd("tool inspect", NoLocalWrite("prints a tool")),
    cmd("tool invoke", NoLocalWrite("calls a tool")),
    cmd("tool list", NoLocalWrite("lists tools")),
    cmd("trust generate", LocalOnly("writes a trust document")),
    cmd("trust inspect", NoLocalWrite("prints a trust document")),
    cmd(
        "trust lab evaluate",
        LocalOnly("writes evaluation baselines"),
    ),
    cmd("trust validate", NoLocalWrite("validates a trust document")),
    cmd("upgrade", PartB(8, "migrates local config files")),
    cmd("validate", PartB(5, "--fix rewrites capability files")),
];

/// One call in the CLI's production source of a shared config writer: its
/// file, the fn it sits in, and its class.
struct WriteSite {
    file: &'static str,
    func: &'static str,
    class: Class,
}

const fn site(file: &'static str, func: &'static str, class: Class) -> WriteSite {
    WriteSite { file, func, class }
}

/// The shared writers a CLI command persists config through: the config
/// writer's in-place splice and alias rewrite, and the persistence layer's
/// atomic writes and backup copy. `src/commands/config_write.rs` is the
/// writer itself and is not scanned.
const WRITERS: [&str; 5] = [
    "config_write::write(",
    "rewrite_url_aliases_in(",
    "config_persistence::write_atomic(",
    "config_persistence::write_text_atomic(",
    "config_persistence::copy_keeping_access(",
];

const CLIENT_CONFIG: &str = "an AI client's own config file on this host";
const UPGRADE: &str = "migrates local config files";

/// Every call site of a [`WRITERS`] entry under src/commands and src/cli.
const CONFIG_WRITES: &[WriteSite] = &[
    site(
        "src/cli/entry.rs",
        "write_discovered_to_config",
        PartB(1, "adds discovered servers to the config"),
    ),
    site(
        "src/commands/add_remove.rs",
        "run_add_command",
        Remote {
            method: "POST",
            path: routes::UI_BACKENDS,
            note: "remote form in slice 2",
        },
    ),
    site(
        "src/commands/add_remove.rs",
        "run_remove_command",
        Remote {
            method: "DELETE",
            path: routes::UI_BACKEND,
            note: "remote form in slice 2",
        },
    ),
    site(
        "src/commands/config_export/mod.rs",
        "create_backup",
        LocalOnly(CLIENT_CONFIG),
    ),
    site(
        "src/commands/config_export/mod.rs",
        "merge_into_config",
        LocalOnly(CLIENT_CONFIG),
    ),
    site(
        "src/commands/config_export/mod.rs",
        "rollback_client_config",
        LocalOnly(CLIENT_CONFIG),
    ),
    site(
        "src/commands/protocol_import.rs",
        "write_atomic",
        PartB(4, "writes protocol-import drafts"),
    ),
    site(
        "src/commands/setup.rs",
        "import_servers",
        LocalOnly("first-time setup on this host"),
    ),
    site(
        "src/commands/upgrade.rs",
        "backup_config",
        PartB(8, UPGRADE),
    ),
    site("src/commands/upgrade.rs", "write_stamp", PartB(8, UPGRADE)),
    site(
        "src/commands/upgrade_url_keys.rs",
        "run_upgrade_with_config",
        PartB(8, UPGRADE),
    ),
];

/// `path` with each `{param}` segment replaced by `x`.
pub(crate) fn filled(path: &str) -> String {
    path.split('/')
        .map(|s| {
            if s.starts_with('{') && s.ends_with('}') {
                "x"
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Every leaf subcommand path under `command`, `help` excluded.
fn leaves(command: &clap::Command, prefix: &str, out: &mut BTreeSet<String>) {
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let path = if prefix.is_empty() {
            sub.get_name().to_owned()
        } else {
            format!("{prefix} {}", sub.get_name())
        };
        if sub.has_subcommands() {
            leaves(sub, &path, out);
        } else {
            out.insert(path);
        }
    }
}

/// Whether a file or directory name is test code only: a `tests` directory or
/// file, a `_tests.rs` sibling, or a test-support file.
fn test_only_name(name: &str) -> bool {
    name == "tests"
        || name == "tests.rs"
        || name.ends_with("_tests.rs")
        || name.ends_with("_test_support.rs")
        || name.starts_with("test_")
}

/// The production `.rs` files under `dir`, as crate-relative `/` paths; test
/// files and the writer itself are left out.
fn production_files(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if test_only_name(name) {
            continue;
        }
        if path.is_dir() {
            production_files(root, &path, out);
        } else if name.ends_with(".rs") {
            let rel = path.strip_prefix(root).expect("under the crate root");
            let rel: Vec<_> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect();
            let rel = rel.join("/");
            if rel != "src/commands/config_write.rs" {
                out.push(rel);
            }
        }
    }
}

/// Every call of a [`WRITERS`] entry in the CLI's production code, as
/// (file, enclosing fn); comments, strings and test-only items are blanked.
fn write_sites() -> BTreeSet<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src/commands", "src/cli"] {
        production_files(root, &root.join(dir), &mut files);
    }
    let fn_name = regex::Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").expect("pattern");
    let mut sites = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(&file)).expect("read a source file");
        let code =
            crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
        for needle in WRITERS {
            for (at, _) in code.match_indices(needle) {
                let func = fn_name
                    .captures_iter(&code[..at])
                    .last()
                    .map_or_else(|| "?".to_owned(), |c| c[1].to_owned());
                sites.insert((file.clone(), func));
            }
        }
    }
    sites
}

/// Whether `set` and `table` differ, as a message naming each side's extras.
fn difference(
    set: &BTreeSet<String>,
    table: &BTreeSet<String>,
    only_set: &str,
    only_table: &str,
) -> String {
    let a: Vec<_> = set.difference(table).collect();
    let b: Vec<_> = table.difference(set).collect();
    if a.is_empty() && b.is_empty() {
        String::new()
    } else {
        format!("{only_set}: {a:?}; {only_table}: {b:?}")
    }
}

/// Every non-GET route of the access table has exactly one table entry, and
/// no entry names a route the access table (so the router) does not have.
#[test]
fn every_ui_change_has_one_cli_form() {
    let rows: BTreeSet<String> = plain_rows()
        .into_iter()
        .filter(|(_, method, _, _)| *method != "GET")
        .map(|(path, method, _, _)| format!("{method} {path}"))
        .collect();
    assert!(
        rows.len() >= 20,
        "premise: the access table has its changes, saw {}",
        rows.len()
    );
    let mut table = BTreeSet::new();
    for c in UI_CHANGES {
        let key = format!("{} {}", c.method, c.path);
        assert!(table.insert(key.clone()), "listed twice: {key}");
    }
    let diff = difference(
        &rows,
        &table,
        "UI changes with no CLI form",
        "entries the router does not mount",
    );
    assert!(diff.is_empty(), "{diff}");
}

/// Every leaf subcommand clap builds in this build is classified, and no
/// entry names one it does not build.
#[test]
fn every_cli_subcommand_is_classified() {
    let mut built = BTreeSet::new();
    leaves(&crate::cli::Cli::command(), "", &mut built);
    assert!(
        built.len() >= 40,
        "premise: clap builds the CLI, saw {} leaves",
        built.len()
    );
    let mut all = BTreeSet::new();
    for c in CLI_COMMANDS {
        assert!(all.insert(c.path), "listed twice: {}", c.path);
    }
    let table: BTreeSet<String> = CLI_COMMANDS
        .iter()
        .filter(|c| c.built)
        .map(|c| c.path.to_owned())
        .collect();
    let diff = difference(
        &built,
        &table,
        "unclassified subcommands",
        "entries clap does not build",
    );
    assert!(diff.is_empty(), "{diff}");
}

/// Every call of a shared config writer in the CLI's production code is
/// classified by file and fn, and no entry names a call that is gone.
#[test]
fn every_config_write_site_is_classified() {
    let found: BTreeSet<String> = write_sites()
        .into_iter()
        .map(|(file, func)| format!("{file} {func}"))
        .collect();
    assert!(
        found
            .iter()
            .any(|s| s.starts_with("src/commands/add_remove.rs ")),
        "premise: the scan sees the add command's write, found {found:?}"
    );
    let mut table = BTreeSet::new();
    for s in CONFIG_WRITES {
        let key = format!("{} {}", s.file, s.func);
        assert!(table.insert(key.clone()), "listed twice: {key}");
    }
    let diff = difference(
        &found,
        &table,
        "unclassified write sites",
        "entries with no write",
    );
    assert!(diff.is_empty(), "{diff}");
}

/// Every class that claims a remote form names a change in [`UI_CHANGES`].
#[test]
fn each_remote_class_names_a_ui_change() {
    let changes: BTreeSet<(&str, &str)> = UI_CHANGES.iter().map(|c| (c.method, c.path)).collect();
    let classes = CLI_COMMANDS.iter().map(|c| (c.path, c.class));
    let classes = classes.chain(CONFIG_WRITES.iter().map(|s| (s.func, s.class)));
    let mut remote = 0;
    for (name, class) in classes {
        if let Remote { method, path, .. } = class {
            remote += 1;
            assert!(
                changes.contains(&(method, path)),
                "{name}: {method} {path} is not a UI change"
            );
        }
    }
    assert!(
        remote >= 2,
        "premise: some entries are remote forms, saw {remote}"
    );
}

/// Every entry says why: no empty reason, area or note, and each Part B item
/// is one of G1 to G9.
#[test]
fn every_entry_gives_its_reason() {
    for c in UI_CHANGES {
        let (Config(why) | Other(why)) = c.kind;
        assert!(!why.is_empty(), "{} {}: no reason", c.method, c.path);
    }
    let classes = CLI_COMMANDS.iter().map(|c| (c.path, c.class));
    for (name, class) in classes.chain(CONFIG_WRITES.iter().map(|s| (s.func, s.class))) {
        let why = match class {
            NoLocalWrite(why) | LocalOnly(why) => why,
            Remote { note, .. } => note,
            PartB(item, why) => {
                assert!(
                    (1..=9).contains(&item),
                    "{name}: G{item} is not a Part B item"
                );
                why
            }
        };
        assert!(!why.is_empty(), "{name}: no reason");
    }
}

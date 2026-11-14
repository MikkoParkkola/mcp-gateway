// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source scans for the captured invocation (test plan H11, rows INV-22, MAIN-1,
//! API-1, API-2): production text only, comments and literals blanked, paths
//! anchored at the manifest, each with a positive control.

use std::path::{Path, PathBuf};

use crate::test_source_text::{production_text, sanitize};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap()
}

/// Code only, whitespace collapsed to single spaces.
fn flat(text: &str) -> String {
    sanitize(&production_text(text))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// INV-22: the capture is `cli::run`'s first statement, in the frozen shape,
/// before tracing.
#[test]
fn inv22_capture_is_the_first_statement_of_cli_run() {
    let text = read("src/cli/entry.rs");
    let code: String = production_text(&text)
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let code = code.split_whitespace().collect::<Vec<_>>().join(" ");
    let head = "pub fn run(args: Cli) -> ExitCode { ";
    let at = code.find(head).expect("positive control: cli::run found") + head.len();
    let want = "crate::restart::invocation::capture_and_install( \
                crate::restart::invocation::CaptureInputs { \
                args: std::env::args_os().collect(), \
                cwd: std::env::current_dir(), \
                path_env: std::env::var_os(\"PATH\"), \
                #[cfg(unix)] mask: crate::restart::invocation::current_thread_mask(), \
                }, &args, );";
    assert!(
        code[at..].starts_with(want),
        "first statement: {}",
        &code[at..at + 300_usize.min(code.len() - at)]
    );
    assert!(
        code[at + want.len()..].contains("setup_tracing("),
        "positive control: setup_tracing after the capture"
    );
}

/// MAIN-1: main.rs hands `Cli::parse()`'s value to `cli::run` unchanged.
#[test]
fn main1_main_passes_the_parsed_cli_unchanged() {
    let code = flat(&read("src/main.rs"));
    assert!(
        code.contains("let cli = Cli::parse(); cli::run(cli)"),
        "{code}"
    );
}

fn production_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if !name.ends_with("_tests") {
                production_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// Each `pub` token not followed by `(`: a public item.
fn public_items(code: &str) -> Vec<usize> {
    let b = code.as_bytes();
    let mut found = Vec::new();
    for (i, _) in code.match_indices("pub") {
        let before = i.checked_sub(1).map(|j| b[j]);
        let after = b.get(i + 3).copied();
        let word = before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b'_'))
            && after.is_some_and(|c| !(c.is_ascii_alphanumeric() || c == b'_'));
        if word && !code[i + 3..].trim_start().starts_with('(') {
            found.push(i);
        }
    }
    found
}

/// API-1: nothing under src/restart/ is public, and lib.rs keeps the
/// module private.
#[test]
fn api1_restart_items_are_crate_private() {
    let dir = root().join("src/restart");
    let mut files = Vec::new();
    production_files(&dir, &mut files);
    let mut names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["invocation.rs", "mod.rs"], "inventory");
    for file in &files {
        let code = sanitize(&production_text(&std::fs::read_to_string(file).unwrap()));
        assert!(
            public_items(&code).is_empty(),
            "public item in {}",
            file.display()
        );
        assert!(!code.contains("macro_export"), "{}", file.display());
    }
    let inv = flat(&read("src/restart/invocation.rs"));
    assert!(
        inv.contains("pub(crate) fn invocation()"),
        "positive control"
    );
    let lib = flat(&read("src/lib.rs"));
    assert!(lib.contains("mod restart;"), "positive control: declared");
    assert!(
        !lib.contains("pub mod restart") && !lib.contains("restart::"),
        "lib.rs exposes restart"
    );
}

/// API-2: `cli::run` is the only production caller of the capture, so
/// `Gateway::run` and every other entry cannot enable restart.
#[test]
fn api2_capture_has_one_production_caller() {
    let mut files = Vec::new();
    production_files(&root().join("src"), &mut files);
    let rel = |p: &Path| {
        p.strip_prefix(root())
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
    };
    let names: Vec<String> = files.iter().map(|p| rel(p)).collect();
    assert!(
        names.len() > 500,
        "positive control: {} files read",
        names.len()
    );
    for must in ["src/cli/entry.rs", "src/gateway/mod.rs"] {
        assert!(
            names.iter().any(|n| n == must),
            "positive control: {must} read"
        );
    }
    let mut callers = Vec::new();
    for (file, name) in files.iter().zip(&names) {
        let code = sanitize(&production_text(&std::fs::read_to_string(file).unwrap()));
        let calls = code.matches("capture_and_install(").count()
            - code.matches("fn capture_and_install(").count();
        for _ in 0..calls {
            callers.push(name.clone());
        }
    }
    assert_eq!(callers, ["src/cli/entry.rs"]);
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! windows-portability family (Family-fix: MIK-7911): path handling and
//! shell or YAML quoting written for Unix, once per place instead of once.
//! Every Windows-sensitive fixture helper goes through every consumer that
//! reads its output, on every host, and no second copy of a helper, nor a
//! second way of spelling a path for a capability child, may appear.

#[path = "common/windows_paths.rs"]
mod windows_paths;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mcp_gateway::transport::{split_command_unix, split_command_windows};
use windows_paths::{hostile_home, sh_path, yaml_single_quoted};

/// Helpers that exist once, in `tests/common/windows_paths.rs`. A `fn` of one
/// of these names defined anywhere else under `tests/` is a second copy.
const HELPERS: [&str; 4] = [
    "sh_path",
    "yaml_single_quoted",
    "hostile_home",
    "spaced_home",
];

/// Every `canonicalize(` call in the capability executor's non-test code, by
/// (file, enclosing fn, count). `cli::canonical` is the one spelling a child
/// is handed (MIK-7911); `spelled` checks the plain form resolves back;
/// `confine` compares the verbatim forms; `save` canonicalizes its own local
/// download root, which is never handed to a child.
const CANONICALIZE_SITES: [(&str, &str, usize); 4] = [
    ("cli.rs", "canonical", 1),
    ("cli.rs", "spelled", 1),
    ("cli.rs", "confine", 2),
    ("save_file.rs", "save", 1),
];

/// Paths a fixture can hand a shell: a real temp home with a space and an
/// apostrophe, and fixed Windows and Unix spellings of the same hazards.
fn hostile_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("peer.sh"),
        PathBuf::from(r"C:\Users\O'Brien\a b\peer.sh"),
        PathBuf::from("/tmp/a b/o'peer.sh"),
    ]
}

#[test]
fn every_windows_sensitive_helper_round_trips_a_hostile_path() {
    let home = hostile_home();
    let shown = home.path().display().to_string();
    assert!(shown.contains(' ') && shown.contains('\''), "{shown}");
    for path in hostile_paths(home.path()) {
        let expected = path.display().to_string().replace('\\', "/");
        let command = format!("sh {}", sh_path(&path));
        let argv = Some(vec!["sh".to_string(), expected.clone()]);
        assert_eq!(split_command_unix(&command), argv, "POSIX split: {command}");
        assert_eq!(
            split_command_windows(&command),
            argv,
            "Windows split: {command}"
        );
        let yaml = format!("command: {}", yaml_single_quoted(&command));
        let read: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("valid YAML");
        assert_eq!(read["command"].as_str(), Some(command.as_str()), "{yaml}");
        let printed = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", sh_path(&path)))
            .output()
            .expect("sh runs");
        assert_eq!(
            String::from_utf8_lossy(&printed.stdout),
            expected,
            "sh: {command}"
        );
    }
}

/// `line` as code: string literal contents blanked to `""`, and a `//`
/// outside a literal ends it. Lexical, per the design's stop rule.
fn code_of(line: &str) -> String {
    let mut code = String::new();
    let mut chars = line.trim_start().chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    in_string = false;
                    code.push('"');
                }
                _ => {}
            }
        } else if c == '/' && chars.peek() == Some(&'/') {
            break;
        } else {
            in_string = c == '"';
            code.push(c);
        }
    }
    code
}

/// Code lines in `text` that define one of [`HELPERS`]: comments and string
/// literals do not count.
fn helper_copies(file: &str, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = code_of(line);
        for name in HELPERS {
            let def = format!("fn {name}");
            let defines = code.match_indices(&def).any(|(at, _)| {
                let next = code[at + def.len()..].chars().next();
                !next.is_some_and(|c| c.is_alphanumeric() || c == '_')
            });
            if defines {
                found.push(format!("{file}:{} defines {name}", n + 1));
            }
        }
    }
    found
}

/// `canonicalize(` calls in `text` by enclosing fn (the latest `fn` seen),
/// each with the line it is on.
fn canonicalize_sites(file: &str, text: &str) -> BTreeMap<(String, String), Vec<usize>> {
    let mut sites = BTreeMap::new();
    let mut current = String::new();
    for (n, line) in text.lines().enumerate() {
        let code = code_of(line);
        if let Some(at) = code.find("fn ") {
            let name: String = code[at + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                current = name;
            }
        }
        for _ in code.matches("canonicalize(") {
            sites
                .entry((file.to_string(), current.clone()))
                .or_insert_with(Vec::new)
                .push(n + 1);
        }
    }
    sites
}

/// How many calls each (file, fn) holds.
fn counts(sites: &BTreeMap<(String, String), Vec<usize>>) -> BTreeMap<(String, String), usize> {
    sites
        .iter()
        .map(|(at, lines)| (at.clone(), lines.len()))
        .collect()
}

fn key(file: &str, function: &str) -> (String, String) {
    (file.to_string(), function.to_string())
}

fn allowed_sites() -> BTreeMap<(String, String), usize> {
    CANONICALIZE_SITES
        .iter()
        .map(|(file, function, n)| (key(file, function), *n))
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_second_copy_of_a_windows_sensitive_helper_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("tests"), &mut files);
    let mut copies = Vec::new();
    for path in &files {
        let shown = path
            .strip_prefix(root)
            .expect("under the root")
            .display()
            .to_string();
        let shown = shown.replace('\\', "/");
        if shown == "tests/common/windows_paths.rs" || shown == "tests/windows_portability.rs" {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("readable source");
        copies.extend(helper_copies(&shown, &text));
    }
    assert!(
        copies.is_empty(),
        "use tests/common/windows_paths.rs: {copies:?}"
    );

    let mut sites = BTreeMap::new();
    let dir = root.join("src/capability/executor");
    let mut executor = Vec::new();
    rust_files(&dir, &mut executor);
    for path in executor {
        // Relative to the executor, so two files of one name stay apart.
        let file = path
            .strip_prefix(&dir)
            .expect("under the executor")
            .display()
            .to_string()
            .replace('\\', "/");
        if file.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable source");
        sites.extend(canonicalize_sites(&file, &text));
    }
    assert_eq!(
        counts(&sites),
        allowed_sites(),
        "a path a child is handed goes through cli::canonical; calls by line: {sites:?}"
    );
}

/// The scanners reject what they exist to catch and pass what they must not.
#[test]
fn the_portability_scanners_reject_a_copy_and_pass_a_mention() {
    assert_eq!(
        helper_copies("x.rs", "fn sh_path(path: &Path) -> String {").len(),
        1
    );
    assert_eq!(
        helper_copies("x.rs", "    fn spaced_home() -> TempDir {").len(),
        1
    );
    assert!(helper_copies("x.rs", "// fn sh_path( is shared now").is_empty());
    assert!(helper_copies("x.rs", r#"let s = "fn sh_path(";"#).is_empty());
    assert_eq!(
        helper_copies("x.rs", "fn sh_path<P: AsRef<Path>>(p: P) {").len(),
        1
    );
    assert!(helper_copies("x.rs", "fn sh_path_list() {").is_empty());
    assert!(helper_copies("x.rs", "let a = 1; // fn sh_path( was here").is_empty());

    let confine_three =
        "fn confine() {\n canonicalize(a);\n canonicalize(b);\n canonicalize(c);\n}";
    let sites = canonicalize_sites("cli.rs", confine_three);
    assert_eq!(sites.get(&key("cli.rs", "confine")), Some(&vec![2, 3, 4]));
    assert_eq!(allowed_sites().get(&key("cli.rs", "confine")), Some(&2));
    let stray = canonicalize_sites(
        "mcp.rs",
        "fn bound_roots() {\n std::fs::canonicalize(p);\n}",
    );
    assert_eq!(stray.get(&key("mcp.rs", "bound_roots")), Some(&vec![2]));
    assert!(!allowed_sites().contains_key(&key("mcp.rs", "bound_roots")));
    assert!(canonicalize_sites("cli.rs", "// canonicalize(x)").is_empty());
    let quoted = "fn save() {\n log(\"fn other canonicalize(p) failed\");\n canonicalize(p);\n}";
    let sites = canonicalize_sites("save_file.rs", quoted);
    assert_eq!(
        sites.get(&key("save_file.rs", "save")),
        Some(&vec![3]),
        "{sites:?}"
    );
    assert_eq!(sites.len(), 1, "{sites:?}");
}

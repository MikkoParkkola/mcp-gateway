// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the test stub writer guarantees: a stub it writes holds its contents
//! and runs, it never opens the stub in the test process, and no other test
//! file writes an executable stub of its own.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::test_source_files::rust_files;
use super::test_source_text::sanitize;
use super::test_stub::write_executable;

/// The one product file allowed a shebang plus an executable mode: the uv
/// fetch's interpreter wrapper, written while the preview helper has one
/// thread and no child (its order is pinned by its own row).
const WRAPPER_FILE: &str = "src/preview_sandbox/linux/fetch_uv.rs";
const WRAPPER_MODE: &str = "from_mode(0o555)";

/// Each line of `text` that sets an octal mode with any execute bit, in the
/// three spellings the tree uses, as (line number, trimmed line).
fn executable_modes(text: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for call in ["from_mode(0o", "set_mode(0o", ".mode(0o"] {
            let mut rest = line;
            while let Some(at) = rest.find(call) {
                rest = &rest[at + call.len()..];
                let digits: String = rest.chars().take_while(|c| c.is_digit(8)).collect();
                if u32::from_str_radix(&digits, 8).is_ok_and(|mode| mode & 0o111 != 0) {
                    hits.push((index + 1, line.trim().to_owned()));
                }
            }
        }
    }
    hits
}

/// The places in one file (`rel`, from the package root) that write a stub
/// program themselves: a `"#!/` string literal and an executable mode in the
/// same file. A regression guard for these spellings, not a proof that no
/// stub can be written another way: a mode computed at run time, or a stub
/// with no `#!/` literal, is not seen.
fn stub_writers(rel: &str, text: &str) -> Vec<String> {
    // The helper itself is the one allowed writer.
    if rel == "src/test_stub.rs" || !text.contains("\"#!/") {
        return Vec::new();
    }
    // These rows' fixtures spell the patterns out inside string literals, so
    // in this file only code counts: a real writer beside them is still seen.
    let scanned = if rel == "src/test_stub_tests.rs" {
        sanitize(text)
    } else {
        text.to_owned()
    };
    executable_modes(&scanned)
        .into_iter()
        .filter(|(_, code)| !(rel == WRAPPER_FILE && code.contains(WRAPPER_MODE)))
        .map(|(line, code)| format!("{rel}:{line}: {code}"))
        .collect()
}

/// Whether the wrapper file's text sets the allowed mode exactly once: a second
/// such line would pass through the allowance unseen, and none means the
/// allowance names nothing and goes.
fn wrapper_allowance_holds(text: &str) -> bool {
    executable_modes(text)
        .iter()
        .filter(|(_, code)| code.contains(WRAPPER_MODE))
        .count()
        == 1
}

/// A test that writes and runs its own stub can fail with ETXTBSY when a
/// sibling test forks while the write is open; every stub goes through the
/// helper instead.
#[test]
fn only_the_helper_writes_executable_stubs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    files.sort();
    assert!(
        files.len() > 100,
        "the walk found only {} files under src/ and tests/",
        files.len()
    );
    let mut found = Vec::new();
    let mut wrapper_ok = false;
    for file in &files {
        let rel = file
            .strip_prefix(&root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(file).expect("readable source");
        if rel == WRAPPER_FILE {
            wrapper_ok = wrapper_allowance_holds(&text);
        }
        found.extend(stub_writers(&rel, &text));
    }
    assert!(
        found.is_empty(),
        "write these stubs with crate::test_stub::write_executable, so no test thread holds their write descriptor:\n{}",
        found.join("\n")
    );
    // The allowance names one line: when it goes, the allowance goes too.
    assert!(
        wrapper_ok,
        "{WRAPPER_FILE} no longer sets {WRAPPER_MODE} once; update the allowance"
    );
}

#[test]
fn a_planted_stub_writer_is_named() {
    let planted = "fn put(p: &Path) {\n    write(p, \"#!/bin/sh\\n\");\n    chmod(p, Permissions::from_mode(0o755));\n}\n";
    assert_eq!(stub_writers("src/x_tests.rs", planted).len(), 1);
    // Owner-only and read-execute modes count; a mode with no execute bit does not.
    assert_eq!(
        executable_modes("a.set_mode(0o700); b.mode(0o555); c.from_mode(0o644)").len(),
        2
    );
    // The wrapper's own line is allowed, and only in its own file.
    let wrapper = "\"#!/bin/sh\" ... Permissions::from_mode(0o555)";
    assert!(stub_writers(WRAPPER_FILE, wrapper).is_empty());
    assert_eq!(stub_writers("src/elsewhere.rs", wrapper).len(), 1);
    // The allowance holds for exactly one such line: not for none, not for two.
    assert!(wrapper_allowance_holds(wrapper));
    assert!(!wrapper_allowance_holds("\"#!/bin/sh\""));
    assert!(!wrapper_allowance_holds(&format!("{wrapper}\n{wrapper}")));
}

/// The census reads this file too, as code only: a real writer here is named,
/// while a mode spelled in a literal or a comment, as the fixtures do, is not.
#[test]
fn the_census_reads_its_own_file_as_code() {
    let own = "src/test_stub_tests.rs";
    let writer = "let s = \"#!/bin/sh\";\nset_mode(0o755);\n";
    assert_eq!(stub_writers(own, writer).len(), 1);
    let inert = "let s = \"#!/bin/sh from_mode(0o755)\";\n// set_mode(0o755)\n";
    assert!(stub_writers(own, inert).is_empty());
}

#[test]
fn a_stub_holds_its_contents_and_runs() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("stub");
    write_executable(&path, "#!/bin/sh\necho stub-ok\n");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        "#!/bin/sh\necho stub-ok\n"
    );
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755, "mode {mode:o}");
    let out = std::process::Command::new(&path)
        .output()
        .expect("the stub runs");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "stub-ok\n");
}

#[test]
fn a_stub_in_a_missing_directory_panics_naming_its_path() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("missing").join("stub");
    let caught = std::panic::catch_unwind(|| write_executable(&path, "#!/bin/sh\n"));
    let payload = caught.expect_err("writing into a missing directory panics");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    assert!(
        message.contains(&path.display().to_string()),
        "the panic does not name the path: {message}"
    );
}

/// The fix is that the test process never holds the stub's write descriptor;
/// a helper that opens the file itself brings the race back.
#[test]
fn the_helper_never_opens_the_stub_itself() {
    // Code only (comments and literals blanked); any std::fs path or File
    // opener counts, not only the common spellings.
    let helper = sanitize(include_str!("test_stub.rs"));
    for call in ["fs::", "File", "OpenOptions", "set_permissions"] {
        assert!(
            !helper.contains(call),
            "src/test_stub.rs calls {call}: the stub must be written by a child process"
        );
    }
}

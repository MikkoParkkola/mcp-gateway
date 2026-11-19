// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only ELF stand-ins, built with `cc` when a row starts. The launcher
//! refuses a `uv` or `python3` that is a script, so every stand-in for either
//! is an ELF. `cc` is the Linux Rust toolchain's linker, so it is present
//! wherever these rows build; its absence fails the row, never skips it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `source` compiled by `cc` into `dir/name`, `args` after the source (a
/// library given there is kept under `--as-needed`).
pub(super) fn cc(dir: &Path, name: &str, source: &str, args: &[&str]) -> PathBuf {
    // The source sits apart, so no `*.c` file lands beside the output.
    let scratch = tempfile::tempdir().expect("scratch");
    let src = scratch.path().join("main.c");
    std::fs::write(&src, source).expect("the C source");
    let out = dir.join(name);
    let status = Command::new("cc")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .args(args)
        .status()
        .expect("cc runs (it is the Linux Rust toolchain's linker)");
    assert!(status.success(), "cc {name}: {status}");
    out
}

/// `s` as a C string literal; ASCII only, as every fixture string is.
pub(super) fn c_str(s: &str) -> String {
    assert!(s.is_ascii(), "a fixture string is ASCII: {s:?}");
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// An ELF at `dir/name` that runs `/bin/sh -c script` with its own argv
/// (`$0` is the path it was run as, `"$@"` its arguments).
pub(super) fn sh_elf(dir: &Path, name: &str, script: &str) -> PathBuf {
    let source = format!(
        "#include <unistd.h>\n\
         int main(int argc, char **argv) {{\n\
         char *a[argc + 4];\n\
         a[0] = \"sh\"; a[1] = \"-c\"; a[2] = {script};\n\
         for (int i = 0; i < argc; i++) a[3 + i] = argv[i];\n\
         a[3 + argc] = 0;\n\
         execv(\"/bin/sh\", a);\n\
         return 127;\n\
         }}\n",
        script = c_str(script)
    );
    cc(dir, name, &source, &[])
}

/// A stub `libpython3.12.so.1.0` in `lib` and two executables in `bin`,
/// `python3.12` linked to it (its `DT_NEEDED` names it) and `unlinked` not.
pub(super) fn placement_elfs(lib: &Path, bin: &Path) -> (PathBuf, PathBuf, PathBuf) {
    std::fs::create_dir_all(lib).expect("lib");
    std::fs::create_dir_all(bin).expect("bin");
    let so = cc(
        lib,
        "libpython3.12.so.1.0",
        "int py_stub(void) { return 0; }\n",
        &["-shared", "-fPIC", "-Wl,-soname,libpython3.12.so.1.0"],
    );
    let so_arg = so.to_str().expect("UTF-8 path").to_owned();
    let linked = cc(
        bin,
        "python3.12",
        "int py_stub(void);\nint main(void) { return py_stub(); }\n",
        &[so_arg.as_str()],
    );
    let unlinked = cc(bin, "unlinked", "int main(void) { return 0; }\n", &[]);
    (so, linked, unlinked)
}

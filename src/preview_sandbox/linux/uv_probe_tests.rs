// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the uv fetch's launcher probe (its test plan, U-place
//! and U-uv-place): pure, on fixture trees in each row's own temp dir.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::super::elf_fixture::placement_elfs;
use super::super::{ProgramBind, READ_ONLY, program_bind};
use super::{PythonPlace, place_python, python_real, uv_beside};
use crate::preview_sandbox::Refusal;

/// A file that is not a script: the probe reads only its first two bytes.
fn binary(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    std::fs::write(path, b"\x7fELF").expect("binary");
}

/// A shell script at `path`.
fn script(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("script");
}

fn s(path: &Path) -> String {
    path.to_str().expect("UTF-8").to_owned()
}

fn system() -> Vec<String> {
    READ_ONLY.iter().map(ToString::to_string).collect()
}

/// A Python 3.12 prefix at `prefix`: the placement ELFs, the stdlib with
/// both package directories, and the Debian-style `lib/python3/dist-packages`.
/// Returns the linked and the unlinked interpreter.
fn prefix_tree(prefix: &Path) -> (PathBuf, PathBuf) {
    let stdlib = prefix.join("lib/python3.12");
    for dir in ["site-packages", "dist-packages"] {
        std::fs::create_dir_all(stdlib.join(dir)).expect("package dir");
    }
    std::fs::write(stdlib.join("os.py"), "").expect("os.py");
    std::fs::create_dir_all(prefix.join("lib/python3/dist-packages")).expect("python3 dir");
    let (_, linked, unlinked) = placement_elfs(&prefix.join("lib"), &prefix.join("bin"));
    (linked, unlinked)
}

/// The masks every layout of a 3.12 prefix gets.
fn masks(prefix: &Path) -> Vec<String> {
    vec![
        s(&prefix.join("lib/python3.12/site-packages")),
        s(&prefix.join("lib/python3.12/dist-packages")),
        s(&prefix.join("lib/python3/dist-packages")),
    ]
}

/// U-place, kills m-tree-bind, m-always-libpython and m-no-mask: a runtime
/// tree (pyenv) and a prefix outside the known trees each get exactly the
/// interpreter's real file, its stdlib dir and, only when the binary links
/// it, libpython, never the tree; every package directory is masked.
#[test]
fn u_place_binds_only_the_interpreter_its_stdlib_and_its_libpython() {
    let root = tempfile::tempdir().expect("root");
    for prefix in [
        root.path().join(".pyenv/versions/3.12.1"),
        root.path().join("usr/local"),
    ] {
        let (linked, unlinked) = prefix_tree(&prefix);
        let stdlib = prefix.join("lib/python3.12");
        assert_eq!(
            place_python(&linked, (3, 12), &system()).expect("linked"),
            PythonPlace {
                read_only: vec![
                    s(&linked),
                    s(&stdlib),
                    s(&prefix.join("lib/libpython3.12.so.1.0")),
                ],
                bound_back: Vec::new(),
                masks: masks(&prefix),
            },
            "linked, {}",
            prefix.display()
        );
        assert_eq!(
            place_python(&unlinked, (3, 12), &system()).expect("unlinked"),
            PythonPlace {
                read_only: vec![s(&unlinked), s(&stdlib)],
                bound_back: Vec::new(),
                masks: masks(&prefix),
            },
            "unlinked, {}",
            prefix.display()
        );
    }
}

/// U-place, the system layout: the system root already shows the host's
/// interpreter, so nothing is bound, and its package directories, listed
/// from the host here, are masked.
#[test]
fn u_place_a_system_interpreter_binds_nothing_and_masks_its_packages() {
    let real = std::fs::canonicalize("/usr/bin/python3").expect("the host has /usr/bin/python3");
    let name = real
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a file name");
    let (x, y) = name
        .strip_prefix("python")
        .and_then(|v| v.split_once('.'))
        .and_then(|(x, y)| Some((x.parse().ok()?, y.parse().ok()?)))
        .expect("the real file is named pythonX.Y");
    let candidates = [
        format!("/usr/lib/python{x}.{y}/site-packages"),
        format!("/usr/lib/python{x}.{y}/dist-packages"),
        "/usr/lib/python3/dist-packages".to_owned(),
    ];
    let present: Vec<String> = candidates
        .into_iter()
        .filter(|d| Path::new(d).is_dir())
        .collect();
    assert_eq!(
        place_python(&real, (x, y), &system()).expect("system"),
        PythonPlace {
            read_only: Vec::new(),
            bound_back: Vec::new(),
            masks: present,
        }
    );
}

/// U-place, kills m-shim-accepted: a version-manager shim (a script) found
/// as `python3` refuses by its path.
#[test]
fn u_place_a_script_interpreter_refuses_by_name() {
    let root = tempfile::tempdir().expect("root");
    let shim = root.path().join("shims/python3");
    script(&shim);
    let refusal = python_real(&shim).expect_err("a script refuses");
    assert_eq!(
        refusal,
        Refusal::Step(format!("placing python3 ({} is a script)", shim.display()))
    );
}

/// U-uv-place, kills m-script-uv: a `uv` that is a script refuses by name.
#[test]
fn u_uv_place_a_script_uv_refuses_by_name() {
    let root = tempfile::tempdir().expect("root");
    binary(&root.path().join("bin/uvx"));
    script(&root.path().join("bin/uv"));
    let refusal = uv_beside(&root.path().join("bin/uvx")).expect_err("a script refuses");
    assert_eq!(
        refusal,
        Refusal::Step(format!(
            "placing uv ({} is a script)",
            root.path().join("bin/uv").display()
        ))
    );
}

/// U-uv-place, kills m-uvx-raw: a `uvx` symlink resolves `uv` beside its
/// real file, not beside the link (a decoy `uv` sits there).
#[test]
fn u_uv_place_uv_is_found_beside_the_real_uvx() {
    let root = tempfile::tempdir().expect("root");
    binary(&root.path().join("real/uvx"));
    binary(&root.path().join("real/uv"));
    binary(&root.path().join("link/uv"));
    symlink(root.path().join("real/uvx"), root.path().join("link/uvx")).expect("link");
    let real = std::fs::canonicalize(root.path().join("real")).expect("real dir");
    assert_eq!(
        uv_beside(&root.path().join("link/uvx")).expect("found"),
        real.join("uv")
    );
}

/// U-uv-place, kills m-lone-uv-tree: a lone `uv` outside the known trees is
/// bound as that one file by the program rule, never its directory.
#[test]
fn u_uv_place_a_lone_uv_binds_as_a_file() {
    let root = tempfile::tempdir().expect("root");
    let uv = root.path().join("tools/uv");
    binary(&uv);
    let real = std::fs::canonicalize(&uv).expect("real");
    assert_eq!(
        program_bind(&real, &system()),
        ProgramBind::File(real.clone())
    );
}

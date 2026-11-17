// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The launcher's probe for a uv fetch (its design, 1 and 2): uv beside
//! the canonical `uvx` the target names, and the host's `python3` placed by
//! narrow binds, never its whole tree, with every globally installed package
//! directory masked.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use super::plan::{Plan, UvFetch};
use super::{ProgramBind, program_bind, utf8};
use crate::preview_sandbox::install::uv_name;
use crate::preview_sandbox::{Refusal, Target};

/// The uv fetch a `uvx` target needs (design 1, 2 and 4): uv beside the
/// real `uvx`, its floor checked; `python3` on `path`, probed with `-S`, and
/// placed by narrow binds and masks; uv placed by the program rule. `uvx`
/// itself is never run, so what was bound for it as the program goes first.
pub(super) fn uv_fetch(
    target: &Target,
    plan: &mut Plan,
    path: Option<&OsStr>,
    proxy: &Path,
    spec: String,
    run_args: &[OsString],
) -> Result<UvFetch, Refusal> {
    let requested = target.program.to_str().unwrap_or("uvx");
    let uvx = super::resolve_command(requested, path, None)
        .map_err(|e| Refusal::Step(format!("finding {requested} ({e})")))?;
    let uv = uv_beside(&uvx)?;
    check_uv(&uv)?;
    let python = super::resolve_command("python3", path, None)
        .map_err(|e| Refusal::Step(format!("finding python3 ({e})")))?;
    let python = python_real(&python)?;
    let xy = python_xy(&python)?;
    let uvx_real = fs::canonicalize(&uvx).unwrap_or_else(|_| uvx.clone());
    let uvx_tree = super::runtime_tree(&uvx_real);
    plan.bound_back.clear();
    plan.read_only
        .retain(|r| Path::new(r) != uvx_real && uvx_tree.as_deref() != Some(Path::new(r)));
    let place = place_python(&python, xy, &plan.read_only)?;
    plan.read_only.extend(place.read_only);
    plan.bound_back.extend(place.bound_back);
    plan.hidden.extend(place.masks);
    match program_bind(&uv, &plan.read_only) {
        ProgramBind::Refused => {
            return Err(Refusal::Step(format!(
                "placing uv ({} lies under a masked secret path)",
                uv.display()
            )));
        }
        ProgramBind::System => {}
        ProgramBind::UsrLocal(dirs) => {
            for dir in dirs {
                plan.bound_back.push(utf8(&dir)?);
            }
        }
        ProgramBind::Runtime(tree) => plan.read_only.push(utf8(&tree)?),
        ProgramBind::File(file) => plan.read_only.push(utf8(&file)?),
    }
    let ip = super::probe::find_ip(&super::probe::IP_CANDIDATES, &|p: &Path| {
        super::placed(p, plan)
    })?;
    let run_args = run_args
        .iter()
        .map(|a| a.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Refusal::Step("reading an argument (not UTF-8)".to_owned()))?;
    let python_dir = python.parent().ok_or_else(|| {
        Refusal::Step(format!(
            "placing python3 ({} has no directory)",
            python.display()
        ))
    })?;
    Ok(UvFetch {
        name: uv_name(&spec),
        spec,
        run_args,
        uv: utf8(&uv)?,
        python: utf8(&python)?,
        python_dir: utf8(python_dir)?,
        ip,
        proxy: utf8(proxy)?,
    })
}

/// The largest interpreter binary read for its library names.
const MAX_BINARY: u64 = 256 << 20;
/// uv older than this refuses the fetch (CI's pinned uv; older ones are not
/// verified).
pub(super) const UV_FLOOR: [u32; 3] = [0, 13, 1];
/// The script the interpreter probe runs: the interpreter's `X.Y`.
pub(super) const VERSION_SCRIPT: &str = "import sys; print('%d.%d' % sys.version_info[:2])";

/// Refuse a uv older than [`UV_FLOOR`]: `uv --version`, environment cleared,
/// within 10 s.
pub(super) fn check_uv(uv: &Path) -> Result<(), Refusal> {
    let out = super::probe::answer(uv, &["--version"], None, "uv --version")?;
    let line = out.trim();
    let found = line
        .strip_prefix("uv ")
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|v| v.split('.').count() == 3)
        .and_then(|v| {
            let parts: Option<Vec<u32>> = v.split('.').map(|p| p.parse().ok()).collect();
            parts.map(|p| (v, p))
        });
    let Some((version, parts)) = found else {
        return Err(Refusal::Step(format!("reading uv's version ({line:?})")));
    };
    if parts.as_slice() < UV_FLOOR.as_slice() {
        let [x, y, z] = UV_FLOOR;
        return Err(Refusal::Step(format!(
            "uv {version} is older than {x}.{y}.{z}"
        )));
    }
    Ok(())
}

/// The interpreter's `X.Y`: `python -S -I -c` [`VERSION_SCRIPT`], environment
/// cleared, within 10 s, so no site processing runs on the host either.
pub(super) fn python_xy(python: &Path) -> Result<(u32, u32), Refusal> {
    let out = super::probe::answer(
        python,
        &["-S", "-I", "-c", VERSION_SCRIPT],
        None,
        "python3's version probe",
    )?;
    let line = out.trim();
    line.split_once('.')
        .and_then(|(x, y)| Some((x.parse().ok()?, y.parse().ok()?)))
        .ok_or_else(|| Refusal::Step(format!("reading python3's version ({line:?})")))
}

/// uv beside the real file of `uvx` (both come from one install), as its
/// real file; a `uv` that is a script refuses by name.
pub(super) fn uv_beside(uvx: &Path) -> Result<PathBuf, Refusal> {
    let real = fs::canonicalize(uvx)
        .map_err(|e| Refusal::Step(format!("finding uv beside {} ({e})", uvx.display())))?;
    let uv = real
        .parent()
        .map(|dir| dir.join("uv"))
        .filter(|uv| uv.is_file())
        .ok_or_else(|| {
            Refusal::Step(format!("finding uv beside {} (not there)", real.display()))
        })?;
    let uv = fs::canonicalize(&uv)
        .map_err(|e| Refusal::Step(format!("finding uv beside {} ({e})", real.display())))?;
    refuse_script("uv", &uv)?;
    Ok(uv)
}

/// The real file of the `python3` found on the gateway's PATH; a script (a
/// version manager's shim) refuses by name.
pub(super) fn python_real(python: &Path) -> Result<PathBuf, Refusal> {
    let real = fs::canonicalize(python)
        .map_err(|e| Refusal::Step(format!("finding python3 at {} ({e})", python.display())))?;
    refuse_script("python3", &real)?;
    Ok(real)
}

/// Refuse `file` by name when it starts with `#!`.
fn refuse_script(what: &str, file: &Path) -> Result<(), Refusal> {
    use std::io::Read as _;
    let mut head = Vec::with_capacity(2);
    fs::File::open(file)
        .and_then(|f| f.take(2).read_to_end(&mut head))
        .map_err(|e| Refusal::Step(format!("placing {what} (reading {}: {e})", file.display())))?;
    if head == b"#!" {
        return Err(Refusal::Step(format!(
            "placing {what} ({} is a script)",
            file.display()
        )));
    }
    Ok(())
}
/// What the root must show of the interpreter in both phases, and what it
/// covers with an empty directory after every bind and bind-back.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PythonPlace {
    /// Bound read-only at their own paths.
    pub(super) read_only: Vec<String>,
    /// Bound back under the masked `/usr/local`.
    pub(super) bound_back: Vec<String>,
    /// Package directories hidden from both phases.
    pub(super) masks: Vec<String>,
}

/// The binds and masks for the interpreter whose real file is `real` and
/// whose version is `xy`; `system` lists the roots the sandbox shows anyway.
pub(super) fn place_python(
    real: &Path,
    (x, y): (u32, u32),
    system: &[String],
) -> Result<PythonPlace, Refusal> {
    let prefix = real.parent().and_then(Path::parent).ok_or_else(|| {
        Refusal::Step(format!(
            "placing python3 ({} has no prefix)",
            real.display()
        ))
    })?;
    let lib = prefix.join("lib");
    let stdlib = lib.join(format!("python{x}.{y}"));
    if !stdlib.is_dir() {
        return Err(Refusal::Step(format!(
            "placing python3 (no standard library at {})",
            stdlib.display()
        )));
    }
    let mut masks = Vec::new();
    for dir in [
        stdlib.join("site-packages"),
        stdlib.join("dist-packages"),
        lib.join("python3/dist-packages"),
    ] {
        if dir.is_dir() {
            masks.push(utf8(&dir)?);
        }
    }
    let mut binds = vec![utf8(real)?, utf8(&stdlib)?];
    if links_libpython(real, (x, y))? {
        let stem = format!("libpython{x}.{y}.so");
        let mut libs = Vec::new();
        for entry in fs::read_dir(&lib).map_err(|e| {
            Refusal::Step(format!("placing python3 (listing {}: {e})", lib.display()))
        })? {
            let entry = entry.map_err(|e| {
                Refusal::Step(format!("placing python3 (listing {}: {e})", lib.display()))
            })?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&stem))
            {
                libs.push(utf8(&entry.path())?);
            }
        }
        libs.sort();
        binds.extend(libs);
    }
    let mut place = PythonPlace {
        masks,
        ..PythonPlace::default()
    };
    // Never the tree the program rule would bind for a runtime: the
    // interpreter's own pieces only.
    match program_bind(real, system) {
        ProgramBind::Refused => {
            return Err(Refusal::Step(format!(
                "placing python3 ({} lies under a masked secret path)",
                real.display()
            )));
        }
        ProgramBind::System => {}
        ProgramBind::UsrLocal(_) => place.bound_back = binds,
        ProgramBind::Runtime(_) | ProgramBind::File(_) => place.read_only = binds,
    }
    Ok(place)
}

/// Whether the interpreter's binary names `libpythonX.Y.so` (the dynamic
/// section's `DT_NEEDED` string of a linked build).
// ponytail: a byte search, not an ELF parse; a stray mention only adds a
// read-only bind of a library file that exists; parse the dynamic section
// if that ever matters.
fn links_libpython(real: &Path, (x, y): (u32, u32)) -> Result<bool, Refusal> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    fs::File::open(real)
        .and_then(|f| f.take(MAX_BINARY + 1).read_to_end(&mut bytes))
        .map_err(|e| Refusal::Step(format!("placing python3 (reading {}: {e})", real.display())))?;
    if bytes.len() as u64 > MAX_BINARY {
        return Err(Refusal::Step(format!(
            "placing python3 ({} is over 256 MiB)",
            real.display()
        )));
    }
    let needle = format!("libpython{x}.{y}.so");
    Ok(bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes()))
}

#[cfg(test)]
#[path = "uv_probe_tests.rs"]
mod tests;

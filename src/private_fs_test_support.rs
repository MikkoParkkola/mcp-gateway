// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows test fixtures for owner-only custody (test plan §1-§3). Plants and
//! reads descriptors with PowerShell and `icacls`, never with `win_acl`, so
//! construction and inspection are not the same code.

use std::path::Path;
use std::process::Command;

/// The current user's SID, in `S-1-...` form, from `whoami` (not `win_acl`).
pub(crate) fn user_sid() -> String {
    let out = Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .arg("/nh")
        .output();
    let text = String::from_utf8_lossy(&out.expect("whoami runs").stdout).into_owned();
    text.trim()
        .rsplit(',')
        .next()
        .map(|sid| sid.trim_matches('"').to_owned())
        .filter(|sid| sid.starts_with("S-1-"))
        .unwrap_or_else(|| fixture_fail("user_sid", &format!("whoami printed {text:?}")))
}

/// A fixture error: the plant did not produce the state the row needs.
pub(crate) fn fixture_fail(row: &str, detail: &str) -> ! {
    panic!("WT-FIXTURE {row}: {detail}")
}

fn powershell(script: &str) -> Result<String, String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// Owner and DACL of `path` as SDDL (group excluded: Windows supplies it).
pub(crate) fn read_sddl(row: &str, path: &Path) -> String {
    powershell(&format!(
        "(Get-Acl -LiteralPath {}).GetSecurityDescriptorSddlForm('Owner, Access')",
        quoted(path)
    ))
    .unwrap_or_else(|e| fixture_fail(row, &format!("Get-Acl failed: {e}")))
}

/// Set an exact owner + DACL, then read it back and require `expect_back`
/// (the literal the row depends on) before the store is ever invoked.
pub(crate) fn plant_sddl(row: &str, path: &Path, sddl: &str, expect_back: &str) {
    powershell(&format!(
        "$a = Get-Acl -LiteralPath {p}; $a.SetSecurityDescriptorSddlForm('{sddl}'); \
         Set-Acl -LiteralPath {p} -AclObject $a",
        p = quoted(path)
    ))
    .unwrap_or_else(|e| fixture_fail(row, &format!("Set-Acl {sddl} failed: {e}")));
    let back = read_sddl(row, path);
    if back != expect_back {
        fixture_fail(
            row,
            &format!("planted {sddl}, read back {back}, wanted {expect_back}"),
        );
    }
}

/// Set a descriptor whose read-back Windows may normalise; returns it.
pub(crate) fn plant_any(row: &str, path: &Path, sddl: &str) -> String {
    powershell(&format!(
        "$a = Get-Acl -LiteralPath {p}; $a.SetSecurityDescriptorSddlForm('{sddl}'); \
         Set-Acl -LiteralPath {p} -AclObject $a",
        p = quoted(path)
    ))
    .unwrap_or_else(|e| fixture_fail(row, &format!("Set-Acl {sddl} failed: {e}")));
    read_sddl(row, path)
}

/// Run `icacls` with `args` on `path`.
pub(crate) fn icacls(row: &str, path: &Path, args: &[&str]) {
    let out = Command::new("icacls").arg(path).args(args).output();
    match out {
        Ok(out) if out.status.success() => {}
        Ok(out) => fixture_fail(row, &String::from_utf8_lossy(&out.stdout)),
        Err(e) => fixture_fail(row, &e.to_string()),
    }
}

/// A parsed `O:...D:...` descriptor, for field-by-field checks.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Parsed {
    pub(crate) owner: String,
    pub(crate) protected: bool,
    /// (type, flags, rights, sid) per ACE, flags without auto-inherit marks.
    pub(crate) aces: Vec<(String, String, String, String)>,
}

/// Parse the subset of SDDL `read_sddl` returns.
pub(crate) fn parse_sddl(sddl: &str) -> Parsed {
    let rest = sddl.strip_prefix("O:").unwrap_or(sddl);
    let (owner, dacl) = rest.split_once("D:").unwrap_or((rest, ""));
    let flags_end = dacl.find('(').unwrap_or(dacl.len());
    let aces = dacl[flags_end..]
        .split(')')
        .filter_map(|ace| ace.strip_prefix('('))
        .map(|ace| {
            let f: Vec<&str> = ace.split(';').collect();
            let flags = f.get(1).copied().unwrap_or("").replace("ID", "");
            let field = |i: usize| f.get(i).copied().unwrap_or("").to_owned();
            (field(0), flags, field(2), field(5))
        })
        .collect();
    Parsed {
        owner: owner.to_owned(),
        protected: dacl[..flags_end].contains('P'),
        aces,
    }
}

/// Assert, with the row's marker, that `path` carries exactly the one
/// owner-only ACE the design creates.
pub(crate) fn assert_owner_only(row: &str, path: &Path, dir: bool) {
    let user = user_sid();
    let got = parse_sddl(&read_sddl(row, path));
    let flags = if dir { "OICI" } else { "" };
    let want = Parsed {
        owner: user.clone(),
        protected: true,
        aces: vec![("A".into(), flags.into(), "FA".into(), user)],
    };
    assert_eq!(
        got,
        want,
        "WT-ASSERT {row}: {} is not owner-only",
        path.display()
    );
}

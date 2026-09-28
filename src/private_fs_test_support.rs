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

/// Run every repair line a refusal printed (the lines after its "run these
/// lines" header), verbatim, in Windows PowerShell, as a user pastes them.
/// Returns how many ran; a failing line is a fixture error.
pub(crate) fn run_printed_repair(row: &str, text: &str) -> usize {
    let lines: Vec<&str> = text
        .lines()
        .skip_while(|l| !l.contains("run these lines"))
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    for line in &lines {
        let script = format!(
            "$ErrorActionPreference = 'Stop'; {line}; if ($LASTEXITCODE) {{ exit $LASTEXITCODE }}"
        );
        if let Err(error) = powershell(&script) {
            fixture_fail(row, &format!("remediation command failed: {line}: {error}"));
        }
    }
    lines.len()
}

fn powershell(script: &str) -> Result<String, String> {
    // Windows PowerShell must not inherit a PowerShell 7 module path (the CI
    // shell is pwsh), or it cannot load its own security module.
    let out = Command::new("powershell")
        .env_remove("PSModulePath")
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

/// Native plant/read through the Win32 SDDL functions, compiled by PowerShell
/// at test time. .NET's `Set-Acl` cannot express a NULL DACL or a callback ACE
/// (it rewrites both into ordinary allow ACEs), and neither can `icacls`.
/// Independent of `win_acl` by construction: different code, different calls.
const NATIVE: &str = r#"Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class MgwSd {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint rev, out IntPtr sd, out uint len);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(byte[] sd, uint rev, uint info, out IntPtr s, out uint len);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool SetFileSecurityW(string path, uint info, IntPtr sd);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool GetFileSecurityW(string path, uint info, byte[] sd, uint len, out uint need);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  const uint OWNER = 1, DACL = 4, PROT = 0x80000000, UNPROT = 0x20000000;
  public static void Set(string path, string sddl, bool protect) {
    IntPtr sd; uint n;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out n)) throw new System.ComponentModel.Win32Exception();
    try { if (!SetFileSecurityW(path, OWNER | DACL | (protect ? PROT : UNPROT), sd)) throw new System.ComponentModel.Win32Exception(); }
    finally { LocalFree(sd); }
  }
  public static string Get(string path) {
    uint need; GetFileSecurityW(path, OWNER | DACL, null, 0, out need);
    byte[] b = new byte[need];
    if (!GetFileSecurityW(path, OWNER | DACL, b, need, out need)) throw new System.ComponentModel.Win32Exception();
    IntPtr s; uint n;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(b, 1, OWNER | DACL, out s, out n)) throw new System.ComponentModel.Win32Exception();
    try { return Marshal.PtrToStringUni(s); } finally { LocalFree(s); }
  }
}
'@
function Numeric($d) { [regex]::Replace($d, '(?<=O:|;;;)([A-Z]{2})(?=D:|\)|;|$)', { param($m) try { (New-Object System.Security.Principal.SecurityIdentifier($m.Value)).Value } catch { $m.Value } }) }
"#;

/// Owner and DACL of `path` as SDDL, every SID numeric (aliases such as `LA`,
/// `BA`, `WD` translated), read with the native Win32 conversion.
pub(crate) fn read_sddl(row: &str, path: &Path) -> String {
    powershell(&format!(
        "{NATIVE}\nNumeric ([MgwSd]::Get({}))",
        quoted(path)
    ))
    .unwrap_or_else(|e| fixture_fail(row, &format!("reading the descriptor failed: {e}")))
}

fn native_set(row: &str, path: &Path, sddl: &str) {
    let protect = sddl.contains("D:P");
    powershell(&format!(
        "{NATIVE}\n[MgwSd]::Set({}, '{sddl}', ${protect})",
        quoted(path)
    ))
    .unwrap_or_else(|e| fixture_fail(row, &format!("planting {sddl} failed: {e}")));
}

/// Compare two descriptors semantically: owner, protection, and the ACE set
/// (order-free, flags normalised to a sorted form).
fn same_descriptor(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let mut p = parse_sddl(s);
        for ace in &mut p.aces {
            let mut flags: Vec<String> = ace
                .1
                .as_bytes()
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            flags.sort();
            ace.1 = flags.concat();
        }
        p.aces.sort();
        let null = s.contains("NO_ACCESS_CONTROL");
        (p, null)
    };
    norm(a) == norm(b)
}

/// Set an exact owner + DACL, then read it back and require `expect_back`
/// (the literal the row depends on) before the store is ever invoked.
pub(crate) fn plant_sddl(row: &str, path: &Path, sddl: &str, expect_back: &str) {
    let expect_back = &numeric_aliases(expect_back);
    native_set(row, path, sddl);
    let back = read_sddl(row, path);
    if !same_descriptor(&back, expect_back) {
        fixture_fail(
            row,
            &format!("planted {sddl}, read back {back}, wanted {expect_back}"),
        );
    }
}

/// Make `path` owner-only for the current user, the Windows counterpart of a
/// fixture's `chmod 0600`: owner = user, protected DACL granting only the user.
pub(crate) fn plant_owner_only(row: &str, path: &Path) {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(A;;FA;;;{user})");
    plant_sddl(row, path, &sddl, &sddl);
}

/// Set a descriptor whose read-back Windows may normalise; returns it.
pub(crate) fn plant_any(row: &str, path: &Path, sddl: &str) -> String {
    native_set(row, path, sddl);
    read_sddl(row, path)
}

/// The well-known aliases the plants use, in numeric form.
fn numeric_aliases(sddl: &str) -> String {
    sddl.replace("O:BA", "O:S-1-5-32-544")
        .replace(";;;BU)", ";;;S-1-5-32-545)")
        .replace(";;;WD)", ";;;S-1-1-0)")
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
    let mut got = parse_sddl(&read_sddl(row, path));
    for ace in &mut got.aces {
        if ace.1 == "CIOI" {
            ace.1 = "OICI".into();
        }
    }
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

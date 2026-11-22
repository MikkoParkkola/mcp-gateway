// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The R rows: each env the rule refuses or accepts, judged in a child that
//! runs the probe with that env.

use super::{FIX, probe, with_override};
#[cfg(unix)]
use crate::private_home::Expect;
use crate::private_home::{self, canonical, fresh_private_dir, literal_env_command, refuse};
use std::path::Path;
#[cfg(windows)]
use std::process::Command;

/// The fix line when a config or data variable broke the rule.
const FIX_ENV: &str = "env -u XDG_CONFIG_HOME -u MCP_GATEWAY_CONFIG_DIR";

/// R1: no override at all.
#[test]
fn r1_an_unset_override_is_refused() {
    probe(
        literal_env_command(),
        &refuse(
            &[
                "(check 2)",
                "MCP_GATEWAY_TEST_HOME_DIR is unset or empty",
                FIX,
            ],
            &[FIX_ENV],
        ),
        Vec::new(),
    );
}

/// R2: an empty override.
#[test]
fn r2_an_empty_override_is_refused() {
    let mut command = literal_env_command();
    command.env("MCP_GATEWAY_TEST_HOME_DIR", ""); // spawn-check: not the gateway: the probe child, this test binary
    probe(
        command,
        &refuse(
            &[
                "(check 2)",
                "MCP_GATEWAY_TEST_HOME_DIR is unset or empty",
                FIX,
            ],
            &[FIX_ENV],
        ),
        Vec::new(),
    );
}

/// R3: an override naming nothing. Its own message, before any canonicalisation.
#[test]
fn r3_a_nonexistent_override_is_refused() {
    let parent = fresh_private_dir();
    let command = with_override(&parent.path().join("absent"));
    probe(
        command,
        &refuse(
            &["(check 3)", "names no existing directory", FIX],
            &[FIX_ENV],
        ),
        vec![parent],
    );
}

/// R10: an override naming a regular file.
#[test]
fn r10_an_override_naming_a_file_is_refused() {
    let parent = fresh_private_dir();
    let file = parent.path().join("file");
    std::fs::write(&file, b"").expect("a regular file");
    probe(
        with_override(&file),
        &refuse(
            &["(check 3)", "names no existing directory", FIX],
            &[FIX_ENV],
        ),
        vec![parent],
    );
}

/// R4: the real home itself. Read-only: the rule refuses before any lookup.
#[test]
fn r4_the_real_home_is_refused() {
    let home = private_home::real_home_raw().expect("this host has a home");
    probe(
        with_override(&home),
        &refuse(&["(check 4)", "is the real home", FIX], &[FIX_ENV]),
        Vec::new(),
    );
}

/// R5: a symlink to the real home, the same home by another name.
#[cfg(unix)]
#[test]
fn r5_a_symlink_to_the_real_home_is_refused() {
    let home = private_home::real_home().expect("this host has a home");
    let dir = fresh_private_dir();
    let link = dir.path().join("home-link");
    std::os::unix::fs::symlink(&home, &link).expect("a symlink");
    probe(
        with_override(&link),
        &refuse(&["(check 4)", "is the real home", FIX], &[FIX_ENV]),
        vec![dir],
    );
}

/// R6: a release build refuses a valid env (the release library ignores the
/// override). Runs only in a release build; no CI job builds integration tests
/// in release.
#[cfg(not(debug_assertions))]
#[test]
fn r6_a_release_build_is_refused() {
    let home = fresh_private_dir();
    probe(
        with_override(home.path()),
        &refuse(
            &[
                "(check 1)",
                "these tests need a debug build",
                "without --release",
            ],
            &[FIX],
        ),
        vec![home],
    );
}

/// A private override plus one config or data variable set to `value`,
/// expected refused by `check` with `text`.
fn refuse_var(
    var: &str,
    value: impl FnOnce(&Path, &Path) -> std::path::PathBuf,
    check: &str,
    text: &str,
) {
    let home = fresh_private_dir();
    let other = fresh_private_dir();
    let mut command = with_override(home.path());
    command.env(var, value(home.path(), other.path()));
    probe(
        command,
        &refuse(&[check, text, FIX_ENV], &[]),
        vec![home, other],
    );
}

const XDG_TEXT: &str = "XDG_CONFIG_HOME must be unset or <override>/.config";
const DATA_TEXT: &str = "MCP_GATEWAY_CONFIG_DIR must be unset or <override>/.mcp-gateway";

/// R7a: the right name under the wrong parent.
#[test]
fn r7a_xdg_under_another_dir_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, other| other.join(".config"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R7b: the right parent with the wrong name.
#[test]
fn r7b_xdg_with_another_name_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |home, _| home.join("other"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R8a: the right name under the wrong parent.
#[test]
fn r8a_data_dir_under_another_dir_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, other| other.join(".mcp-gateway"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R8b: the right parent with the wrong name.
#[test]
fn r8b_data_dir_with_another_name_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |home, _| home.join("other"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R11: an empty `XDG_CONFIG_HOME`, which the library would take as the working dir.
#[test]
fn r11_an_empty_xdg_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, _| std::path::PathBuf::new(),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R12: an empty `MCP_GATEWAY_CONFIG_DIR`, likewise.
#[test]
fn r12_an_empty_data_dir_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, _| std::path::PathBuf::new(),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R13a: `XDG_CONFIG_HOME` under a parent that cannot be resolved.
#[test]
fn r13a_xdg_under_a_missing_parent_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, other| other.join("absent").join(".config"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R13b: `MCP_GATEWAY_CONFIG_DIR` under a parent that cannot be resolved.
#[test]
fn r13b_data_dir_under_a_missing_parent_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, other| other.join("absent").join(".mcp-gateway"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// A private override whose `leaf` is a link (made by `link`) to a decoy dir
/// outside it, expected refused by check 7.
fn refuse_leaf(leaf: &str, link: impl FnOnce(&Path, &Path)) {
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let at = home.path().join(leaf);
    std::fs::create_dir_all(at.parent().expect("a parent")).expect("the leaf's parent");
    assert!(!at.exists(), "premise: the leaf is absent before the link");
    assert!(
        decoy.path().is_absolute() && decoy.path().is_dir(),
        "premise: the decoy is an existing absolute dir"
    );
    link(decoy.path(), &at);
    assert_eq!(
        canonical(&at),
        canonical(decoy.path()),
        "premise: the leaf resolves to the decoy"
    );
    let text = format!("{leaf} resolves outside the override");
    probe(
        with_override(home.path()),
        &refuse(&["(check 7)", &text, FIX_ENV], &[]),
        vec![home, decoy],
    );
}

/// R14: `<override>/.config` is a symlink out of the override.
#[cfg(unix)]
#[test]
fn r14_a_config_leaf_symlink_out_is_refused() {
    refuse_leaf(".config", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink");
    });
}

/// R15: `<override>/.mcp-gateway` is a symlink out of the override.
#[cfg(unix)]
#[test]
fn r15_a_data_leaf_symlink_out_is_refused() {
    refuse_leaf(".mcp-gateway", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink");
    });
}

/// R16: a discovery input other than the two leaves, `<override>/.cursor`, is a
/// symlink out of the override.
#[cfg(unix)]
#[test]
fn r16_a_discovery_input_symlink_out_is_refused() {
    refuse_leaf(".cursor", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink");
    });
}

/// R17: a link below the top level, `<override>/.cursor/mcp.json`, out of the override.
#[cfg(unix)]
#[test]
fn r17_a_nested_symlink_out_is_refused() {
    refuse_leaf(".cursor/mcp.json", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink");
    });
}

/// R18: a dangling link counts as outside: a write through it would create its target.
#[cfg(unix)]
#[test]
fn r18_a_dangling_symlink_is_refused() {
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let target = decoy.path().join("absent");
    let at = home.path().join(".claude.json");
    std::os::unix::fs::symlink(&target, &at).expect("a symlink");
    assert!(
        at.symlink_metadata().is_ok() && !target.exists(),
        "premise: the link dangles"
    );
    probe(
        with_override(home.path()),
        &refuse(
            &[
                "(check 7)",
                ".claude.json resolves outside the override",
                FIX_ENV,
            ],
            &[],
        ),
        vec![home, decoy],
    );
}

/// Gives a directory mode 0o700 back when dropped, failing run or not, so the
/// temp dirs holding it can be removed. Declare it after the dir it lives in,
/// so it drops first.
#[cfg(unix)]
struct RestoreMode(std::path::PathBuf);

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// R19: a directory that cannot be listed is refused. An execute-only `.cursor`
/// still opens `.cursor/mcp.json` by its known path, here a link out.
#[cfg(unix)]
#[test]
fn r19_an_unlistable_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let cursor = home.path().join(".cursor");
    std::fs::create_dir(&cursor).expect("a dir");
    std::os::unix::fs::symlink(decoy.path(), cursor.join("mcp.json")).expect("a symlink");
    std::fs::set_permissions(&cursor, std::fs::Permissions::from_mode(0o100))
        .expect("execute-only");
    let _restore = RestoreMode(cursor.clone());
    assert!(
        std::fs::read_dir(&cursor).is_err() && cursor.join("mcp.json").symlink_metadata().is_ok(),
        "premise: .cursor cannot be listed yet opens by a known path (fails as root)"
    );
    probe(
        with_override(home.path()),
        &refuse(&["(check 7)", ".cursor cannot be listed", FIX_ENV], &[]),
        vec![decoy],
    );
}

/// R20: a test-home file that is the real home's file at the same path (here a
/// hard link: same device and inode) is refused. The real home is a decoy (HOME),
/// never the developer's own. Unix only: std has no stable file id on Windows, so
/// there this is a declared limit of check 7.
#[cfg(unix)]
#[test]
fn r20_a_hard_link_to_real_config_is_refused() {
    use std::os::unix::fs::MetadataExt;
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let real = decoy.path().join(".cursor").join("mcp.json");
    let at = home.path().join(".cursor").join("mcp.json");
    for dir in [decoy.path(), home.path()] {
        std::fs::create_dir(dir.join(".cursor")).expect("a .cursor dir");
    }
    std::fs::write(&real, "{}").expect("the decoy's config");
    std::fs::hard_link(&real, &at).expect("a hard link");
    let (a, b) = (
        std::fs::metadata(&at).expect("linked"),
        std::fs::metadata(&real).expect("real"),
    );
    assert!(
        a.dev() == b.dev() && a.ino() == b.ino(),
        "premise: one file under both names"
    );
    let mut command = with_override(home.path());
    command.env("HOME", decoy.path()); // spawn-check: not the gateway: the probe child, this test binary
    probe(
        command,
        &refuse(
            &[
                "(check 7)",
                ".cursor/mcp.json is the real home's .cursor/mcp.json (the same file)",
                FIX_ENV,
            ],
            &[],
        ),
        vec![home, decoy],
    );
}

/// R21: a test-home file is refused when the real home's file at the same path
/// cannot be read: the comparison fails closed. The decoy real home's `.cursor`
/// cannot be searched (mode 0o600), and the test home holds its own file with one
/// name at the same path (R20 covers the hard link).
#[cfg(unix)]
#[test]
fn r21_an_unreadable_real_counterpart_is_refused() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let real_dir = decoy.path().join(".cursor");
    let real = real_dir.join("mcp.json");
    let at = home.path().join(".cursor").join("mcp.json");
    std::fs::create_dir(&real_dir).expect("the decoy's .cursor");
    std::fs::create_dir(home.path().join(".cursor")).expect("the test home's .cursor");
    std::fs::write(&real, "{}").expect("the decoy's config");
    std::fs::write(&at, "{}").expect("the test home's own config");
    std::fs::set_permissions(&real_dir, std::fs::Permissions::from_mode(0o600))
        .expect("unsearchable");
    let _restore = RestoreMode(real_dir.clone());
    let denied =
        std::fs::metadata(&real).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
    assert!(
        denied && std::fs::metadata(&at).is_ok_and(|m| m.nlink() == 1),
        "premise: the real file cannot be read, the test-home file has one name (fails as root)"
    );
    let mut command = with_override(home.path());
    command.env("HOME", decoy.path()); // spawn-check: not the gateway: the probe child, this test binary
    probe(
        command,
        &refuse(
            &[
                "(check 7)",
                ".cursor/mcp.json cannot be judged: the real home's .cursor/mcp.json cannot be read",
                FIX_ENV,
            ],
            &[],
        ),
        vec![home],
    );
}

/// R22: a test-home file reached from the real home through a symlink is the real
/// home's file (a dotfiles directory used as the test home). The decoy real home's
/// `.cursor` links to the test home's `.cursor`, whose `mcp.json` has one name.
#[cfg(unix)]
#[test]
fn r22_a_real_home_symlink_into_the_test_home_is_refused() {
    use std::os::unix::fs::MetadataExt;
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let cursor = home.path().join(".cursor");
    std::fs::create_dir(&cursor).expect("the test home's .cursor");
    std::fs::write(cursor.join("mcp.json"), "{}").expect("the config");
    std::os::unix::fs::symlink(&cursor, decoy.path().join(".cursor")).expect("a symlink");
    let ours = std::fs::metadata(cursor.join("mcp.json")).expect("ours");
    let theirs = std::fs::metadata(decoy.path().join(".cursor").join("mcp.json")).expect("theirs");
    assert!(
        ours.nlink() == 1 && ours.ino() == theirs.ino() && ours.dev() == theirs.dev(),
        "premise: one name, and the real home's path reaches the same file"
    );
    let mut command = with_override(home.path());
    command.env("HOME", decoy.path()); // spawn-check: not the gateway: the probe child, this test binary
    probe(
        command,
        &refuse(
            &[
                "(check 7)",
                ".cursor/mcp.json is the real home's .cursor/mcp.json (the same file)",
                FIX_ENV,
            ],
            &[],
        ),
        vec![home, decoy],
    );
}

/// R0d: the gateway's own hard links inside the test home are accepted (a
/// journal publish or a kept backup gives one file two names), though the real
/// home (a decoy) holds a different file at the same relative path.
#[cfg(unix)]
#[test]
fn r0d_hard_links_inside_the_test_home_are_accepted() {
    use std::os::unix::fs::MetadataExt;
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    for root in [home.path(), decoy.path()] {
        std::fs::create_dir(root.join(".mcp-gateway")).expect("a data dir");
        std::fs::write(root.join(".mcp-gateway").join("journal.json"), "{}").expect("a journal");
    }
    let journal = home.path().join(".mcp-gateway").join("journal.json");
    let kept = home.path().join(".mcp-gateway").join("journal.json.kept");
    std::fs::hard_link(&journal, &kept).expect("a kept backup");
    let ours = std::fs::metadata(&journal).expect("the journal");
    let theirs = std::fs::metadata(decoy.path().join(".mcp-gateway").join("journal.json"))
        .expect("the decoy's journal");
    assert!(
        ours.nlink() == 2 && ours.ino() != theirs.ino(),
        "premise: two names inside the test home, another file at the same path in the real home"
    );
    let mut command = with_override(home.path());
    command.env("HOME", decoy.path()); // spawn-check: not the gateway: the probe child, this test binary
    probe(command, &Expect::Pass, vec![home, decoy]);
}

/// R0c: a link that stays inside the override is accepted: check 7 judges where
/// a link resolves, not that it is one.
#[cfg(unix)]
#[test]
fn r0c_a_link_that_stays_inside_is_accepted() {
    let home = fresh_private_dir();
    let real = home.path().join("real-cursor");
    std::fs::create_dir(&real).expect("a dir");
    std::os::unix::fs::symlink(&real, home.path().join(".cursor")).expect("a symlink");
    probe(with_override(home.path()), &Expect::Pass, vec![home]);
}

/// A directory junction at `at` to `decoy`; `mklink /J` needs no admin rights.
#[cfg(windows)]
fn junction(decoy: &Path, at: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(at)
        .arg(decoy)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("cmd runs");
    assert!(status.success(), "mklink /J made the junction");
}

/// R14w: `<override>\.config` is a junction out of the override. Required on Windows.
#[cfg(windows)]
#[test]
fn r14w_a_config_leaf_junction_out_is_refused() {
    refuse_leaf(".config", junction);
}

/// R15w: `<override>\.mcp-gateway` is a junction out of the override. Required on Windows.
#[cfg(windows)]
#[test]
fn r15w_a_data_leaf_junction_out_is_refused() {
    refuse_leaf(".mcp-gateway", junction);
}

/// R16w: `<override>\.cursor` is a junction out of the override. Required on Windows.
#[cfg(windows)]
#[test]
fn r16w_a_discovery_input_junction_out_is_refused() {
    refuse_leaf(".cursor", junction);
}

/// R9 (Windows): the real profile spelt three other ways is still the real home.
#[cfg(windows)]
mod r9_windows_aliases {
    use super::{FIX, FIX_ENV, probe, refuse, with_override};
    use std::path::PathBuf;

    fn refused(alias: &std::path::Path) {
        probe(
            with_override(alias),
            &refuse(&["(check 4)", "is the real home", FIX], &[FIX_ENV]),
            Vec::new(),
        );
    }

    /// The verbatim form (`\\?\C:\...`), which canonicalisation itself returns.
    #[test]
    fn r9a_the_verbatim_form_is_refused() {
        refused(&crate::private_home::real_home().expect("a home"));
    }

    /// A case variant: Windows paths are case-insensitive.
    #[test]
    fn r9b_a_case_variant_is_refused() {
        let raw = crate::private_home::real_home_raw().expect("a home");
        // ASCII only: Unicode uppercasing can change a name's length (ß to SS),
        // which is another path, not a case alias.
        refused(&PathBuf::from(raw.to_string_lossy().to_ascii_uppercase()));
    }

    /// The 8.3 short form, read from cmd. Skipped, saying why, when the volume
    /// has 8.3 names off (the short form equals the long one).
    #[test]
    fn r9c_the_short_form_is_refused() {
        use std::os::windows::process::CommandExt as _;
        let raw = crate::private_home::real_home_raw().expect("a home");
        // raw_arg: cmd parses its own command line, so the quotes must reach it
        // unescaped. /u: cmd writes UTF-16LE, so a non-ASCII profile survives.
        let out = std::process::Command::new("cmd")
            .args(["/u", "/c"])
            .raw_arg(format!("for %I in (\"{}\") do @echo %~sI", raw.display()))
            .output()
            .expect("cmd runs");
        assert!(out.status.success(), "cmd failed: {}", out.status);
        let (pairs, odd) = out.stdout.as_chunks::<2>();
        assert!(
            odd.is_empty(),
            "cmd /u printed an odd byte count: not UTF-16"
        );
        let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
        let short = String::from_utf16_lossy(&units).trim().to_string();
        assert!(!short.is_empty(), "cmd printed no short form");
        if short.eq_ignore_ascii_case(&raw.to_string_lossy()) {
            crate::required::skip_or_fail(&format!("8.3 short names on this volume (got {short})"));
            return;
        }
        refused(&PathBuf::from(short));
    }
}

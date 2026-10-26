// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` row `lock-directories` (Windows): a directory the gateway keeps
//! cross-process lock files in that broad local groups (`BUILTIN\Users`,
//! Authenticated Users) may create files in. The gateway proceeds there with
//! one warning; this row reports the same finding, and a directory it would
//! refuse. Elsewhere the row passes: no lock directory is judged.

use std::path::{Path, PathBuf};

use mcp_gateway::config::Config;

use super::CheckResult;

pub(super) fn check_lock_directories(config: &Config) -> CheckResult {
    let findings: Vec<String> = lock_directories(config)
        .iter()
        .filter_map(|dir| mcp_gateway::lock_directory_finding(dir))
        .collect();
    let row = if findings.is_empty() {
        CheckResult::pass(
            "lock-directories",
            "no lock directory lets another account create files",
        )
    } else {
        CheckResult::warn("lock-directories", findings.join("; "))
    };
    row.with_category("security")
}

/// The gateway data directory, and the directories of the grant file and the
/// audit log when they are enabled and given as absolute paths. A `~` path
/// lies under the user's profile, whose default ACL lets no other account
/// create files, so it is not read here.
fn lock_directories(config: &Config) -> Vec<PathBuf> {
    let mut dirs = vec![mcp_gateway::config_persistence::gateway_data_dir()];
    let grants = &config.security.identity_grants;
    if grants.enabled {
        dirs.extend(parent_if_absolute(&grants.path));
    }
    let log = &config.security.transparency_log;
    if log.is_enabled(config.auth.enabled) {
        dirs.extend(parent_if_absolute(&log.path));
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

fn parent_if_absolute(path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    path.is_absolute()
        .then(|| path.parent().map(Path::to_path_buf))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data directory is always judged; a relative or `~` grant path is
    /// not, an absolute one is.
    #[test]
    fn the_data_directory_and_absolute_store_paths_are_judged() {
        let mut config = Config::default();
        config.security.identity_grants.enabled = true;
        config.security.identity_grants.path = "~/grants.yaml".to_owned();
        assert_eq!(
            lock_directories(&config),
            vec![mcp_gateway::config_persistence::gateway_data_dir()]
        );
        let absolute = std::env::temp_dir().join("grants").join("grants.yaml");
        config.security.identity_grants.path = absolute.display().to_string();
        assert!(lock_directories(&config).contains(&absolute.parent().unwrap().to_path_buf()));
    }

    /// Off Windows the row passes; on Windows a directory that only broad
    /// local groups may write is a warning naming it.
    #[test]
    fn the_row_reports_a_directory_broad_groups_may_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.security.identity_grants.enabled = true;
        config.security.identity_grants.path = dir.path().join("grants.yaml").display().to_string();
        #[cfg(windows)]
        {
            let user = std::process::Command::new("whoami")
                .arg("/user")
                .output()
                .expect("whoami");
            let text = String::from_utf8_lossy(&user.stdout);
            let sid = text
                .split_whitespace()
                .find(|word| word.starts_with("S-1-"))
                .expect("a SID")
                .to_owned();
            let acl = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;0x1301bf;;;BU)");
            // Windows PowerShell must not inherit a PowerShell 7 module path (the CI
            // shell is pwsh), or it cannot load its own security module.
            let set = std::process::Command::new("powershell")
                .env_remove("PSModulePath")
                .args(["-NoProfile", "-Command"])
                .arg(format!(
                    "$a = Get-Acl -LiteralPath '{}'; $a.SetSecurityDescriptorSddlForm('{acl}'); \
                     Set-Acl -LiteralPath '{}' -AclObject $a",
                    dir.path().display(),
                    dir.path().display()
                ))
                .output()
                .expect("powershell");
            assert!(set.status.success(), "{set:?}");
        }
        let row = check_lock_directories(&config);
        #[cfg(windows)]
        assert!(
            row.detail.contains(&dir.path().display().to_string()),
            "{}",
            row.detail
        );
        #[cfg(not(windows))]
        assert!(row.detail.contains("no lock directory"), "{}", row.detail);
    }
}

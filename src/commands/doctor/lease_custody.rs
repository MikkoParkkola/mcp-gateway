// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` findings for passthrough token custody (MIK-8833 E8 and the
//! swap rule): a gateway with a `passthrough` backend may hold
//! its event subscribers' own tokens in memory. The gateway lowers its own
//! core-file limit before the first lease and refuses leases where it cannot;
//! swap is the host's, so it is reported here: a warning unless every active
//! swap entry is verified encrypted.

use mcp_gateway::config::Config;
use mcp_gateway::identity_propagation::PropagationStrategyKind;

use super::CheckResult;

const LABEL: &str = "Passthrough token custody";

pub(super) fn check_passthrough_custody(config: &Config) -> Vec<CheckResult> {
    let passthrough = config.enabled_backends().any(|(_, b)| {
        b.identity_propagation
            .as_ref()
            .is_some_and(|p| p.strategy == PropagationStrategyKind::Passthrough)
    });
    if !passthrough {
        return Vec::new();
    }
    vec![platform(), swap()]
}

/// Where leases can be held at all: the core-dump guard needs a Unix.
fn platform() -> CheckResult {
    if cfg!(unix) {
        CheckResult::pass(
            LABEL,
            "event leases hold subscribers' tokens in memory only; the gateway sets a zero \
             core-file limit (and, on Linux, a not-dumpable process) before the first one",
        )
    } else {
        CheckResult::warn(
            LABEL,
            "this platform cannot disable core dumps, so passthrough event leases are refused \
             (core_dump_guard_unavailable, platform_unsupported)",
        )
    }
}

/// What the host's swap means for a token held in memory.
#[derive(Debug, PartialEq, Eq)]
enum Swap {
    /// No active swap, or every entry is encrypted or memory-only.
    Safe(&'static str),
    /// Some entry could not be verified encrypted: its path.
    Unverified(String),
}

fn swap() -> CheckResult {
    let label = "Swap encryption for held tokens";
    let verdict = if cfg!(target_os = "macos") {
        Swap::Safe("macOS encrypts swap")
    } else if cfg!(target_os = "linux") {
        match std::fs::read_to_string("/proc/swaps") {
            Ok(table) => linux_swap(&table, dm_crypt),
            Err(_) => Swap::Unverified("/proc/swaps".to_owned()),
        }
    } else {
        Swap::Unverified("(this platform)".to_owned())
    };
    match verdict {
        Swap::Safe(why) => CheckResult::pass(label, why),
        Swap::Unverified(entry) => {
            let mut result = CheckResult::warn(
                label,
                format!(
                    "swap entry {entry} is not verified encrypted: a held event token could be \
                     written to disk"
                ),
            );
            result.hint = Some(
                "use encrypted swap (dm-crypt) or zram, or disable swap, on a host that holds \
                 passthrough event leases"
                    .to_owned(),
            );
            result
        }
    }
}

/// Judge `/proc/swaps`: each active entry must be zram (memory only) or a
/// dm-crypt device; anything else, or anything unreadable, is unverified.
fn linux_swap(table: &str, crypt: impl Fn(&str) -> Option<bool>) -> Swap {
    for line in table.lines().skip(1) {
        let Some(entry) = line.split_whitespace().next() else {
            continue;
        };
        let device = entry.rsplit('/').next().unwrap_or(entry);
        if device.starts_with("zram") {
            continue;
        }
        if crypt(entry) != Some(true) {
            return Swap::Unverified(entry.to_owned());
        }
    }
    Swap::Safe("every active swap entry is encrypted or memory-only")
}

/// Whether swap `entry` is a dm-crypt device: its device-mapper UUID starts
/// with `CRYPT-`. `None` when that cannot be read (a file, a plain disk).
fn dm_crypt(entry: &str) -> Option<bool> {
    let resolved = std::fs::canonicalize(entry).ok()?;
    let name = resolved.file_name()?.to_str()?;
    if !name.starts_with("dm-") {
        return None;
    }
    let uuid = std::fs::read_to_string(format!("/sys/block/{name}/dm/uuid")).ok()?;
    Some(uuid.starts_with("CRYPT-"))
}

#[cfg(test)]
mod tests {
    use super::{Swap, linux_swap};

    const HEADER: &str = "Filename\tType\tSize\tUsed\tPriority\n";

    #[test]
    fn no_active_swap_is_safe() {
        assert!(matches!(linux_swap(HEADER, |_| None), Swap::Safe(_)));
    }

    #[test]
    fn zram_and_dm_crypt_are_safe_and_anything_else_warns() {
        let table = format!("{HEADER}/dev/zram0 partition 1 0 100\n/dev/dm-1 partition 1 0 -2\n");
        assert!(matches!(
            linux_swap(&table, |e| (e == "/dev/dm-1").then_some(true)),
            Swap::Safe(_)
        ));
        let plain = format!("{HEADER}/swapfile file 1 0 -2\n");
        assert_eq!(
            linux_swap(&plain, |_| None),
            Swap::Unverified("/swapfile".to_owned())
        );
        let open = format!("{HEADER}/dev/dm-2 partition 1 0 -2\n");
        assert_eq!(
            linux_swap(&open, |_| Some(false)),
            Swap::Unverified("/dev/dm-2".to_owned()),
            "a dm device that is not dm-crypt"
        );
    }
}

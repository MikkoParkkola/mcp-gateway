// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process helpers for rows that start processes of their own: whether a pid
//! is still alive, and a guard that kills it when the row ends.
#![allow(dead_code, reason = "each test crate uses part of this helper")]

use std::process::Stdio;

/// Whether `pid` is a live process (not gone, not a zombie).
pub fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}

/// SIGKILLs a pid when the row ends, so a red run leaks no process.
pub struct KillPid(pub u32);

impl Drop for KillPid {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &self.0.to_string()])
            .stderr(Stdio::null())
            .status();
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process helpers for rows that start processes of their own: whether a pid
//! is still alive, and a guard that kills it when the row ends.
#![allow(dead_code, reason = "each test crate uses part of this helper")]

use std::process::Stdio;

/// `pid`'s state as `ps` prints it, its letter first and then any flags
/// (`S`, `Tl`, `Z+`); empty once the pid is gone.
fn stat(pid: u32) -> String {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Whether `pid` is a live process (not gone, not a zombie).
pub fn alive(pid: u32) -> bool {
    let stat = stat(pid);
    !stat.is_empty() && !stat.starts_with('Z')
}

/// Whether `pid` is stopped (SIGSTOP): its state letter is `T`, whatever flags follow it.
pub fn stopped(pid: u32) -> bool {
    stat(pid).starts_with('T')
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

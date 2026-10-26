// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A descriptor the gateway holds without close-on-exec makes the preview
//! refuse instead of leaking into it (ADR-027, Linux step 1).
//!
//! Its own test binary: the leaked descriptor would reach every process any
//! concurrent test in the same binary starts.
#![cfg(target_os = "linux")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};

use mcp_gateway::preview_sandbox::{Target, start_with_helper};
use tokio::io::AsyncReadExt as _;

#[tokio::test]
async fn an_inherited_descriptor_makes_the_preview_refuse() {
    let file = tempfile::tempfile().unwrap();
    rustix::io::fcntl_setfd(file.as_fd(), rustix::io::FdFlags::empty()).unwrap();
    let target = Target {
        program: PathBuf::from("/bin/true"),
        args: Vec::new(),
    };
    let mut started = match start_with_helper(Path::new(gateway_bin::path()), &target, &[]) {
        Ok(started) => started,
        Err(refusal) => {
            assert!(
                std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
                "the sandbox is required here but refused: {refusal}"
            );
            return;
        }
    };
    let mut stderr = String::new();
    started
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .await
        .unwrap();
    let status = started.child.wait().await.unwrap();
    if stderr.starts_with("unshare:") {
        assert!(
            std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
            "the sandbox is required here but refused: {stderr}"
        );
        return;
    }
    assert!(!status.success());
    assert!(
        stderr.contains("refused at checking descriptors (inherited:"),
        "{stderr}"
    );
    drop(file);
}

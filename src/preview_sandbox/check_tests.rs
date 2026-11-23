// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R18b: `check`, what the route may offer a preview at all before any token
//! or start, taken directly (no route seam in between).

use std::ffi::OsString;
use std::path::PathBuf;

use super::{Refusal, Target, check};

fn target(program: &str, args: &[&str]) -> Target {
    Target {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
    }
}

/// R18b, kills "the old uv step text" and "check refuses too much": a plain
/// command and plain npx pass; an option before npx's spec refuses with the
/// plan's words; uvx refuses with the gate's words.
#[test]
fn r18b_check_passes_plain_commands_and_refuses_options_and_uvx() {
    assert_eq!(check(&target("sh", &["server.sh"])), Ok(()));
    assert_eq!(check(&target("npx", &["probe-cli"])), Ok(()));
    assert_eq!(check(&target("npx", &["-y", "probe-cli"])), Ok(()));
    assert_eq!(
        check(&target("npx", &["--registry=http://x", "p"])),
        Err(Refusal::Command(
            "an npx/uvx option before the package".into()
        ))
    );
    assert_eq!(
        check(&target("uvx", &["probe-cli"])),
        Err(Refusal::Command(
            "uvx previews are not enabled in this build".into()
        ))
    );
}

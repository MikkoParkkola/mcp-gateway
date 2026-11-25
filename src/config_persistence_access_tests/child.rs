// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The save a row runs as another user. With no target in its environment
//! (any ordinary run of ignored tests) it does nothing.

use std::path::PathBuf;

use super::{CHILD_MODE, CHILD_TARGET, RESULT};
use crate::config_persistence::{FileMode, Symlink, write_atomic, write_text_atomic};

#[test]
#[ignore = "child process"]
fn save() {
    let Some(target) = std::env::var_os(CHILD_TARGET) else {
        return;
    };
    let target = PathBuf::from(target);
    let mode = match std::env::var(CHILD_MODE).as_deref() {
        Ok("private") => FileMode::Private,
        Ok("inherit") => FileMode::Inherit,
        // The config text writer: its error is a String, reported with kind `Text`.
        Ok("text") => {
            match write_text_atomic(&target, "new") {
                Ok(()) => println!("{RESULT} saved"),
                Err(message) => println!("{RESULT} refused Text {message}"),
            }
            return;
        }
        other => panic!("{CHILD_MODE} must be private, inherit or text, got {other:?}"),
    };
    match write_atomic(&target, b"new", mode, Symlink::Follow) {
        Ok(()) => println!("{RESULT} saved"),
        Err(e) => println!("{RESULT} refused {:?} {e}", e.kind()),
    }
}

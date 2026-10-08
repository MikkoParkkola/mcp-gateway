// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: what `start` refuses before a child ever runs, and how.

use std::collections::HashMap;
use std::time::Duration;

use super::StdioTransport;
use crate::Error;

// A command line that cannot be split, or splits to nothing, is refused
// before any spawn as a config error: retrying cannot fix it.
#[tokio::test]
async fn an_unterminated_quote_is_a_config_error() {
    let transport = StdioTransport::new(
        "server \"unterminated",
        HashMap::new(),
        None,
        Duration::from_secs(1),
        None,
    );
    let err = transport
        .start()
        .await
        .expect_err("bad quoting cannot start");
    assert!(matches!(err, Error::Config(_)), "got {err:?}");
}

// A file that exists and may be executed but is no program the OS can
// load (ENOEXEC) is neither of the two kinds `start` treats as permanent,
// so it stays a retryable transport failure. Linux refuses the spawn; macOS
// spawns it and the child exits 126 before initialize. Both are Transport.
#[cfg(unix)]
#[tokio::test]
async fn a_file_the_os_cannot_execute_is_a_transport_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-program");
    std::fs::write(&path, b"\x00\x01\x02 no shebang, no format\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let transport = StdioTransport::new(
        path.to_str().unwrap(),
        HashMap::new(),
        None,
        Duration::from_secs(1),
        None,
    );
    let err = transport.start().await.expect_err("nothing to run");
    let expected = if cfg!(target_os = "macos") {
        "exit status: 126"
    } else {
        "Failed to spawn"
    };
    assert!(
        matches!(&err, Error::Transport(m) if m.contains(expected)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_blank_command_is_a_config_error() {
    for command in ["", "   "] {
        let transport =
            StdioTransport::new(command, HashMap::new(), None, Duration::from_secs(1), None);
        let err = transport.start().await.expect_err("nothing to spawn");
        assert!(
            matches!(&err, Error::Config(m) if m == "Empty command"),
            "{command:?}: got {err:?}"
        );
    }
}

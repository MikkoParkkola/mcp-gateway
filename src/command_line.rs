//! Shared shell-style command parsing helpers.

use std::path::Path;

use crate::{Error, Result};

/// Split a shell-style command string into tokens.
///
/// Quoted paths and arguments are preserved as single tokens. Returns a config
/// error when the command is empty or contains invalid quoting.
pub fn split_command_line(command: &str) -> Result<Vec<String>> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(Error::Config("Command cannot be empty".to_string()));
    }

    let parts = shlex::split(trimmed)
        .ok_or_else(|| Error::Config(format!("Invalid command quoting: {command}")))?;

    if parts.is_empty() {
        return Err(Error::Config("Command cannot be empty".to_string()));
    }

    Ok(parts)
}

/// Parse a command string into the program and trailing arguments.
pub fn program_and_args(command: &str) -> Result<(String, Vec<String>)> {
    let mut parts = split_command_line(command)?;
    let program = parts.remove(0);
    Ok((program, parts))
}

/// Check whether a program exists either as a path or on `PATH`.
pub fn command_exists(program: &str) -> bool {
    let path = Path::new(program);
    if path.is_absolute() || path.components().count() > 1 {
        return path.is_file();
    }

    std::env::var_os("PATH").is_some_and(|path_var| {
        std::env::split_paths(&path_var).any(|dir| dir.join(program).is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_line_preserves_quoted_paths() {
        let parts = split_command_line(r#""/tmp/My App/bin/server" --flag "two words""#).unwrap();
        assert_eq!(
            parts,
            vec![
                "/tmp/My App/bin/server".to_string(),
                "--flag".to_string(),
                "two words".to_string(),
            ]
        );
    }

    #[test]
    fn split_command_line_rejects_invalid_quoting() {
        let error = split_command_line(r#""/tmp/My App/bin/server --flag"#).unwrap_err();
        assert!(error.to_string().contains("Invalid command quoting"));
    }

    #[test]
    fn command_exists_supports_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("fake-binary");
        std::fs::write(&binary, "#!/bin/sh\n").unwrap();

        assert!(command_exists(binary.to_str().unwrap()));
    }
}

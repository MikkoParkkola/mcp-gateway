// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `println!` and `print!` for CLI output that end the process cleanly when
//! stdout's reader has gone.
//!
//! Why: `mcp-gateway list | head` closes the pipe after ten lines, and the
//! next write fails with `BrokenPipe`. A Unix tool would be killed by SIGPIPE
//! and the shell would think nothing of it; Rust ignores SIGPIPE, so std's
//! `println!` panics instead and the release profile's `panic = "abort"`
//! dumps core. These exit 0 on `io::ErrorKind::BrokenPipe`, as a SIGPIPE'd
//! tool effectively does, and panic exactly as std does on every other write
//! error, so a full disk or a closed fd is still loud.
//!
//! SIGPIPE's disposition is deliberately left alone: restoring the default
//! would kill a serving gateway the moment a client socket closed.
//!
//! Scope: the binary takes these for every module with `#[macro_use]`. In the
//! library only the two CLI-output modules the binary prints through
//! (`cli::output`, `validator::cli_handler`) import them; server code keeps
//! std's macros.

/// Write formatted output to stdout, ending the process on `BrokenPipe`.
macro_rules! print {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let written = ::std::write!(::std::io::stdout().lock(), $($arg)*);
        if let ::std::result::Result::Err(error) = written {
            if error.kind() == ::std::io::ErrorKind::BrokenPipe {
                ::std::process::exit(0);
            }
            ::std::panic!("failed printing to stdout: {error}");
        }
    }};
}

/// Write a formatted line to stdout, ending the process on `BrokenPipe`.
macro_rules! println {
    () => {{
        use ::std::io::Write as _;
        let written = ::std::writeln!(::std::io::stdout().lock());
        if let ::std::result::Result::Err(error) = written {
            if error.kind() == ::std::io::ErrorKind::BrokenPipe {
                ::std::process::exit(0);
            }
            ::std::panic!("failed printing to stdout: {error}");
        }
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let written = ::std::writeln!(::std::io::stdout().lock(), $($arg)*);
        if let ::std::result::Result::Err(error) = written {
            if error.kind() == ::std::io::ErrorKind::BrokenPipe {
                ::std::process::exit(0);
            }
            ::std::panic!("failed printing to stdout: {error}");
        }
    }};
}

// Path imports for library modules; the binary reaches the macros through
// `#[macro_use]` and leaves these unused.
#[allow(unused_imports)]
pub(crate) use {print, println};

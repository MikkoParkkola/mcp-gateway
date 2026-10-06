// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `println!` and `print!` for CLI output that end the process cleanly when
//! stdout's reader has gone.
//!
//! `mcp-gateway list | head`: once `head` exits, the next write fails with
//! `BrokenPipe`. Rust ignores SIGPIPE, so std's `println!` panics there, and the
//! release profile's `panic = "abort"` dumps core. A command whose reader has
//! gone has nothing more to say, so these exit with success instead. The
//! decision reads the error's `io::ErrorKind`; any other write failure panics
//! as std's macros do.
//!
//! These shadow std's macros by name. The binary takes them for every module
//! with `#[macro_use]` ahead of its other modules; a library module that prints
//! CLI output imports them with `use crate::cli::stdout::{print, println};`.

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

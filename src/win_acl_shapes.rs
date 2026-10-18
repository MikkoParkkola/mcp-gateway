// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The safe half of the Windows store custody module: the SID, descriptor
//! and ACE shapes, and the path encoding every Win32 call takes. Nothing here
//! is `unsafe`; every Win32 call stays in `win_acl.rs` (ADR-016).
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use super::SID_HEADER;

/// An owned, validated SID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sid(pub(super) Vec<u8>);

impl Sid {
    /// SDDL-style `S-R-A-S1-...` rendering, for refusal messages.
    pub(crate) fn to_sddl(&self) -> String {
        let b = &self.0;
        let authority = b[2..8]
            .iter()
            .fold(0_u64, |acc, x| (acc << 8) | u64::from(*x));
        let mut out = format!("S-{}-{authority}", b[0]);
        for chunk in b[SID_HEADER..].as_chunks::<4>().0 {
            let _ = write!(out, "-{}", u32::from_le_bytes(*chunk));
        }
        out
    }

    /// A SID from its authority and sub-authorities: well-known SIDs for
    /// value comparison, and synthetic `Inspection` values in tests. A SID has
    /// at most 15 sub-authorities (a caller bug above that, so it panics).
    pub(crate) fn from_parts(authority: u8, subs: &[u32]) -> Self {
        assert!(subs.len() <= 15, "a SID has at most 15 sub-authorities");
        let mut b = vec![
            1,
            u8::try_from(subs.len()).expect("at most 15"),
            0,
            0,
            0,
            0,
            0,
            authority,
        ];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        Self(b)
    }
}

/// Which kind of object a descriptor is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectKind {
    Dir,
    File,
}

/// Share mode for a created file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Share {
    /// No sharing: scratch files.
    Exclusive,
    /// Read and write sharing, never delete: custody sidecars.
    LockSidecar,
}

/// One decoded ACE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Ace {
    Allowed {
        flags: u8,
        mask: u32,
        sid: Sid,
    },
    Denied {
        flags: u8,
        mask: u32,
        sid: Sid,
    },
    /// Any other ACE type; its body is never read.
    Other {
        ace_type: u8,
    },
}

/// What `inspect` read from an open handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    pub(crate) owner: Option<Sid>,
    /// `None` is a NULL DACL (grants everyone).
    pub(crate) dacl: Option<Vec<Ace>>,
    pub(crate) protected: bool,
}

/// UTF-16, NUL-terminated; refuses an interior NUL (ADR-016 contract 5).
pub(super) fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let w: Vec<u16> = OsStr::new(path).encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    let mut w = long_form(path, w)?;
    w.push(0);
    Ok(w)
}

/// std's `get_long_path` rule, so these calls reach every path `std::fs`
/// does without the long-path opt-in: at or past `CreateDirectoryW`'s 248-unit
/// limit the absolute path gets the verbatim prefix (`\\?\`, UNC as
/// `\\?\UNC\`); a verbatim or shorter path reaches Win32 unchanged, and
/// one long only as written (`..`) reaches it resolved.
fn long_form(path: &Path, w: Vec<u16>) -> io::Result<Vec<u16>> {
    const LEGACY_MAX_PATH: usize = 248;
    let starts = |w: &[u16], p: &str| {
        p.encode_utf16()
            .enumerate()
            .all(|(i, c)| w.get(i) == Some(&c))
    };
    if w.is_empty() || starts(&w, r"\\?\") || starts(&w, r"\??\") {
        return Ok(w);
    }
    // GetFullPathNameW: absolute, `/` → `\`, `..` resolved (verbatim skips that).
    let abs: Vec<u16> = std::path::absolute(path)?
        .as_os_str()
        .encode_wide()
        .collect();
    if abs.len() + 1 < LEGACY_MAX_PATH {
        // Short once resolved: the written form unless that is the long one.
        return Ok(if w.len() + 1 < LEGACY_MAX_PATH {
            w
        } else {
            abs
        });
    }
    let (prefix, rest) = if starts(&abs, r"\\?\") || starts(&abs, r"\??\") {
        ("", &abs[..])
    } else if starts(&abs, r"\\.\") {
        (r"\\?\", &abs[4..])
    } else if starts(&abs, r"\\") {
        (r"\\?\UNC\", &abs[2..])
    } else if abs.get(1) == Some(&u16::from(b':')) {
        (r"\\?\", &abs[..])
    } else {
        ("", &abs[..])
    };
    Ok(prefix.encode_utf16().chain(rest.iter().copied()).collect())
}

/// A zeroed, 8-byte-aligned buffer of at least `bytes` bytes (contract 2).
pub(super) fn aligned(bytes: usize) -> Vec<u64> {
    vec![0_u64; bytes.div_ceil(8)]
}

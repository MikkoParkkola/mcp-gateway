// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows of `win_acl` that need its private helpers.

use super::wide;
use std::path::Path;

fn text(w: &[u16]) -> String {
    assert_eq!(w.last(), Some(&0), "wide() output is NUL-terminated");
    String::from_utf16(&w[..w.len() - 1]).unwrap()
}

// W-T27a: at or past CreateDirectoryW's 248-unit limit a path reaches
// Win32 in verbatim form (UNC as `\\?\UNC\`), as `std::fs` sends it; an
// already-verbatim or short path reaches it unchanged.
#[test]
fn wt27a_long_paths_reach_win32_verbatim() {
    let long = "d".repeat(250);
    let edge = |n: usize| format!(r"C:\{}", "e".repeat(n));
    let cases = [
        (format!(r"C:\{long}\f"), format!(r"\\?\C:\{long}\f")),
        (format!("C:/{long}/f"), format!(r"\\?\C:\{long}\f")),
        (
            format!(r"\\srv\share\{long}"),
            format!(r"\\?\UNC\srv\share\{long}"),
        ),
        (format!(r"\\?\C:\{long}"), format!(r"\\?\C:\{long}")),
        (r"C:\short\f".to_owned(), r"C:\short\f".to_owned()),
        // The threshold counts the terminating NUL: 246 units stay, 247 do not.
        (edge(243), edge(243)),
        (edge(244), format!(r"\\?\{}", edge(244))),
        (format!(r"\\.\C:\{long}"), format!(r"\\?\C:\{long}")),
        // Long as written, short once `..` resolves: the resolved form.
        (format!(r"C:\{long}\..\f"), r"C:\f".to_owned()),
    ];
    for (input, want) in cases {
        let got = text(&wide(Path::new(&input)).unwrap());
        assert_eq!(got, want, "WT-ASSERT W-T27a: {input}");
    }
    let relative = text(&wide(Path::new(&long)).unwrap());
    assert!(
        relative.starts_with(r"\\?\") && relative.ends_with(&format!(r"\{long}")),
        "WT-ASSERT W-T27a: relative long path became {relative}"
    );
}

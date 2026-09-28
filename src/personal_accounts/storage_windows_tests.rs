// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! W-T7 lexical rows (test plan §3): `validate_path` on its own.

use super::super::validate_path;
use crate::personal_accounts::AccountError;
use std::path::Path;

macro_rules! lexical_case {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                validate_path(Path::new($path)),
                Err(AccountError::InvalidConfiguration),
                "WT-ASSERT W-T7/{}: {} passed the lexical rule",
                stringify!($name),
                $path
            );
        }
    };
}
lexical_case!(wt7_lexical_unc, r"\\localhost\C$\mgw-wt7");
lexical_case!(wt7_lexical_verbatim_unc, r"\\?\UNC\localhost\C$\mgw-wt7");
lexical_case!(wt7_lexical_device, r"\\.\C:\mgw-wt7");
lexical_case!(wt7_lexical_globalroot, r"\\?\GLOBALROOT\Device\mgw-wt7");
lexical_case!(wt7_lexical_drive_relative, r"C:mgw-wt7");
lexical_case!(wt7_lexical_root_relative, r"\mgw-wt7");
lexical_case!(wt7_lexical_relative, r"mgw-wt7");
lexical_case!(wt7_lexical_parent_component, r"C:\a\..\mgw-wt7");

// The accepted forms: a drive and its verbatim spelling.
#[test]
fn wt7_lexical_drive_paths_pass() {
    for path in [r"C:\mgw-wt7-absent\x", r"\\?\C:\mgw-wt7-absent\x"] {
        assert_eq!(
            validate_path(Path::new(path)),
            Ok(()),
            "WT-ASSERT W-T7/accepted: {path}"
        );
    }
}

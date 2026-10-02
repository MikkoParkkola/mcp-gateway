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

// R1/R2 custody rows: the refusal and error arms of `private_directory` and
// `create_directory`, on real directories.
mod custody {
    use super::super::{create_directory, private_directory};
    use crate::personal_accounts::AccountError;
    use crate::private_fs::test_support::{assert_owner_only, deny_user, icacls, remove_deny};

    #[test]
    fn create_directory_makes_each_missing_level_private() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("a").join("b");
        assert_eq!(create_directory(&leaf), Ok(()));
        assert_owner_only("R2/leaf", &leaf, true);
        assert_owner_only("R2/parent", leaf.parent().unwrap(), true);
        // A second call finds the directory and changes nothing.
        assert_eq!(create_directory(&leaf), Ok(()));
    }

    #[test]
    fn create_directory_refuses_a_file_in_the_way() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            create_directory(&file),
            Err(AccountError::InvalidConfiguration)
        );
        assert_eq!(
            create_directory(&file.join("child")),
            Err(AccountError::InvalidConfiguration)
        );
    }

    #[test]
    fn create_directory_reports_a_parent_that_refuses_creation() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("locked");
        std::fs::create_dir(&parent).unwrap();
        deny_user("R2/deny", &parent, "WD,AD");
        let result = create_directory(&parent.join("child"));
        remove_deny("R2/deny", &parent);
        assert_eq!(result, Err(AccountError::StorageUnavailable));
    }

    #[test]
    fn private_directory_refuses_an_absent_path_a_file_and_a_shared_directory() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            private_directory(&root.path().join("absent")).err(),
            Some(AccountError::StorageUnavailable)
        );

        let file = root.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(private_directory(&file).is_err());

        let shared = root.path().join("shared");
        create_directory(&shared).unwrap();
        icacls("R1/shared", &shared, &["/grant", "*S-1-1-0:R"]);
        assert_eq!(
            private_directory(&shared).err(),
            Some(AccountError::InvalidConfiguration)
        );
    }
}

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check_identity_sources.py (MIK-8286 R7): every way around the
single-constructor rule fails the check; the real tree's shapes pass."""

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_identity_sources as cis  # noqa: E402

ORACLE = """impl VerifiedIdentity {
    pub(crate) fn checked(issuer: String, subject: String) -> Option<Self> {
        Some(Self { issuer, subject })
    }
}
"""


def tree(extra: dict[str, str], lib_mods: str = "") -> Path:
    files = {
        "src/lib.rs": "pub mod key_server;\n" + lib_mods,
        "src/main.rs": "fn main() {}\n",
        "src/key_server/mod.rs": "pub mod oidc;\n",
        "src/key_server/oidc.rs": "pub struct VerifiedIdentity { pub subject: String }\n"
                                  "#[path = \"oidc_identity.rs\"]\nmod identity;\n",
        "src/key_server/oidc_identity.rs": ORACLE,
    }
    files.update(extra)
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class Shapes(unittest.TestCase):
    def test_the_allowed_constructor_passes_and_a_return_type_is_no_literal(self):
        self.assertEqual(cis.violations(tree({})), [])

    def test_a_second_literal_in_an_allowed_file_fails(self):
        root = tree({"src/key_server/oidc_identity.rs": ORACLE.replace(
            "}\n}\n", "}\n    fn other() -> Self { Self { issuer: x, subject: y } }\n}\n")})
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_named_literal_anywhere_else_fails(self):
        root = tree({"src/a.rs": "fn mint() -> VerifiedIdentity { VerifiedIdentity { subject: s } }\n"},
                    "mod a;\n")
        self.assertIn("src/a.rs:1", cis.violations(root)[0])

    def test_a_type_alias_fails(self):
        root = tree({"src/a.rs": "type Vi = VerifiedIdentity;\nfn f() -> Vi { Vi { subject: s } }\n"},
                    "mod a;\n")
        self.assertTrue(any("alias" in v for v in cis.violations(root)))

    def test_grant_subject_new_outside_checked_fails_including_self_new(self):
        root = tree({"src/a.rs": "fn f() { let g = GrantSubject::new(a, b, None); }\n"
                     "impl GrantSubject { fn sneaky() -> Self { Self::new(a, b, None) } }\n"},
                    "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 2, cis.violations(root))


class ReadBacks(unittest.TestCase):
    CARRIER = "#[derive(Deserialize)]\npub struct Tok { identity: VerifiedIdentity }\n"

    def test_an_inferred_from_value_into_a_carrier_fails(self):
        root = tree({"src/a.rs": self.CARRIER + "fn load(v: Value) -> Tok { serde_json::from_value(v).unwrap() }\n"},
                    "mod a;\n")
        self.assertTrue(any("deserializes" in v for v in cis.violations(root)))

    def test_a_yaml_reader_into_a_carrier_fails(self):
        root = tree({"src/a.rs": self.CARRIER + "fn load(r: R) { let t: Tok = serde_yaml::from_reader(r).unwrap(); }\n"},
                    "mod a;\n")
        self.assertTrue(any("deserializes" in v for v in cis.violations(root)))

    def test_deserializing_an_unrelated_type_passes(self):
        root = tree({"src/a.rs": self.CARRIER + "fn load(v: Value) -> Other { serde_json::from_value(v).unwrap() }\n"},
                    "mod a;\n")
        self.assertEqual(cis.violations(root), [])


class TestDetection(unittest.TestCase):
    LIT = "fn mint() -> VerifiedIdentity { VerifiedIdentity { subject: s } }\n"

    def test_a_gated_path_module_is_test_code(self):
        root = tree({"src/a.rs": "#[cfg(test)]\n#[path = \"a_tests.rs\"]\nmod tests;\n", "src/a_tests.rs": self.LIT},
                    "mod a;\n")
        self.assertEqual(cis.violations(root), [])

    def test_a_production_module_named_tests_is_still_inspected(self):
        root = tree({"src/foo_tests.rs": self.LIT}, "mod foo_tests;\n")
        self.assertEqual(len(cis.violations(root)), 1)

    def test_a_gated_fn_is_skipped_but_its_ungated_neighbour_is_not(self):
        root = tree({"src/a.rs": "#[cfg(test)]\n" + self.LIT + self.LIT.replace("mint", "mint2")}, "mod a;\n")
        found = cis.violations(root)
        self.assertEqual(len(found), 1, found)
        self.assertIn("mint2", found[0])

    def test_cfg_alternatives_with_one_name_each_resolve_their_own_path(self):
        root = tree({
            "src/a.rs": "#[cfg(unix)]\n#[path = \"a_unix.rs\"]\nmod platform;\n"
                        "#[cfg(windows)]\n#[path = \"a_windows.rs\"]\nmod platform;\n",
            "src/a_unix.rs": "fn f() {}\n",
            "src/a_windows.rs": self.LIT,
        }, "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 1, "the windows file is reached and inspected")

    def test_an_unreached_file_fails_closed(self):
        root = tree({"src/orphan.rs": "fn f() {}\n"})
        self.assertTrue(any("not reached" in v for v in cis.violations(root)))


class RealTree(unittest.TestCase):
    def test_the_repository_passes(self):
        self.assertEqual(cis.violations(HERE.parents[1]), [])

    def test_the_repository_fails_without_its_allow_list(self):
        saved = dict(cis.ALLOWED)
        try:
            cis.ALLOWED.clear()
            found = {v.split(": ", 1)[0].rsplit(":", 1)[0] + " " + v.split("`")[3]
                     for v in cis.violations(HERE.parents[1])}
            self.assertEqual(found, {
                "src/identity_grants.rs new", "src/identity_grants.rs checked",
                "src/key_server/oidc_identity.rs checked", "src/mtls/identity.rs from_der",
            })
        finally:
            cis.ALLOWED.update(saved)


class CodeReviewBypasses(unittest.TestCase):
    """Each bypass the code-review seats found (MIK-8286 round 1) now fails."""

    LIT = "fn mint() -> VerifiedIdentity { VerifiedIdentity { subject: s } }\n"

    def test_a_cfg_that_also_compiles_outside_tests_is_production(self):
        root = tree({"src/a.rs": "#[cfg(any(test, unix))]\n" + self.LIT}, "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_cfg_all_with_test_is_test_code(self):
        root = tree({"src/a.rs": "#[cfg(all(test, unix))]\n" + self.LIT}, "mod a;\n")
        self.assertEqual(cis.violations(root), [])

    def test_production_reachability_wins_whatever_the_walk_order(self):
        root = tree({
            "src/a.rs": "#[cfg(test)]\n#[path = \"shared.rs\"]\nmod t;\n",
            "src/b.rs": "#[path = \"shared.rs\"]\nmod p;\n",
            "src/shared.rs": self.LIT,
        }, "mod a;\nmod b;\n")
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_renamed_import_fails(self):
        root = tree({"src/a.rs": "use crate::key_server::oidc::VerifiedIdentity as Vi;\n"}, "mod a;\n")
        self.assertTrue(any("imported as" in v for v in cis.violations(root)))

    def test_a_spaced_constructor_path_fails(self):
        root = tree({"src/a.rs": "fn f() { GrantSubject :: new (a, b, None); }\n"}, "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_spaced_self_constructor_in_an_identity_impl_fails(self):
        root = tree({"src/a.rs": "impl GrantSubject { fn f() -> Self { Self :: new (a, b, None) } }\n"},
                    "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_an_enum_or_crate_visible_carrier_read_back_fails(self):
        for carrier in (
            "#[derive(Deserialize)]\npub(crate) enum Tok { A(VerifiedIdentity) }\n",
            "#[derive(Deserialize)]\npub(crate) struct Tok(GrantSubject);\n",
        ):
            root = tree({"src/a.rs": carrier + "fn load(v: Value) -> Tok { serde_json::from_value(v).unwrap() }\n"},
                        "mod a;\n")
            self.assertTrue(any("deserializes" in v for v in cis.violations(root)), carrier)

if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check_identity_sources.py (MIK-8286 R7): every way around the
single-constructor rule fails the check; the real tree's shapes pass."""

import sys
import tempfile
import unittest
from unittest import mock
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
        "src/key_server/oidc.rs": "mod verified;\npub use verified::VerifiedIdentity;\n",
        "src/key_server/oidc/verified.rs": "pub struct VerifiedIdentity { pub subject: String }\n"
                                           + ORACLE,
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
        root = tree({"src/key_server/oidc/verified.rs": "pub struct VerifiedIdentity { pub subject: String }\n" + ORACLE.replace(
            "}\n}\n", "}\n    fn other() -> Self { Self { issuer: x, subject: y } }\n}\n")})
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_named_literal_anywhere_else_fails(self):
        root = tree({"src/a.rs": "fn mint() -> VerifiedIdentity { VerifiedIdentity { subject: s } }\n"},
                    "mod a;\n")
        self.assertIn("src/a.rs:1", cis.violations(root)[0])

    def test_a_literal_in_the_old_checked_constructor_file_fails(self):
        # The allow-list names the constructor's new file only; the same fn
        # name in the file it moved out of is no longer a listed site.
        root = tree({"src/key_server/oidc.rs": "mod verified;\npub use verified::VerifiedIdentity;\n"
                                               "#[path = \"oidc_identity.rs\"]\nmod identity;\n",
                     "src/key_server/oidc_identity.rs": ORACLE.replace("Self {", "VerifiedIdentity {")})
        found = cis.violations(root)
        self.assertEqual(len(found), 1, found)
        self.assertIn("src/key_server/oidc_identity.rs:3", found[0])

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

    # MIK-8425 MIG.1a: a read routed through the YAML adapter is still a read.
    ADAPTER_READS = ("from_str", "from_str_loose", "from_value", "documents")

    def test_an_adapter_read_into_a_carrier_fails_bare_and_prefixed(self):
        for prefix in ("yaml::", "crate::yaml::"):
            for name in self.ADAPTER_READS:
                with self.subTest(call=prefix + name):
                    body = f"fn load(s: &str) -> Tok {{ {prefix}{name}(s).unwrap() }}\n"
                    root = tree({"src/a.rs": self.CARRIER + body}, "mod a;\n")
                    self.assertTrue(any("deserializes" in v for v in cis.violations(root)))

    def test_an_adapter_write_and_a_lookalike_module_pass(self):
        for body in ("fn save(t: &Tok) -> String { yaml::to_string(t).unwrap() }\n",
                     "fn load(s: &str) -> Tok { my_yaml::from_str(s).unwrap() }\n"):
            with self.subTest(body=body):
                root = tree({"src/a.rs": self.CARRIER + body}, "mod a;\n")
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
                "src/identity_grants/subject.rs new",
                "src/key_server/oidc/verified.rs checked", "src/mtls/identity/cert.rs parse",
                # GrantSubject::new is checked; each call site is listed
                # until the rule is retired.
                "src/identity_grants/subject.rs try_from",
                "src/decisions/mod.rs access_key", "src/decisions/mod.rs covered",
                "src/decisions/mod.rs denial_from_record",
                "src/gateway/meta_mcp/invoke/budget.rs grant_subject_from_api_key",
                "src/gateway/router/identity.rs grant_subject_from_cert_identity",
                "src/gateway/router/identity.rs grant_subject_from_oauth_agent",
                "src/gateway/router/identity.rs grant_subject_from_verified_identity",
                "src/gateway/router/identity.rs trusted_proxy_identity",
                "src/gateway/ui/admin_audit.rs caller_who",
                "src/gateway/ui/admin_audit.rs recorded",
                "src/gateway/ui/events.rs admitted", "src/gateway/ui/tool_call.rs via_label",
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

    # MIK-9387.TCFG.2: the shared reader decides (scripts/dev/check-orphan-test-modules.py).
    def test_an_any_whose_every_operand_needs_test_is_test_code(self):
        root = tree({"src/a.rs": "#[cfg(any(test, all(test, unix)))]\n" + self.LIT}, "mod a;\n")
        self.assertEqual(cis.violations(root), [])

    def test_a_quoted_comma_is_not_an_operand(self):
        root = tree({"src/a.rs": '#[cfg(all(feature = "a,test,b"))]\n' + self.LIT}, "mod a;\n")
        self.assertEqual(len(cis.violations(root)), 1, cis.violations(root))

    def test_a_child_of_an_inner_test_file_is_test_code(self):
        root = tree({"src/a.rs": "#![cfg(test)]\nmod child;\n", "src/a/child.rs": self.LIT}, "mod a;\n")
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


class SameNames(unittest.TestCase):
    """Two types may share a name in different modules; only the one a
    reference resolves to decides whether it carries an identity."""

    A = "#[derive(Deserialize)]\npub struct Decision { who: GrantSubject }\n"
    READ = "fn load(s: &str) -> Body { serde_json::from_str(s).unwrap() }\n"
    MODS = "mod a;\nmod b;\nmod c;\n"

    def run_b(self, b: str, c: str = "") -> list[str]:
        root = tree({"src/a.rs": self.A, "src/b.rs": b + self.READ, "src/c.rs": c}, self.MODS)
        return [v for v in cis.violations(root) if "deserializes" in v]

    def test_a_namesake_is_flagged_until_its_site_is_listed(self):
        b = ("#[derive(Deserialize)]\nenum Decision { Yes, No }\n"
             "#[derive(Deserialize)]\nstruct Body { d: Decision }\n")
        self.assertEqual(len(self.run_b(b)), 1, "a name is never resolved, so a namesake counts")
        with mock.patch.dict(cis.READ_BACKS, {("src/b.rs", "load"): "row: a namesake enum, no identity"}):
            self.assertEqual(self.run_b(b), [])

    def test_a_listed_site_that_is_no_longer_flagged_fails(self):
        b = "#[derive(Deserialize)]\nstruct Body { d: u8 }\n"
        root = tree({"src/a.rs": self.A, "src/b.rs": b + self.READ, "src/c.rs": ""}, self.MODS)
        with mock.patch.dict(cis.READ_BACKS, {("src/b.rs", "load"): "row: stale"}, clear=True):
            self.assertEqual(len(cis.stale_read_backs(cis.scan(root)[1])), 1)
            self.assertEqual(cis.main(["x", str(root)]), 1)

    def test_the_repository_has_no_stale_read_back(self):
        self.assertEqual(cis.stale_read_backs(cis.scan(HERE.parents[1])[1]), [])

    def test_an_imported_carrier_still_fails(self):
        b = "use crate::a::Decision;\n#[derive(Deserialize)]\nstruct Body { d: Decision }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_qualified_carrier_still_fails(self):
        b = "#[derive(Deserialize)]\nstruct Body { d: crate::a::Decision }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_carrier_imported_under_another_name_fails(self):
        b = "use crate::a::Decision as Choice;\n#[derive(Deserialize)]\nstruct Body { d: Choice }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_type_alias_of_a_carrier_fails(self):
        b = "type Choice = crate::a::Decision;\n#[derive(Deserialize)]\nstruct Body { d: Choice }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_re_exported_carrier_fails(self):
        b = "use crate::c::Decision;\n#[derive(Deserialize)]\nstruct Body { d: Decision }\n"
        self.assertEqual(len(self.run_b(b, "pub use crate::a::Decision;\n")), 1)

    def test_an_unresolvable_name_fails_closed(self):
        b = "use crate::a::*;\n#[derive(Deserialize)]\nstruct Body { d: Decision }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_carrier_in_a_generic_default_fails(self):
        b = ("#[derive(Deserialize)]\nstruct Wrap<T = GrantSubject> { who: T }\n"
             "#[derive(Deserialize)]\nstruct Body { d: Wrap }\n")
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_carrier_in_an_alias_generic_default_fails(self):
        b = "type Choice<T = crate::a::Decision> = Vec<T>;\n#[derive(Deserialize)]\nstruct Body { d: Choice }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_manual_deserialize_impl_carrier_fails(self):
        b = ("struct Wrap { who: GrantSubject }\n"
             "impl<'de> serde::Deserialize<'de> for Wrap { fn deserialize() {} }\n"
             "#[derive(Deserialize)]\nstruct Body { d: Wrap }\n")
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_union_carrier_fails(self):
        b = ("#[derive(Deserialize)]\nunion Wrap { who: std::mem::ManuallyDrop<GrantSubject> }\n"
             "#[derive(Deserialize)]\nstruct Body { d: Wrap }\n")
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_carrier_renamed_by_a_re_export_behind_a_glob_fails(self):
        b = "use crate::c::*;\n#[derive(Deserialize)]\nstruct Body { d: Choice }\n"
        self.assertEqual(len(self.run_b(b, "pub use crate::a::Decision as Choice;\n")), 1)

    def test_a_wrapping_type_alias_of_a_carrier_fails(self):
        b = "type Choice = Vec<crate::a::Decision>;\n#[derive(Deserialize)]\nstruct Body { d: Choice }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_carrier_through_a_module_alias_fails(self):
        b = ("#[derive(Deserialize)]\nenum Decision { Yes }\nuse crate::a as m;\n"
             "#[derive(Deserialize)]\nstruct Body { d: m::Decision }\n")
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_generic_parameter_shadowing_a_namesake_fails(self):
        b = ("#[derive(Deserialize)]\nenum Decision { Yes }\n"
             "#[derive(Deserialize)]\nstruct Body { d: u8 }\n"
             "fn read<Decision: DeserializeOwned>(s: &str) -> Decision { serde_json::from_str(s).unwrap() }\n")
        self.assertEqual(len(self.run_b(b)), 1)

    def test_a_lowercase_carrier_fails(self):
        b = "#[derive(Deserialize)]\nstruct body_t { who: GrantSubject }\nstruct Body;\n" \
            "fn read(s: &str) -> body_t { serde_json::from_str(s).unwrap() }\n"
        self.assertEqual(len(self.run_b(b)), 1)

    def test_cfg_alternative_imports_of_one_name_fail(self):
        c = "#[derive(Deserialize)]\npub enum Decision { Yes, No }\n"
        b = ("#[cfg(unix)]\nuse crate::c::Decision;\n#[cfg(not(unix))]\nuse crate::a::Decision;\n"
             "#[derive(Deserialize)]\nstruct Body { d: Decision }\n")
        self.assertEqual(len(self.run_b(b, c)), 1)

    def test_a_namesake_in_a_file_included_twice_fails(self):
        c = "#[derive(Deserialize)]\npub enum Decision { Yes, No }\n"
        b = "use crate::c::Decision;\n#[derive(Deserialize)]\nstruct Body { d: Decision }\n"
        root = tree({"src/a.rs": self.A, "src/b.rs": b + self.READ, "src/c.rs": c},
                    self.MODS + '#[path = "c.rs"]\nmod c2;\n')
        self.assertEqual(len([v for v in cis.violations(root) if "deserializes" in v]), 1)


if __name__ == "__main__":
    unittest.main()

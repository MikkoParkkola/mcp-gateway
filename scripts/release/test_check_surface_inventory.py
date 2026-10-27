#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Plain-assert checks for check_surface_inventory.py (MIK-8044).

Runs the real check over the repository, so CI fails while any surface item
is unclassified, and proves the check fails on each kind of gap.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_surface_inventory as inv  # noqa: E402

DOC = """# x
## Surface: env
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `A` | KEEP | needed | - | src/a.rs:1 |
| `B` | INTERNAL | test hook | test-only | src/b.rs:2 |
## Notes
| `C` | BOGUS | outside any surface table, ignored | - | x |
"""
EXTRACTED = {"env": [inv.Entry("A", "src/a.rs", 1), inv.Entry("B", "src/b.rs", 9)]}


# cli has no extractor here (its membership is tests/cli_surface_inventory.rs):
# its filler row is extracted by nothing and must sit under src/cli/.
FILLER = {s: [inv.Entry(f"x-{s}", "src/x.rs", 1)] for s in inv.EXTRACTORS if s != "env"}
FILLER_ROWS = "".join(
    f"## Surface: {s}\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n"
    f"| `x-{s}` | KEEP | filler | - | {'src/cli/x.rs:1' if s == 'cli' else 'src/x.rs:1'} |\n"
    for s in inv.SURFACES
    if s != "env"
)


def check(doc: str, extracted=None) -> list[str]:
    full = dict(FILLER)
    full.update(extracted if extracted is not None else EXTRACTED)
    return inv.check(doc + FILLER_ROWS, full)


def test_complete_doc_passes() -> None:
    assert check(DOC) == [], check(DOC)


def test_blank_or_missing_reason_fails() -> None:
    for placeholder in ("", "-", "—", "n/a", "N/A", "none", "?", "  "):
        doc = DOC.replace("| `A` | KEEP | needed |", f"| `A` | KEEP | {placeholder} |")
        assert any("'A' has no reason" in e for e in check(doc)), (placeholder, check(doc))
    no_col = DOC.replace("| Item | Class | Reason | Migration |", "| Item | Class | Migration |").replace(" needed |", "").replace(" test hook |", "")
    assert {"line 5: 'A' has no reason", "line 6: 'B' has no reason"} <= set(check(no_col)), check(no_col)


def test_missing_row_fails() -> None:
    errors = check(DOC, {"env": EXTRACTED["env"] + [inv.Entry("D", "src/d.rs", 4)]})
    assert any("unclassified 'D'" in e for e in errors), errors


def test_stale_row_fails() -> None:
    errors = check(DOC, {"env": EXTRACTED["env"][:1]})
    assert any("'B' no longer exists" in e for e in errors), errors


def test_bad_class_fails() -> None:
    errors = check(DOC.replace("| KEEP |", "| MAYBE |"))
    assert any("class 'MAYBE'" in e for e in errors), errors


def test_non_keep_without_migration_fails() -> None:
    errors = check(DOC.replace("| test-only |", "| - |"))
    assert any("no migration story" in e for e in errors), errors


def test_wrong_file_fails() -> None:
    errors = check(DOC.replace("src/b.rs:2", "src/z.rs:2"))
    assert any("is defined in src/b.rs" in e for e in errors), errors


def test_duplicate_row_fails() -> None:
    dup = DOC.replace("| `B` |", "| `A` | KEEP | x | - | src/a.rs:1 |\n| `B` |")
    assert any("listed twice" in e for e in check(dup)), check(dup)


def test_empty_surface_fails() -> None:
    errors = inv.check(DOC + FILLER_ROWS, {**FILLER, "env": []})
    assert any("env: extractor returned no items" in e for e in errors), errors
    errors = inv.check(DOC + FILLER_ROWS, {k: v for k, v in FILLER.items()} | {"env": EXTRACTED["env"]} | {"lib": []})
    assert any("lib: extractor returned no items" in e for e in errors), errors


def test_route_with_named_handler_is_extracted() -> None:
    """A literal path is an item whatever its handler expression looks like."""
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        f = Path(tmp) / "planted.rs"
        f.write_text(
            'fn r(h: H, s: S, n: Router) -> Router {\n'
            '    Router::new().route("/planted", h).route_service("/svc", s).nest("/nested", n)\n}\n',
            encoding="utf-8",
        )
        ids = {e.id for e in inv.extract_routes()}
    for path in ('"/planted"', '"/svc"', '"/nested"'):
        assert any(path in i for i in ids), (path, sorted(ids))


def test_route_expression_over_a_constant_is_an_item() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        (Path(tmp) / "planted.rs").write_text(
            'fn r() { x.route(routes::HEALTH.trim_end_matches("h"), h) . route ("/spaced", h); }\n',
            encoding="utf-8",
        )
        ids = {e.id for e in inv.extract_routes()}
    assert any("trim_end_matches" in i for i in ids), sorted(ids)
    assert any('"/spaced"' in i for i in ids), sorted(ids)


def test_lib_extractor_sees_async_const_fn_and_macros() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        f = Path(tmp) / "planted_lib.rs"
        f.write_text(
            "pub async fn planted_async() {}\npub const fn planted_const() {}\n"
            "#[macro_export]\nmacro_rules! planted_macro { () => {} }\n",
            encoding="utf-8",
        )
        ids = {e.id for e in inv.extract_lib(f)}
    assert {"mcp_gateway::planted_async", "mcp_gateway::planted_const", "mcp_gateway::planted_macro!"} <= ids, ids


def test_serde_tag_key_is_a_config_item() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        f = Path(tmp) / "planted_cfg.rs"
        f.write_text(
            "#[derive(Deserialize)]\n#[serde(tag = \"kind\")]\nenum PlantedMode { A { x: u8 } }\n",
            encoding="utf-8",
        )
        g = Path(tmp) / "planted_adj.rs"
        g.write_text(
            "#[derive(Deserialize)]\n#[serde(tag = \"t\", content = \"c\")]\nenum PlantedAdj { A { y: u8 } }\n",
            encoding="utf-8",
        )
        w = inv.ConfigWalker()
        w.walk_item(inv.parse_items(f)[0], "planted", "", ())
        w.walk_item(inv.parse_items(g)[0], "adj", "", ())
    assert {"planted.kind", "planted.x", "adj.t", "adj.c", "adj.c.y"} <= set(w.out), sorted(w.out)
    assert "adj.y" not in w.out, sorted(w.out)


def test_ufcs_route_and_extern_crate_are_items() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        (Path(tmp) / "planted.rs").write_text(
            'fn r() { Router::route(app, "/ufcs", h); Router::<()>::route(app, "/generic", h); }\n', encoding="utf-8"
        )
        lib = Path(tmp) / "planted_lib.rs"
        lib.write_text(
            "pub extern crate planted_dep;\npub extern crate planted_raw as planted_alias;\n"
            "pub const unsafe fn planted_cu() {}\n#[macro_export(local_inner_macros)]\nmacro_rules! planted_lim { () => {} }\n",
            encoding="utf-8",
        )
        lib.write_text(lib.read_text(encoding="utf-8") + "mod planted_mac;\npub mod r#planted_raw;\n#[path = \"planted_lib/elsewhere.rs\"]\nmod planted_pathed;\n#[cfg(test)]\nmod planted_t;\n", encoding="utf-8")
        (Path(tmp) / "planted_lib").mkdir()
        mac = "#[macro_export]\nmacro_rules! {} {{ () => {{}} }}\n"
        (Path(tmp) / "planted_lib" / "planted_mac.rs").write_text(mac.format("planted_nested"), encoding="utf-8")
        (Path(tmp) / "planted_lib" / "planted_raw.rs").write_text(mac.format("planted_rawmac"), encoding="utf-8")
        (Path(tmp) / "planted_lib" / "elsewhere.rs").write_text(mac.format("planted_pathmac"), encoding="utf-8")
        (Path(tmp) / "planted_lib" / "planted_t.rs").write_text(mac.format("planted_testonly"), encoding="utf-8")
        (Path(tmp) / "planted_orphan.rs").write_text(mac.format("planted_orphan"), encoding="utf-8")
        ids = {e.id for e in inv.extract_routes()}
        libs = {e.id for e in inv.extract_lib(lib)}
    assert any('"/ufcs"' in i for i in ids), sorted(ids)
    assert any('"/generic"' in i for i in ids), sorted(ids)
    assert {"mcp_gateway::planted_nested!", "mcp_gateway::planted_rawmac!", "mcp_gateway::planted_pathmac!"} <= libs, sorted(libs)
    assert not {"mcp_gateway::planted_testonly!", "mcp_gateway::planted_orphan!"} & libs, sorted(libs)
    assert {"mcp_gateway::planted_dep", "mcp_gateway::planted_alias", "mcp_gateway::planted_cu", "mcp_gateway::planted_lim!"} <= libs, libs


def test_versioned_route_constant_is_read() -> None:
    names = [n for n, _, _ in inv.route_constants('owned_routes! {\n    HEALTH_V2 = "/v2/health",\n}')]
    assert names == ["HEALTH_V2"], names


def test_unresolved_route_constant_is_an_item() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        (Path(tmp) / "planted.rs").write_text("fn r() { x.route(routes::NOT_DECLARED_V9, h); }\n", encoding="utf-8")
        ids = {e.id for e in inv.extract_routes()}
    assert any(i.startswith("unresolved routes::NOT_DECLARED_V9") for i in ids), sorted(ids)


def test_not_http_route_allowlist_is_live() -> None:
    """Every allowlisted non-HTTP `.route(` call still exists, so the list cannot rot."""
    for file, arg in inv.NOT_HTTP_ROUTES:
        code, _ = inv.prod_scan(inv.ROOT / file)
        assert re.search(rf"\.route\(\s*{re.escape(arg)}\s*,", code), (file, arg)


def test_backend_keys_match_strict_keys_oracle() -> None:
    """Direct `backends.<name>` children equal the hand list in strict_keys.rs."""
    code = (inv.SRC / "config/strict_keys.rs").read_text(encoding="utf-8")
    want = set()
    for const in ("KNOWN_BACKEND_KEYS", "A2A_BACKEND_KEYS"):
        body = re.search(rf"const {const}: &\[&str\] = &\[(.*?)\];", code, re.S).group(1)
        want |= set(re.findall(r'"([^"]+)"', re.sub(r"//[^\n]*", "", body)))
    retired = {"idle_timeout", "circuit_breaker"}
    got = {
        e.id.split(".")[2]
        for e in inv.extract_config()
        if e.id.startswith("backends.<name>.") and e.id.count(".") == 2
    }
    assert got - retired == want, (sorted(got - retired - want), sorted(want - got))


def test_placeholder_reasons_fail() -> None:
    # MIK-8077.1/.2: every listed placeholder, plus the spellings reviewers found.
    words = set(inv.PLACEHOLDER_REASONS) | {"TODO", "TBD", "FIXME", "XXX", "later", "pending"}
    for word in sorted(words) + ["Todo", "tbd.", "FIXME!", "Pending"]:
        doc = DOC.replace("| `A` | KEEP | needed |", f"| `A` | KEEP | {word} |")
        assert any("'A' has no reason" in e for e in check(doc)), (word, check(doc))


def test_real_reasons_with_punctuation_pass() -> None:
    # MIK-8077.3: acronyms and punctuation are not placeholders.
    for reason in ("A2A transport (MIK-8063)", "TLS cert path", "later-stage hook, kept for tests"):
        doc = DOC.replace("| `A` | KEEP | needed |", f"| `A` | KEEP | {reason} |")
        assert check(doc) == [], (reason, check(doc))


def test_annotation_keys_are_config_rows() -> None:
    # MIK-8077.7: `_` and `x-` keys load at any level; tightening that must fail the gate.
    config = {e.id for e in inv.extract_config()}
    assert {"_*", "x-*"} <= config, sorted(i for i in config if "*" in i)
    rows = getattr(inv, "annotation_rows", None)
    assert rows is not None, "no annotation-key extractor"
    code = (inv.SRC / "config/strict_keys.rs").read_text(encoding="utf-8")
    narrowed = code.replace(' || key.starts_with("x-")', "")
    assert {e.id for e in rows(code, inv.SRC / "config/strict_keys.rs")} == {"_*", "x-*"}
    assert {e.id for e in rows(narrowed, inv.SRC / "config/strict_keys.rs")} == {"_*"}
    # Fails closed on a body it cannot read and on a removed call site (review r1).
    both = code.replace(' || key.starts_with("x-")', ' && key.starts_with("x-")')
    assert [e.id for e in rows(both, inv.SRC / "config/strict_keys.rs")][0].startswith("is_annotation: unrecognised"), both
    one_site = code.replace("} else if is_annotation(key) {", "} else if false {", 1)
    assert one_site != code
    sk = inv.SRC / "config/strict_keys.rs"
    # Review d2: a removed, negated, narrowed or literal-substituted branch all fail closed.
    for mutated in (
        one_site,
        code.replace("} else if is_annotation(key) {", "} else if !is_annotation(key) {", 1),
        code.replace("} else if is_annotation(key) {", "} else if is_annotation(key) && key.len() > 9 {", 1),
        code.replace("} else if is_annotation(key) {", '} else if "is_annotation(key) {".is_empty() {', 1),
        code.replace("            && is_annotation(leaf)\n", "            && is_annotation(leaf)\n            && leaf.len() > 9\n", 1),
        # Review d3: a narrowing predicate before the call, in either loader.
        code.replace("            && is_annotation(leaf)\n", "            && leaf.len() > 9\n            && is_annotation(leaf)\n", 1),
        code.replace("} else if is_annotation(key) {", "} else if key.len() > 9 && is_annotation(key) {", 1),
        # Review d4: a rejection added after the insert, in either loader.
        code.replace("ignored.insert(path, Ignored::Annotation);\n        } else if", "ignored.insert(path, Ignored::Annotation);\n            return;\n        } else if", 1),
        code.replace("ignored.insert(path, Ignored::Annotation);\n                } else {", "ignored.insert(path, Ignored::Annotation);\n                    found.insert(path, None);\n                } else {", 1),
    ):
        assert mutated != code
        got = [e.id for e in rows(mutated, sk)]
        assert got == ["is_annotation: accepting branches changed, re-read the annotation rows"], got


def test_cli_membership_is_the_rust_tests_and_row_format_stays() -> None:
    # Membership: tests/cli_surface_inventory.rs only; there is no cli extractor
    # here. Row format (class, reason, migration, one row per item, defined under
    # src/cli/) is checked as for every table.
    head = "## Surface: cli\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n"
    full = {s: [inv.Entry(f"x-{s}", "src/x.rs", 1)] for s in inv.EXTRACTORS}
    rows = "".join(f"## Surface: {s}\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n| `x-{s}` | KEEP | filler | - | src/x.rs:1 |\n" for s in full)
    good = head + "| `x --config` | KEEP | path | - | src/cli/mod.rs:1 |\n| `x --help` | KEEP | clap-generated | - | src/cli/mod.rs:1 |\n"
    assert inv.check(good + rows, full) == [], inv.check(good + rows, full)
    assert "cli" not in inv.EXTRACTORS, "no second cli extractor"
    for gone in ("extract_cli", "CliWalker", "cli_root_rows"):
        assert not hasattr(inv, gone), f"{gone} is back: cli membership is the Rust test's"
    try:
        inv.main(["--list", "cli"])
    except SystemExit as exc:
        assert exc.code == 2, f"--list cli exits {exc.code}, want argparse's 2"
    else:
        raise AssertionError("--list cli must be refused by argparse")
    no_rows = head
    assert inv.check(no_rows + rows, full) == [], "a missing cli row is the Rust test's to report, and no 'no items' error"
    elsewhere = good.replace("src/cli/mod.rs:1 |\n| `x --help`", "src/other.rs:1 |\n| `x --help`")
    assert any("want src/cli/" in e for e in inv.check(elsewhere + rows, full)), inv.check(elsewhere + rows, full)
    no_reason = good.replace("| clap-generated |", "| - |")
    assert any("has no reason" in e for e in inv.check(no_reason + rows, full))
    bad_class = good.replace("| `x --config` | KEEP |", "| `x --config` | BOGUS |")
    assert any("has class 'BOGUS'" in e for e in inv.check(bad_class + rows, full))
    no_migration = good.replace("| `x --config` | KEEP | path | - |", "| `x --config` | INTERNAL | path | - |")
    assert any("has no migration story" in e for e in inv.check(no_migration + rows, full))
    twice = good + "| `x --help` | KEEP | clap-generated | - | src/cli/mod.rs:1 |\n"
    assert any("listed twice" in e for e in inv.check(twice + rows, full))

def test_repository_inventory_is_complete() -> None:
    assert inv.main([]) == 0, "docs/design/surface-4.0.md misses surface items; see stderr"


HIDDEN_DOC = """## Surface: config
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `a.kept` | KEEP | needed | - | src/a.rs:1 |
| `a.hidden` | INTERNAL | tuning | hidden key | src/a.rs:2 |
| `a.auto` | AUTO | derived | hidden key | src/a.rs:3 |
"""


def table(*keys: str) -> str:
    return "pub(super) const HIDDEN_CONFIG_KEYS: &[&str] = &[" + ", ".join(f'"{k}"' for k in keys) + "];"


def test_hidden_table_matches_internal_and_auto_rows() -> None:
    assert inv.check_hidden_table(HIDDEN_DOC, table("a.hidden", "a.auto")) == []
    missing = inv.check_hidden_table(HIDDEN_DOC, table("a.hidden"))
    assert any("misses 'a.auto'" in e for e in missing), missing
    extra = inv.check_hidden_table(HIDDEN_DOC, table("a.hidden", "a.auto", "a.kept"))
    assert any("lists 'a.kept'" in e for e in extra), extra
    twice = inv.check_hidden_table(HIDDEN_DOC, table("a.hidden", "a.auto", "a.auto"))
    assert any("twice" in e for e in twice), twice
    assert inv.check_hidden_table(HIDDEN_DOC, "no table here") != []


def _lib_api(text: str, keep: frozenset[str] = frozenset()) -> list[str]:
    import tempfile

    with tempfile.TemporaryDirectory(dir=inv.ROOT / "src") as tmp:
        f = Path(tmp) / "planted_api.rs"
        f.write_text(text, encoding="utf-8")
        return inv.lib_documented(f, keep)


def test_surf5_hidden_crate_root_items_pass() -> None:
    assert _lib_api("#[doc(hidden)]\npub mod planted_h;\n#[doc(hidden)]\npub use crate::x::{A, B};\n#[doc(hidden)]\npub fn planted_f() {}\n") == []


def test_surf5_documented_crate_root_items_fail() -> None:
    found = _lib_api("pub mod planted_m;\npub use crate::x::{A, B};\npub fn planted_f() {}\n")
    for name in ("planted_m", "A", "B", "planted_f"):
        assert any(f"mcp_gateway::{name}" in p for p in found), (name, found)


def test_surf5_a_macro_export_anywhere_is_refused() -> None:
    found = _lib_api("mod inner {\n    #[macro_export]\n    macro_rules! planted { () => {} }\n}\n")
    assert any("macro_export" in p for p in found), found


def test_surf5_a_root_extern_block_is_refused() -> None:
    found = _lib_api('extern "C" {\n    pub fn planted_ext();\n}\n')
    assert any("extern" in p for p in found), found


def test_surf5_a_root_inline_module_is_refused() -> None:
    found = _lib_api("#[doc(hidden)]\npub mod planted_inline {\n    pub fn x() {}\n}\n")
    assert any("inline" in p for p in found), found


def test_surf5_a_pub_extern_block_is_refused() -> None:
    found = _lib_api('pub extern "C" {\n    pub fn planted_ext();\n}\n')
    assert any("extern" in p for p in found), found


def test_surf5_hidden_inside_another_attribute_is_not_hidden() -> None:
    found = _lib_api('#[deprecated(note = "#[doc(hidden)]")]\npub fn planted_f() {}\n')
    assert any("mcp_gateway::planted_f" in p for p in found), found


def test_surf5_a_root_include_is_refused() -> None:
    found = _lib_api('include!("planted_exports.rs");\n')
    assert any("include!" in p for p in found), found

def test_surf5_a_conditional_macro_export_is_refused() -> None:
    found = _lib_api("#[cfg_attr(windows, macro_export)]\nmacro_rules! planted { () => {} }\n")
    assert any("macro_export" in p for p in found), found


def test_surf5_a_conditional_module_path_is_refused() -> None:
    found = _lib_api('#[doc(hidden)]\n#[cfg_attr(windows, path = "planted_win.rs")]\npub mod planted_m;\n')
    assert any("path" in p for p in found), found


def test_surf5_hidden_text_in_a_raw_string_is_not_hidden() -> None:
    found = _lib_api('#[deprecated(note = r#"x "#[doc(hidden)]" y"#)]\npub fn planted_r() {}\n')
    assert any("mcp_gateway::planted_r" in p for p in found), found


def test_surf5_extern_fns_without_or_with_an_unusual_abi_are_seen() -> None:
    found = _lib_api('pub extern fn planted_e1() {}\npub extern "C-unwind" fn planted_e2() {}\n')
    for name in ("planted_e1", "planted_e2"):
        assert any(f"mcp_gateway::{name}" in p for p in found), (name, found)

def test_surf5_a_keep_listed_item_passes() -> None:
    assert _lib_api("pub fn planted_kept() {}\n", frozenset({"mcp_gateway::planted_kept"})) == []


def test_surf5_the_crate_root_documents_no_export() -> None:
    assert inv.lib_documented() == [], inv.lib_documented()


# py/redos (code scanning 531, 533, 573): a line of many attributes followed by
# text that does not complete the match once took seconds per regex, because
# every split of the attribute run was retried. The shared atomic ATTR_RUN
# matches each attribute once. Shapes are codex's measured witnesses.
ATTRS = "#[allow(dead_code)]" * 24


def _bounded(what: str, run) -> None:
    import time

    started = time.perf_counter()
    run()
    took = time.perf_counter() - started
    assert took < 0.25, f"{what} took {took:.3f}s on a pathological input"


def test_redos_outer_attrs_is_linear_on_a_line_of_attributes() -> None:
    text = ATTRS * 4 + "// gap\n"
    _bounded("OUTER_ATTRS_RE", lambda: inv.OUTER_ATTRS_RE.search(text))


def test_redos_lib_item_rejects_a_private_item_promptly() -> None:
    text = ATTRS * 4 + "struct Private;"
    _bounded("LIB_ITEM_RE", lambda: list(inv.LIB_ITEM_RE.finditer(text)))
    assert list(inv.LIB_ITEM_RE.finditer(text)) == [], "a private item is not public surface"


def test_redos_macro_export_is_linear_on_a_line_of_attributes() -> None:
    text = "#[macro_export]\n" + "#[allow(unused_macros)]" * 96 + "// gap\nmacro_rules! sample { () => {} }"
    _bounded("MACRO_EXPORT_RE", lambda: list(inv.MACRO_EXPORT_RE.finditer(text)))


def test_redos_fix_keeps_what_the_attribute_run_captures() -> None:
    same_line = '#[doc(hidden)] #[cfg(feature = "x")] pub fn f() {}'
    m = inv.LIB_ITEM_RE.search(same_line)
    assert m is not None and m.group(2) == "fn", same_line
    assert m.group(1) == '#[doc(hidden)] #[cfg(feature = "x")] ', repr(m.group(1))
    stacked = "#[doc(hidden)]\n#[cfg(test)]\npub mod m;"
    m = inv.LIB_ITEM_RE.search(stacked)
    assert m is not None and m.group(1) == "#[doc(hidden)]\n#[cfg(test)]\n", repr(m and m.group(1))
    exported = "#[macro_export]\n#[doc(hidden)]\nmacro_rules! sample { () => {} }"
    assert [m.group(1) for m in inv.MACRO_EXPORT_RE.finditer(exported)] == ["sample"]
    assert inv.OUTER_ATTRS_RE.search("x\n#[derive(Debug)]\n#[repr(C)]\n").group(1) == "#[derive(Debug)]\n#[repr(C)]\n"

if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {name}: {exc}")
    sys.exit(1 if failed else 0)

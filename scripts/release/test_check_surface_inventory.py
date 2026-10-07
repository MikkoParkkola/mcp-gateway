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


FILLER = {s: [inv.Entry(f"x-{s}", "src/x.rs", 1)] for s in inv.SURFACES if s != "env"}
FILLER_ROWS = "".join(
    f"## Surface: {s}\n| Item | Class | Migration | Defined at |\n|---|---|---|---|\n| `x-{s}` | KEEP | - | src/x.rs:1 |\n"
    for s in FILLER
)


def check(doc: str, extracted=None) -> list[str]:
    full = dict(FILLER)
    full.update(extracted if extracted is not None else EXTRACTED)
    return inv.check(doc + FILLER_ROWS, full)


def test_complete_doc_passes() -> None:
    assert check(DOC) == [], check(DOC)


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
        (Path(tmp) / "planted_mac.rs").write_text("#[macro_export]\nmacro_rules! planted_nested { () => {} }\n", encoding="utf-8")
        ids = {e.id for e in inv.extract_routes()}
        libs = {e.id for e in inv.extract_lib(lib)}
        nested = {e.id for e in inv.extract_lib()}
    assert any('"/ufcs"' in i for i in ids), sorted(ids)
    assert any('"/generic"' in i for i in ids), sorted(ids)
    assert "mcp_gateway::planted_nested!" in nested, sorted(nested)
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


def test_cli_root_globals_carry_their_env() -> None:
    cli = {e.id: e for e in inv.extract_cli()}
    assert "env MCP_GATEWAY_CONFIG" in cli["mcp-gateway --config"].note
    assert "mcp-gateway serve --stdio" in cli


def test_repository_inventory_is_complete() -> None:
    assert inv.main([]) == 0, "docs/design/surface-4.0.md misses surface items; see stderr"


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

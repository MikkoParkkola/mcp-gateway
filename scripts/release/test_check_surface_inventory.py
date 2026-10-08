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
    f"## Surface: {s}\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n| `x-{s}` | KEEP | filler | - | src/x.rs:1 |\n"
    for s in FILLER
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


def test_cli_root_globals_carry_their_env() -> None:
    cli = {e.id: e for e in inv.extract_cli()}
    assert "env MCP_GATEWAY_CONFIG" in cli["mcp-gateway --config"].note
    assert "mcp-gateway serve --stdio" in cli


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


CLI_FIXTURE = """
pub struct Args {
    #[arg(short, long)]
    config: String,
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    #[arg(long)]
    force: bool,
    #[arg(value_name = "DESCRIPTOR")]
    descriptor: PathBuf,
    target: String,
}
"""


def cli_rows(source: str) -> dict[str, inv.Entry]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "args.rs"
        path.write_text(source, encoding="utf-8")
        item = inv.parse_items(path)[0]
        walker = inv.CliWalker.__new__(inv.CliWalker)
        walker.out = {}
        orig_rel = inv.rel
        inv.rel = lambda p: p.name  # the fixture lives outside the repository
        try:
            walker.args(item.members, path, item.line, "x")
        finally:
            inv.rel = orig_rel
    return walker.out


def test_short_flag_alias_is_its_own_row() -> None:
    # MIK-8077.5: `-c` and `-e` are rows, each naming the long form it aliases.
    rows = cli_rows(CLI_FIXTURE)
    assert {"x --config", "x -c", "x --env", "x -e", "x --force"} <= set(rows), sorted(rows)
    assert rows["x -c"].note == "alias of --config", rows["x -c"]
    assert rows["x -e"].note == "alias of --env", rows["x -e"]
    assert "x -f" not in rows, sorted(rows)
    # Removing the `short` attribute removes the row, so the doc's row goes stale.
    assert "x -c" not in cli_rows(CLI_FIXTURE.replace("#[arg(short, long)]", "#[arg(long)]"))


def test_alias_class_must_match_its_long_form() -> None:
    # MIK-8077.5: an alias inherits its long form's class.
    head = "## Surface: cli\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n"
    entries = {"cli": [inv.Entry("x --config", "src/a.rs", 1), inv.Entry("x -c", "src/a.rs", 1, "alias of --config")]}
    full = {s: [inv.Entry(f"x-{s}", "src/x.rs", 1)] for s in inv.SURFACES if s != "cli"}
    full.update(entries)
    rows = "".join(f"## Surface: {s}\n| Item | Class | Reason | Migration | Defined at |\n|---|---|---|---|---|\n| `x-{s}` | KEEP | filler | - | src/x.rs:1 |\n" for s in full if s != "cli")
    same = head + "| `x --config` | KEEP | config path | - | src/a.rs:1 |\n| `x -c` | KEEP | short alias | - | src/a.rs:1 |\n"
    assert inv.check(same + rows, full) == [], inv.check(same + rows, full)
    differ = same.replace("| `x -c` | KEEP | short alias | - |", "| `x -c` | INTERNAL | short alias | use --config |")
    errors = inv.check(differ + rows, full)
    assert any("'x -c'" in e and "long form" in e for e in errors), errors


def test_positional_uses_value_name() -> None:
    # MIK-8077.8: clap shows `value_name`, so the row does too.
    rows = cli_rows(CLI_FIXTURE)
    assert "x <DESCRIPTOR>" in rows and "x <target>" in rows, sorted(rows)
    renamed = cli_rows(CLI_FIXTURE.replace('value_name = "DESCRIPTOR"', 'value_name = "FILE"'))
    assert "x <DESCRIPTOR>" not in renamed and "x <FILE>" in renamed, sorted(renamed)


def test_root_version_and_help_are_rows() -> None:
    # MIK-8077.6: clap generates them from the root `Cli` attributes.
    cli = {e.id for e in inv.extract_cli()}
    assert {"mcp-gateway --version", "mcp-gateway --help"} <= cli, sorted(i for i in cli if i.count(" ") == 1)
    root_rows = getattr(inv, "cli_root_rows", None)
    assert root_rows is not None, "no root-flag extractor"
    root = inv.Index().resolve("Cli", inv.SRC / "cli/mod.rs", "Parser")
    assert "mcp-gateway --version" in {e.id for e in root_rows(root)}
    root.attrs = root.attrs.replace("#[command(version, ", "#[command(")
    assert "mcp-gateway --version" not in {e.id for e in root_rows(root)}, root.attrs


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

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Plain-assert checks for surface_upgrading.py (MIK-8044.SURF.6).

UPGRADING-4.0.md carries a generated appendix naming every non-KEEP row of
docs/design/surface-4.0.md, and every REMOVE and AUTO row cites the prose a
user reads about it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import surface_upgrading as su  # noqa: E402

INV = """# x
## Surface: config
| Item | Class | Default | Reason | Migration | Defined at |
|---|---|---|---|---|---|
| `a.keep` | KEEP | - | needed | - | s:1 |
| `a.h1` | INTERNAL | - | limit one | hidden key, still read | s:2 |
| `a.h2` | INTERNAL | - | limit two | hidden key, still read | s:3 |
| `a.h3` | INTERNAL | - | other | hidden \\| piped | s:4 |
| `a.gone` | REMOVE | - | dead | refused at load; see UPGRADING 2 | s:5 |
| `a.auto` | AUTO | - | derived from x | hidden key; see upgrading.d/9-1.md | s:6 |
| `a.same` | AUTO | - | negotiated | no UPGRADING item: already derived in 3.x | s:7 |
## Surface: cli
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `tool x` | INTERNAL | dev | hidden key, still read | s:8 |
| `tool x --help` | INTERNAL | clap | hidden key, still read | s:9 |
## Notes
"""
GUIDE = """# Upgrading
## What changed
| # | Change |
|---|---|
| 1 | one |
| 2 | two |
## 1. One
x
## 2. Two
y
## Upgrading from 3.5.x: a walkthrough
w
## Rolling back
r
"""
FRAGS = {"9-1.md": "f"}


def rows(inv: str = INV):
    return su.rows_of(inv)


def block(inv: str = INV) -> str:
    return su.render(rows(inv))


def item_lines(text: str) -> list[str]:
    return [l for l in text.splitlines() if l.startswith("| `")]


def test_g1_equal_migrations_share_a_line_naming_every_id() -> None:
    lines = item_lines(block())
    one = [l for l in lines if "`a.h1`" in l]
    assert len(one) == 1 and "`a.h2`" in one[0], lines


def test_g1b_a_different_migration_is_its_own_line() -> None:
    lines = item_lines(block())
    assert not any("`a.h1`" in l and "`a.h3`" in l for l in lines), lines


def test_g1c_the_same_migration_on_two_surfaces_is_two_lines() -> None:
    lines = item_lines(block())
    assert not any("`a.h1`" in l and "`tool x`" in l for l in lines), lines


def test_g1d_help_flags_fold_into_their_command() -> None:
    lines = item_lines(block())
    assert any("`tool x`" in l and "`tool x --help`" in l for l in lines), lines


def test_g2_every_non_keep_id_appears_once_in_the_item_column() -> None:
    ids = su.item_ids(block())
    want = sorted(r.id for r in rows() if r.cls != "KEEP")
    assert sorted(ids) == want, (ids, want)


def test_g3_pipes_round_trip_and_order_is_stable() -> None:
    assert block() == block()
    assert "hidden \\| piped" in block(), block()


def test_g4_remove_and_auto_rows_stand_alone_with_their_reason() -> None:
    lines = item_lines(block())
    auto = [l for l in lines if "`a.auto`" in l]
    assert len(auto) == 1 and "derived from x" in auto[0] and "`a.same`" not in auto[0], lines


def test_g5_class_words() -> None:
    text = block()
    assert "| hidden |" in text and "| derived |" in text and "| removed |" in text, text


def test_d1_the_parser_keeps_an_escaped_pipe_in_its_cell() -> None:
    h3 = [r for r in rows() if r.id == "a.h3"][0]
    assert h3.migration == "hidden | piped", h3.migration


def test_c1_check_passes_when_current_and_names_write_when_stale() -> None:
    guide = su.write(GUIDE, block())
    assert su.appendix_errors(guide, block()) == []
    stale = su.write(GUIDE, block().replace("a.h1", "a.hX"))
    errs = su.appendix_errors(stale, block())
    assert len(errs) == 1 and "surface_upgrading.py write" in errs[0], errs


def test_m1_markers_missing_duplicated_or_reversed_fail() -> None:
    assert su.appendix_errors(GUIDE, block()), "missing markers passed"
    twice = su.write(GUIDE, block()) + "\n" + su.START + "\n" + su.END + "\n"
    assert su.appendix_errors(twice, block()), "duplicated markers passed"
    rev = GUIDE + "\n" + su.END + "\n" + su.START + "\n"
    assert su.appendix_errors(rev, block()), "reversed markers passed"


def test_m2_write_refuses_to_invent_markers_in_a_guide_that_has_some() -> None:
    try:
        su.write(GUIDE + su.START + "\n", block())
    except ValueError:
        return
    raise AssertionError("write accepted a lone start marker")


def test_a2_the_appendix_is_the_last_thing_in_the_guide() -> None:
    guide = su.write(GUIDE, block())
    assert guide.rstrip().endswith(su.END), guide[-200:]
    early = GUIDE.replace("## Rolling back", su.START + "\n" + block() + su.END + "\n## Rolling back")
    errs = su.appendix_errors(early, block())
    assert any("last" in e for e in errs), errs


def test_p1_remove_and_auto_rows_need_a_citation() -> None:
    bad = INV.replace("refused at load; see UPGRADING 2", "refused at load")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("`a.gone`" in e and "cites no UPGRADING item" in e for e in errs), errs
    bad = INV.replace("hidden key; see upgrading.d/9-1.md", "hidden key")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("`a.auto`" in e for e in errs), errs
    assert su.citation_errors(rows(), GUIDE, FRAGS) == []


def test_p3_internal_rows_need_no_citation() -> None:
    assert not any("a.h1" in e for e in su.citation_errors(rows(), GUIDE, FRAGS))


def test_p4_the_no_item_escape_is_for_auto_only() -> None:
    bad = INV.replace("refused at load; see UPGRADING 2", "no UPGRADING item: nothing changed")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("`a.gone`" in e for e in errs), errs


def test_p5_a_cited_item_that_does_not_exist_fails() -> None:
    bad = INV.replace("see UPGRADING 2", "see UPGRADING 99")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("UPGRADING 99" in e and "does not exist" in e for e in errs), errs


def test_p5b_a_cited_fragment_that_does_not_exist_fails() -> None:
    bad = INV.replace("upgrading.d/9-1.md", "upgrading.d/9-2.md")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("upgrading.d/9-2.md" in e for e in errs), errs


def test_p6_a_bare_upgrading_mention_is_no_citation() -> None:
    bad = INV.replace("see UPGRADING 2", "(UPGRADING entry)")
    errs = su.citation_errors(rows(bad), GUIDE, FRAGS)
    assert any("`a.gone`" in e for e in errs), errs


def test_a3_folding_a_fragment_rewrites_its_citations() -> None:
    inv = su.rewrite_citations(INV, {"9-1.md": 3})
    assert "see UPGRADING 3" in inv and "upgrading.d/9-1.md" not in inv, inv


def test_a3b_fragment_numbers_follow_the_assemble_order() -> None:
    import upgrading_fragments as uf

    assert uf.fragment_numbers(175, ["8044-6.md", "3730.md", "8044-2.md"]) == {
        "3730.md": 176,
        "8044-2.md": 177,
        "8044-6.md": 178,
    }


def test_a1_assemble_leaves_the_appendix_after_the_last_section() -> None:
    import upgrading_fragments as uf

    guide = su.write(GUIDE, block())
    frag = "---\nchange: c\naction: a\n---\n## Third\n\n**Startup:** no notice\n\nbody\n"
    out, _ = uf.assemble(guide, 2, {"9-1.md": frag})
    assert out.rstrip().endswith(su.END), out[-300:]
    assert out.split(su.START, 1)[1].split(su.END, 1)[0] == block()


QS = """# Quickstart
<!-- quickstart-minimal-config -->
```yaml
server:
  port: 39400
backends:
  everything:
    command: "npx -y @modelcontextprotocol/server-everything"
```
<!-- /quickstart-minimal-config -->
"""


def test_r2_the_minimal_setup_block() -> None:
    assert su.minimal_setup_errors(QS, {"e2e_fresh_home.rs"}) == []
    assert su.minimal_setup_errors(QS.replace("<!-- quickstart-minimal-config -->\n", ""), {"e2e_fresh_home.rs"})
    assert su.minimal_setup_errors(QS + QS, {"e2e_fresh_home.rs"})
    assert su.minimal_setup_errors(QS.replace("backends:\n  everything:\n    command: \"npx -y @modelcontextprotocol/server-everything\"\n", ""), {"e2e_fresh_home.rs"})
    assert su.minimal_setup_errors(QS, set()), "a missing SURF.7 test passed"
    fifteen = QS.replace("    command:", "\n" * 0 + "    command:").replace("```yaml\n", "```yaml\n" + "# pad\n" * 10)
    assert su.minimal_setup_errors(fifteen, {"e2e_fresh_home.rs"}) == [], fifteen
    sixteen = fifteen.replace("```yaml\n", "```yaml\n# pad\n")
    assert su.minimal_setup_errors(sixteen, {"e2e_fresh_home.rs"}), "16 lines passed"


def test_r1_the_repository_is_current() -> None:
    errs = su.repo_errors()
    assert errs == [], "\n".join(errs[:40])


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as exc:  # noqa: BLE001 - a crash is a failed row, named
                failed += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failed else 0)

# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The release notes' Known issues section names no later release, and is empty at a tag."""

import importlib.util
import os
import pathlib
import sys
import tempfile
import traceback

_spec = importlib.util.spec_from_file_location(
    "check_known_issues",
    pathlib.Path(__file__).with_name("check_known_issues.py"),
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def notes(known):
    """Release notes whose Known issues section holds `known`, between two others."""
    return (
        "# mcp-gateway 4.0.0 release notes\n\n"
        "## Breaking changes\n\n- Upgrading from 3.x to 4.0.1 later is fine.\n\n"
        f"## Known issues\n{known}\n"
        "## Performance\n\nThe 4.0.1 numbers come later.\n"
    )


ITEM = "\nThese ship in 4.0.0.\n\n- A replayed webhook can get through (MIK-7854).\n\n"


def run(text, *args):
    # The tag comes from the runner when --tag is absent; on an rc tag the
    # strict cases below would otherwise pass and the suite would go red.
    os.environ.pop("GITHUB_REF_NAME", None)
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp, "notes.md")
        path.write_text(text, encoding="utf-8")
        return check.main(["--notes", str(path), *args])


def test_a_section_without_a_later_release_passes_the_check():
    assert run(notes(ITEM), "--check") == 0


def test_a_later_release_in_a_bullet_fails_the_check():
    assert run(notes(ITEM + "- Fixed in 4.0.1 (MIK-7907).\n"), "--check") == 1


def test_a_later_release_in_the_intro_fails_the_check():
    intro = "\nThese ship in 4.0.0 and are fixed in 4.0.1.\n\n- One (MIK-7854).\n"
    assert run(notes(intro), "--check") == 1


def test_a_later_release_outside_the_section_is_not_its_business():
    # notes() names 4.0.1 under Breaking changes and Performance.
    assert "4.0.1" in notes(ITEM)
    assert run(notes(ITEM), "--check") == 0


def test_the_last_section_runs_to_the_end_of_the_file():
    text = "# Notes\n\n## Known issues\n\n- Fixed in 4.0.1 (MIK-1).\n"
    assert run(text, "--check") == 1


def test_any_content_fails_the_release_gate():
    assert run(notes(ITEM), "--release") == 1
    assert run(notes("\nThese ship in 4.0.0.\n\n"), "--release") == 1


def test_an_empty_or_absent_section_passes_the_release_gate():
    assert run(notes("\n\n"), "--release") == 0
    assert run("# Notes\n\n## Performance\n\nFast.\n", "--release") == 0


def test_the_release_gate_also_refuses_a_later_release():
    assert run(notes("\n- Fixed in 4.0.1.\n"), "--release") == 1


def test_a_prerelease_tag_may_ship_known_gaps():
    # docs/release/v4.0.0-prerelease-channel.md: open items ship as known gaps
    # in a beta's release notes.
    for tag in ("v4.0.0-beta.1", "v4.0.0-rc.2", "v4.0.0-rc.12"):
        assert run(notes(ITEM), "--release", "--tag", tag) == 0, tag


def test_only_beta_and_rc_tags_are_prereleases():
    # Same policy as check_scope_acceptance.py PRERELEASE_400: any other
    # suffix, build metadata included, is held to the final-tag rule.
    for tag in (
        "v4.0.0-alpha.1",
        "v4.0.0-hotfix",
        "v4.0.0-rc",
        "v4.0.0-rc.1+build.7",
        "v4.0.0-beta.1+build-7",
        "v4.0.1-rc.1",
        "v5.0.0-beta.1",
    ):
        assert run(notes(ITEM), "--release", "--tag", tag) == 1, tag


def test_another_version_containing_the_digits_is_not_the_later_release():
    for line in ("- Needs 14.0.1 of the toolchain.\n", "- Seen with 4.0.10 clients.\n"):
        assert run(notes("\n" + line), "--check") == 0, line


def test_the_later_release_is_found_at_any_word_boundary():
    for line in (
        "- Fixed in v4.0.1.\n",
        "- (4.0.1)\n",
        "- Due 4.0.1, maybe.\n",
        "- Fixed in 4.0.1-rc.1.\n",
        "- Fixed in 4.0.1+build.7.\n",
    ):
        assert run(notes("\n" + line), "--check") == 1, line


def test_a_prerelease_tag_still_refuses_a_later_release():
    assert run(notes("\n- Fixed in 4.0.1.\n"), "--release", "--tag", "v4.0.0-rc.1") == 1


def test_the_prerelease_tag_is_read_from_the_runner():
    os.environ["GITHUB_REF_NAME"] = "v4.0.0-beta.3"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "notes.md")
            path.write_text(notes(ITEM), encoding="utf-8")
            assert check.main(["--notes", str(path), "--release"]) == 0
    finally:
        os.environ.pop("GITHUB_REF_NAME", None)


def test_a_final_tag_or_any_other_ref_keeps_the_section_empty():
    # A branch name with a dash is not a prerelease; only a v-semver tag is.
    # A dash inside build metadata does not make a stable tag a prerelease.
    for tag in (
        "v4.0.0",
        "v4.0.0+build.1",
        "v4.0.0+build-1",
        "docs/ranking-1-release-line",
        "4.0.0-rc.1",
    ):
        assert run(notes(ITEM), "--release", "--tag", tag) == 1, tag


def test_an_explicit_tag_wins_over_the_runner_tag():
    os.environ["GITHUB_REF_NAME"] = "v4.0.0-rc.1"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "notes.md")
            path.write_text(notes(ITEM), encoding="utf-8")
            assert check.main(["--notes", str(path), "--release", "--tag", "v4.0.0"]) == 1
    finally:
        os.environ.pop("GITHUB_REF_NAME", None)


def test_an_unreadable_file_fails_closed():
    assert check.main(["--notes", "/nonexistent/notes.md", "--check"]) == 1


def test_a_differently_cased_heading_is_still_the_section():
    text = "# Notes\n\n## Known Issues\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_closing_hashes_and_indentation_still_mark_the_section():
    for heading in ("## Known issues ##", "   ## Known issues", "##  Known issues"):
        text = f"# Notes\n\n{heading}\n\n- Fixed in 4.0.1.\n"
        assert run(text, "--check") == 1, heading


def test_every_known_issues_section_is_checked():
    text = notes("\n\n") + "\n## Known issues\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1
    assert run(notes("\n\n") + "\n## Known issues\n\n- Open.\n", "--release") == 1


def test_a_top_level_heading_ends_the_section():
    text = "# Notes\n\n## Known issues\n\n# Appendix\n\nFixed in 4.0.1.\n"
    assert run(text, "--check") == 0


def test_a_setext_known_issues_heading_is_the_section():
    text = "Notes\n=====\n\nKnown issues\n------------\n\n- One (MIK-1).\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1
    assert run(text.replace("One", "Fixed in 4.0.1"), "--check") == 1


def test_a_setext_heading_ends_the_section_and_a_thematic_break_does_not():
    ends = "## Known issues\n\n- One.\n\nPerformance\n-----------\n\n4.0.1 later.\n"
    assert run(ends, "--check") == 0
    stays = "## Known issues\n\n---\n\n- Fixed in 4.0.1.\n"
    assert run(stays, "--check") == 1
    listed = "## Known issues\n\n- Fixed in 4.0.1.\n---\n"
    assert run(listed, "--check") == 1


def over_dashes(above):
    """A Known issues section with `above` directly over "---", then a 4.0.1 item."""
    return f"## Known issues\n\n{above}\n---\n\n- Fixed in 4.0.1.\n"


# Each row puts a non-heading over "---": the "---" is a thematic break, so the
# section goes on and its 4.0.1 item must be caught.
def test_an_atx_heading_over_dashes_does_not_end_the_section():
    assert run(over_dashes("### Outstanding"), "--check") == 1


def test_a_thematic_break_over_dashes_does_not_end_the_section():
    assert run(over_dashes("***"), "--check") == 1


def test_a_fence_opener_over_dashes_does_not_end_the_section():
    assert run(over_dashes("```text"), "--check") == 1


def test_a_fence_closer_over_dashes_does_not_end_the_section():
    assert run(over_dashes("```\nsample\n```"), "--check") == 1


def test_a_quote_over_dashes_does_not_end_the_section():
    assert run(over_dashes("> Quoted."), "--check") == 1


def test_a_list_continuation_over_dashes_does_not_end_the_section():
    assert run(over_dashes("- Item\n  continued"), "--check") == 1


def test_a_lazy_list_line_over_dashes_does_not_end_the_section():
    assert run(over_dashes("- Item\ncontinued"), "--check") == 1


def test_a_lazy_quote_line_over_dashes_does_not_end_the_section():
    assert run(over_dashes("> Quoted\ncontinued"), "--check") == 1


def test_list_content_after_a_blank_over_dashes_does_not_end_the_section():
    assert run(over_dashes("- Item\n\n  more"), "--check") == 1


def test_a_title_in_an_html_comment_does_not_end_the_section():
    text = "## Known issues\n\n<!--\n\nTitle\n---\n-->\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_a_setext_heading_after_a_blank_line_still_ends_the_section():
    # Same shape as the rows above with paragraph text over "---".
    assert run(over_dashes("- One.\n\nPerformance"), "--check") == 0


def test_a_setext_heading_in_any_other_form_stays_in_the_section():
    # Fail closed: a heading that is not one line after a blank, at column 0,
    # is read as section text, so its 4.0.1 item is still caught.
    assert run(over_dashes("- One.\n\nPerformance\nnumbers"), "--check") == 1


def test_a_fenced_sample_never_ends_the_section():
    for sample in ("key: value\n---", "## Not a heading", "Title\n====="):
        text = f"## Known issues\n\n```yaml\n{sample}\n```\n\n- Fixed in 4.0.1.\n"
        assert run(text, "--check") == 1, sample
        tilde = text.replace("```yaml", "~~~").replace("```", "~~~")
        assert run(tilde, "--check") == 1, sample


LATE = "\n\n## Known issues\n\n- Fixed in 4.0.1.\n"


# Each row puts something before the section that a fence or HTML block
# reading could mistake for an opener: the section must still be found.
def test_an_inline_triple_backtick_span_does_not_hide_the_section():
    assert run("```code``` is an inline span." + LATE, "--check") == 1


def test_a_nested_list_fence_does_not_hide_the_section():
    assert run("- ~~~\n  sample\n  ~~~" + LATE, "--check") == 1


def test_a_wrapped_setext_known_issues_title_is_the_section():
    assert run("Known\nissues\n---\n\n- Fixed in 4.0.1.\n", "--check") == 1


def test_a_title_in_a_pre_block_does_not_end_the_section():
    text = "## Known issues\n\n<pre>\n\nTitle\n---\n</pre>\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_a_reference_definition_over_dashes_does_not_end_the_section():
    assert run(over_dashes("- One.\n\n[details]: /url"), "--check") == 1


def test_every_tag_publish_path_runs_the_release_gate():
    # ci.yml's container publish and release.yml both fire on a v* tag; each
    # must refuse a non-empty section before it publishes.
    workflows = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
    ci = (workflows / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  release-criteria:\n", 1)[1].split("\n  capability-pins:\n", 1)[0]
    assert "check_known_issues.py --release" in job
    assert "check_known_issues.py --release" in (workflows / "release.yml").read_text(
        encoding="utf-8"
    )


if __name__ == "__main__":
    failed = 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"{failed} failed of {len(tests)}")
    sys.exit(1 if failed else 0)

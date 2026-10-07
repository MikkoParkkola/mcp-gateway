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


def test_another_products_version_is_not_a_later_release():
    for line in (
        "- Needs 14.0.1 of the toolchain.\n",
        "- Seen on Node 20.1.\n",
        "- Upgrading from 3.5.1 works.\n",
        "- Found in 4.0.0-rc.1.\n",
    ):
        assert run(notes("\n" + line), "--check") == 0, line


def test_any_later_4x_or_5x_release_fails_the_check():
    for later in ("4.0.2", "4.0.10", "4.1", "4.1.0", "5.0"):
        line = f"- Fixed in {later}.\n"
        assert run(notes("\n" + line), "--check") == 1, line


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


def test_a_known_issues_title_under_other_text_is_the_section():
    text = "Intro line.\nKnown issues\n---\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_dashes_in_a_div_block_do_not_end_the_section():
    text = "## Known issues\n\n<div>\n---\n</div>\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_an_escaped_bracket_reference_over_dashes_does_not_end_the_section():
    assert run(over_dashes("- One.\n\n[error \\[E1\\]]: /e1"), "--check") == 1


def test_an_indented_heading_in_a_list_fence_does_not_end_the_section():
    text = "## Known issues\n\n- ```\n  ## Example\n  ```\n\n- Fixed in 4.0.1.\n"
    assert run(text, "--check") == 1


def test_a_fence_after_an_inline_html_line_is_still_a_fence():
    text = (
        "## Known issues\n\n<span>Example output</span>\n```\n\n## Example\n```\n\n"
        "- Fixed in 4.0.1.\n"
    )
    assert run(text, "--check") == 1


def test_a_heading_with_extra_spaces_between_the_words_is_the_section():
    assert run("## Known  issues\n\n- Fixed in 4.0.1.\n", "--check") == 1


def test_a_heading_after_a_fence_inside_details_does_not_end_the_section():
    text = (
        "## Known issues\n\n<details>\n```\nx\n```\n## Example\n</details>\n\n"
        "- Fixed in 4.0.1.\n"
    )
    assert run(text, "--check") == 1


def test_any_html_in_the_section_keeps_it_open_to_the_end():
    text = (
        "## Known issues\n\n<details>\n```\nx\n```\n<!--\n\n## Example\n\n"
        "- Fixed in 4.0.1.\n"
    )
    assert run(text, "--check") == 1


def test_a_title_with_inline_markdown_is_the_section():
    for title in (
        "*Known issues*",
        "Known issues <!-- note -->",
        "[Known issues](#k)",
        "Known issues <!-- TODO: beta -> final -->",
        "[Known issues][ki]",
    ):
        assert run(f"## {title}\n\n- Fixed in 4.0.1.\n", "--check") == 1, title


def test_any_spelling_that_renders_known_issues_is_the_section():
    # Entities, markup inside a word, a reference label and a level-one setext
    # underline all render "Known issues"; each must still hold its items.
    for head in (
        "## [Known issues][known]\n",
        "## Known&nbsp;issues\n",
        "## Known issu&#101;s\n",
        "## Known iss*ue*s\n",
        "Known issues\n============\n",
    ):
        assert run(f"{head}\n- Open.\n", "--release", "--tag", "v4.0.0") == 1, head
        assert run(head, "--release", "--tag", "v4.0.0") == 0, head


def test_an_escaped_or_encoded_later_release_fails_the_check():
    for line in ("- Fixed in 4\\.0\\.1.\n", "- Fixed in 4.0.&#49;.\n", "- Fixed in 4.0.*1*.\n"):
        assert run(notes("\n" + line), "--check") == 1, line


def test_a_later_release_split_by_inline_html_or_link_markup_fails_the_check():
    for line in (
        "- Fixed in 4.0.<em>1</em>.\n",
        "- Fixed in 4.0.[1](https://example.com/next).\n",
        "- Fixed in [4.0.1][next].\n",
        "- See <https://example.com/v4.0.1>.\n",
    ):
        assert run(notes("\n" + line), "--check") == 1, line


def test_a_later_release_inside_literal_markup_fails_the_check():
    # Code spans, escaped links and undefined references render their markup,
    # so a version inside it is visible.
    for line in (
        "- See `[next](4.0.1)`.\n",
        "- See `<em>4.0.1</em>`.\n",
        "- See \\[next\\](4.0.1).\n",
        "- See [next][4.0.1].\n",
    ):
        assert run(notes("\n" + line), "--check") == 1, line


def test_a_later_release_on_a_wordy_wrapped_titles_first_line_fails_the_check():
    assert run("Known issues fixed in 4.0.1\ncontinued\n---\n", "--check") == 1


def test_an_empty_wrapped_setext_title_passes_at_a_tag():
    assert run("Known\nissues\n---\n", "--release", "--tag", "v4.0.0") == 0


def test_a_later_release_on_a_wrapped_titles_first_line_fails_the_check():
    assert run("Fixed in 4.0.1: Known\nissues\n---\n", "--check") == 1


def test_a_range_ending_in_a_later_release_fails_the_check():
    for line in ("- Seen 4.0.0-4.0.1.\n", "- Seen `4.0.0`-`4.0.1`.\n"):
        assert run(notes("\n" + line), "--check") == 1, line


def test_a_later_release_in_the_title_itself_fails_the_check():
    for head in ("## Known issues [4.0.1][next]\n", "## Known issues &lt;fixed in 4.0.1&gt;\n"):
        assert run(head, "--check") == 1, head


def test_a_level_one_or_formatted_setext_title_is_the_section():
    for head in ("# Known issues\n", "*Known issues*\n---\n"):
        assert run(f"{head}\n- Fixed in 4.0.1.\n", "--check") == 1, head


def test_build_metadata_of_this_release_is_not_a_later_release():
    assert run(notes("\n- Seen in 4.0.0+build-5.1.\n"), "--check") == 0


def test_a_numeric_build_of_this_release_is_not_a_later_release():
    assert run(notes("\n- Seen in 4.0.0+4.0.1.\n"), "--check") == 0


def test_two_code_spans_joined_by_a_plus_are_two_versions():
    assert run(notes("\n- Seen in `4.0.0`+`4.0.1`.\n"), "--check") == 1


def test_an_empty_section_under_a_quoted_tag_title_holds_at_a_tag():
    head = '## Known iss<span title="a>b">u</span>es\n'
    assert run(head, "--release", "--tag", "v4.0.0") == 0


def test_a_tag_inside_a_code_span_is_title_text():
    head = '## Known iss`<span title="a>webhook replay remains">`u`</span>`es\n'
    assert run(head, "--release", "--tag", "v4.0.0") == 1


def test_a_tag_inside_mixed_length_code_spans_is_title_text():
    head = '## Known iss`` `<span title="a>webhook replay remains">` ``u``</span>``es\n'
    assert run(head, "--release", "--tag", "v4.0.0") == 1


def test_a_comment_spanning_lines_does_not_hide_a_version():
    assert run(notes("\n- Fixed in 4.0.<!--\neditor note\n-->1.\n"), "--check") == 1


def test_a_setext_title_over_three_lines_is_the_section():
    text = "Known\nissues\nfor 4.0\n---\n\n- Open.\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1


def test_a_comment_opened_after_text_keeps_the_section_open():
    text = notes("\nEditorial note <!--\n## reminder\n-->\n\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_number_after_the_title_is_section_content():
    assert run("## Known issues \u2014 #3230\n", "--release", "--tag", "v4.0.0") == 1


def test_strikethrough_does_not_hide_a_version():
    for line in ("- Fixed in 4.0.~~1~~.", "- Fixed in 4.0.~1~."):
        assert run(notes(f"\n{line}\n"), "--check") == 1, line


def test_a_tilde_before_a_version_does_not_hide_it():
    for line in ("- Fixed in release~4.0.1.", "- Seen in 4.0.0-rc.1~4.0.1."):
        assert run(notes(f"\n{line}\n"), "--check") == 1, line


def test_a_title_paragraph_over_a_fence_opener_does_not_hide_the_fence():
    text = notes("\nKnown\nissues\n```\n---\n## x\n```\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_title_paragraph_over_a_comment_opener_does_not_hide_the_comment():
    text = notes("\nKnown\nissues\nmore\n<!--\n---\n## x\n-->\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_long_title_paragraph_over_a_fence_opener_does_not_hide_the_fence():
    text = notes("\nKnown\nissues\nmore\n```\n---\n# x\n```\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_title_paragraph_keeps_the_text_above_the_title():
    text = "# Notes\n\nFixed in 4.0.1:\nKnown\nissues\n---\n"
    assert run(text, "--check") == 1


def test_a_title_paragraph_with_a_closed_comment_is_the_section():
    text = "Known <!-- note -->\nissues\nfor 4.0\n---\n\n- Open.\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1


def test_a_title_paragraph_with_an_indented_continuation_is_the_section():
    text = "Known\n    issues\nfor 4.0\n---\n\n- Open.\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1


def test_a_fence_opener_read_as_a_title_line_still_opens_the_fence():
    text = notes("\nKnown issues\n```\n---\n## x\n```\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_comment_opener_read_as_a_title_line_still_opens_the_comment():
    text = notes("\nKnown issues\n<!--\n---\n## x\n-->\n- Fixed in 4.0.1.\n")
    assert run(text.replace("The 4.0.1 numbers come later.", "Later."), "--check") == 1


def test_a_list_item_over_a_thematic_break_is_section_content():
    text = "## Known issues\n\n- Known issues\n---\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1


def test_a_tag_spanning_lines_does_not_hide_a_version():
    assert run(notes('\n- Fixed in 4.0.<em\n  title="x">1</em>.\n'), "--check") == 1


def test_a_prerelease_to_later_release_range_fails_the_check():
    for line in ("- Affected: v4.0.0-rc.1-v4.0.1.", "- Affected: 4.0.0-rc.1-4.0.1."):
        assert run(notes(f"\n{line}\n"), "--check") == 1, line


def test_a_tab_indented_marker_continues_a_title_paragraph():
    text = "Known\n \t# issues\nfor 4.0\n---\n\n- Open.\n"
    assert run(text, "--release", "--tag", "v4.0.0") == 1


def test_an_atx_title_keeps_the_line_above_out():
    text = "# Notes\n\nSee 4.0.1 later.\n## Known issues\n\n## Performance\n"
    assert run(text, "--check") == 0
    assert run(text, "--release", "--tag", "v4.0.0") == 0


def test_a_version_inside_build_metadata_is_not_a_range_end():
    for line in ("- Seen in 4.0.0+build-4.0.1.", "- Seen in 4.0.0+build-v5.1."):
        assert run(notes(f"\n{line}\n"), "--check") == 0, line


def test_a_hyphen_range_to_a_later_release_fails_the_check():
    assert run(notes("\n- Seen in 4.0.0-4.0.1.\n"), "--check") == 1


def test_an_uppercase_v_later_release_fails_the_check():
    assert run(notes("\n- Fixed in V4.0.1.\n"), "--check") == 1


def test_a_quoted_angle_bracket_in_a_tag_does_not_hide_a_version():
    assert run(notes('\n- Fixed in 4.0.<em title="a>b">1</em>.\n'), "--check") == 1


def test_a_quoted_angle_bracket_in_a_tag_does_not_hide_the_title():
    head = '## Known iss<span title="a>b">u</span>es\n'
    assert run(f"{head}\n- Open.\n", "--release", "--tag", "v4.0.0") == 1


def test_an_unbalanced_quote_in_a_title_tag_still_starts_the_section():
    head = "## Known iss<span title='a>u</span>es\n"
    assert run(f"{head}\n- Open.\n", "--release", "--tag", "v4.0.0") == 1


def test_a_hyphen_joined_later_release_fails_the_check():
    assert run(notes("\n- Fixed in release-v4.0.1.\n"), "--check") == 1


def test_a_title_line_that_says_more_is_section_content():
    text = "## Known issues\n\n- Known issues remain; fixed in 4.0.1\n---\n"
    assert run(text, "--check") == 1


def test_an_annotated_setext_title_holds_its_section_at_a_tag():
    head = "Known issues <!-- note -->\n---\n"
    assert run(head, "--release", "--tag", "v4.0.0") == 0
    assert run(head + "\n- Open.\n", "--release", "--tag", "v4.0.0") == 1


def test_an_email_autolink_line_does_not_keep_the_section_open():
    text = "## Known issues\n\n<ops@example.com>\n\n## Performance\n\n4.0.1 later.\n"
    assert run(text, "--check") == 0


def test_an_autolink_line_does_not_keep_the_section_open():
    text = "## Known issues\n\n<https://example.com/x>\n\n## Performance\n\n4.0.1 later.\n"
    assert run(text, "--check") == 0


def test_html_inside_a_fence_does_not_keep_the_section_open():
    text = "## Known issues\n\n```html\n<div>\n```\n\n## Performance\n\n4.0.1 later.\n"
    assert run(text, "--check") == 0


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

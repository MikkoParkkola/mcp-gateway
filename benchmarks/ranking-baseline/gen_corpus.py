#!/usr/bin/env python3
"""Deterministically derive a held-out tool-discovery query corpus from
capabilities/*.yaml for MIK-3274.RANKING.3.

Every query is produced by a mechanical rule applied to the capability
inventory (name / description / tags) -- never by probing the ranker.
Re-running this script on an unchanged capabilities/ tree reproduces the
same corpus.json byte-for-byte (tool listing and rule order are both
sorted / deterministic).
"""
import glob
import json
import os
import sys

REPO = sys.argv[1] if len(sys.argv) > 1 else "."
CAP_DIR = os.path.join(REPO, "capabilities")


def load_tools():
    import yaml
    tools = []
    for path in sorted(glob.glob(os.path.join(CAP_DIR, "**", "*.yaml"), recursive=True)):
        if "/examples/" in path.replace(os.sep, "/"):
            continue
        with open(path) as f:
            try:
                data = yaml.safe_load(f)
            except Exception:
                continue
        if not isinstance(data, dict) or "name" not in data:
            continue
        tools.append({
            "name": data["name"],
            "description": (data.get("description") or "").strip(),
            "tags": list((data.get("metadata") or {}).get("tags") or []),
        })
    tools.sort(key=lambda t: t["name"])
    return tools


def transpose_typo(word: str) -> str:
    """Swap two adjacent interior letters to simulate a one-key-slip typo."""
    if len(word) < 4:
        return word
    mid = len(word) // 2
    chars = list(word)
    chars[mid], chars[mid + 1] = chars[mid + 1], chars[mid]
    return "".join(chars)


def build_corpus(tools):
    cases = []

    # Rule A: name_phrase -- tool name with underscores turned into spaces,
    # sampled every 4th tool (alphabetical) so the corpus doesn't just
    # restate all 119 names.
    name_phrase_tools = [t for i, t in enumerate(tools) if i % 4 == 0]
    for t in name_phrase_tools:
        cases.append({
            "id": f"name_phrase::{t['name']}",
            "query": t["name"].replace("_", " "),
            "derivation": "name_phrase",
            "derivation_detail": "tool name, underscores -> spaces (every 4th tool alphabetically)",
            "gold_tools": [t["name"]],
        })

    # Rule B: description_lead -- first 5 words of the description, the
    # phrasing a user would type after reading what the tool claims to do.
    # Sampled with a different stride/offset so it covers different tools
    # than rule A.
    desc_tools = [t for i, t in enumerate(tools) if i % 5 == 2 and t["description"]]
    for t in desc_tools:
        words = t["description"].split()[:5]
        query = " ".join(words).strip(".,-").lower()
        if not query:
            continue
        cases.append({
            "id": f"description_lead::{t['name']}",
            "query": query,
            "derivation": "description_lead",
            "derivation_detail": "first 5 words of metadata description, lowercased (tools at index%5==2)",
            "gold_tools": [t["name"]],
        })

    # Rule C: tag_query -- a single metadata tag used verbatim as the query.
    # Tags used by exactly one tool give an unambiguous gold; tags shared by
    # several tools are kept too, with every sharing tool as acceptable gold
    # -- this is real, data-derived ambiguity, not injected by hand.
    tag_to_tools = {}
    for t in tools:
        for tag in t["tags"]:
            tag_to_tools.setdefault(tag, []).append(t["name"])
    distinctive_tags = sorted(tag_to_tools.keys())[::3][:20]
    for tag in distinctive_tags:
        cases.append({
            "id": f"tag_query::{tag}",
            "query": tag,
            "derivation": "tag_query",
            "derivation_detail": "a metadata.tags entry typed verbatim (every 3rd tag alphabetically)",
            "gold_tools": sorted(tag_to_tools[tag]),
        })

    # Rule D: abbreviation -- short (<=4 char) alphabetic tags are exactly
    # the acronyms/abbreviations users type (tts, stt, ocr, uuid, pdf, waf, ...).
    abbrev_tags = sorted({tag for tag in tag_to_tools if tag.isalpha() and len(tag) <= 4})
    for tag in abbrev_tags[:15]:
        cases.append({
            "id": f"abbreviation::{tag}",
            "query": tag,
            "derivation": "abbreviation",
            "derivation_detail": "short (<=4 char) alphabetic metadata tag, i.e. an acronym a user would type",
            "gold_tools": sorted(tag_to_tools[tag]),
        })

    # Rule E: shared_prefix_ambiguous -- the leading underscore-segment of
    # the tool name, when >=3 tools share it. A user typing just the family
    # name ("gmail", "video") is a real word-boundary case: does the ranker
    # differentiate members of the family at all, or just return substring hits?
    prefix_to_tools = {}
    for t in tools:
        prefix = t["name"].split("_")[0]
        prefix_to_tools.setdefault(prefix, []).append(t["name"])
    shared_prefixes = sorted(p for p, ts in prefix_to_tools.items() if len(ts) >= 3)
    for prefix in shared_prefixes:
        cases.append({
            "id": f"shared_prefix_ambiguous::{prefix}",
            "query": prefix,
            "derivation": "shared_prefix_ambiguous",
            "derivation_detail": "leading name segment shared by >=3 tools, typed alone",
            "gold_tools": sorted(prefix_to_tools[prefix]),
        })

    # Rule F: typo -- one adjacent-letter transposition applied to the first
    # word of the tool name, sampled from a subset of rule A's tools. Since
    # step 1 established there is no edit-distance tolerance in the ranker,
    # this rule exists to measure that absence, not to exploit it.
    typo_tools = [t for i, t in enumerate(name_phrase_tools) if i % 2 == 0]
    for t in typo_tools:
        first_word = t["name"].split("_")[0]
        typo_word = transpose_typo(first_word)
        if typo_word == first_word:
            continue
        rest = t["name"].split("_")[1:]
        query = " ".join([typo_word] + rest)
        cases.append({
            "id": f"typo::{t['name']}",
            "query": query,
            "derivation": "typo",
            "derivation_detail": "first word of the name with two adjacent interior letters swapped",
            "gold_tools": [t["name"]],
        })

    return cases


def main():
    tools = load_tools()
    cases = build_corpus(tools)
    out = {
        "criterion": "MIK-3274.RANKING.3",
        "tool_inventory_size": len(tools),
        "corpus_size": len(cases),
        "derivation_note": (
            "Every query below is produced by a mechanical rule over "
            "capabilities/*.yaml (name / description / tags), applied with a "
            "fixed alphabetical stride so the sample is reproducible. No query "
            "was chosen by observing ranker output; see gen_corpus.py for the "
            "exact rule that produced each case (derivation/derivation_detail fields)."
        ),
        "cases": cases,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

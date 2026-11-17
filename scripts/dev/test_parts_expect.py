#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""`test_parts.py expect` and the refusals that keep it exact.

`expect` names, per part, every lib test the part's binary lists on one CI target: each test fn's effective cfg (its
own `#[cfg]`s, every enclosing module's, the `mod` declaration's, a file's inner `#![cfg]`) evaluated against the
target's `rustc --print cfg` facts with every feature on, generated tests named from their invocation, raw
identifiers kept. The union job compares each part binary's `--list` with these sets exactly.

`refusals` turns away, at the source, every shape `expect` cannot name: a cfg on a name no source knows, a generator
of another shape, `include!` of Rust source, an item-level macro outside the allowlist, an unexpected attribute at
module position, anything that rebinds `test`, `tokio` or `thread_local`, and a test no CI configuration compiles.

Called through test_parts.py, which passes itself as `tp` (the walk lives there)."""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

CI_TABLE = Path("scripts/dev/test-parts-ci.tsv")


class Undecidable(Exception):
    """A predicate on a name no fact source knows."""


def parse(expr: str):
    """A cfg predicate as a tree: ("all"|"any"|"not", [operands]), ("kv", name, value) or ("atom", name)."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*|[(),=]', expr)
    pos = 0

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def one():
        name = take()
        if pos < len(tokens) and tokens[pos] == "(":
            take()
            ops = []
            while tokens[pos] != ")":
                ops.append(one())
                if tokens[pos] == ",":
                    take()
            take()
            return (name, ops)
        if pos < len(tokens) and tokens[pos] == "=":
            take()
            return ("kv", name, take()[1:-1])
        return ("atom", name)

    tree = one()
    if pos != len(tokens):
        raise Undecidable(f"cannot parse cfg({expr})")
    return tree


class Facts:
    """What is true on one configuration: the target's printed cfgs, `test`, the enabled features, the part."""

    def __init__(self, print_cfg: str, features: set[str], known: set[str], part: int | None, extra=()):
        self.atoms, self.pairs = {"test", *extra}, set()
        for line in print_cfg.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                self.pairs.add((k.strip(), v.strip().strip('"')))
            elif line:
                self.atoms.add(line)
        self.keys = {k for k, _ in self.pairs} | {"feature"}
        self.features = features
        self.known = known  # names a source declares but that are false here: custom cfgs, tp names
        self.part = part

    def holds(self, tree) -> bool:
        kind = tree[0]
        if kind == "kv":
            _, name, value = tree
            if name == "feature":
                return value in self.features
            if name not in self.keys and name not in self.known:
                raise Undecidable(f"{name} = {value!r}")
            return (name, value) in self.pairs
        if kind == "atom":
            name = tree[1]
            if name in self.atoms:
                return True
            m = re.fullmatch(r"tp(\d+)", name)
            if m:
                return self.part is None or int(m.group(1)) == self.part
            if name == "tp_partial":
                return False
            if name in self.known:
                return False
            raise Undecidable(name)
        ops = [self.holds(o) for o in tree[1]]
        if kind == "all":
            return all(ops)
        if kind == "any":
            return any(ops)
        if kind == "not" and len(ops) == 1:
            return not ops[0]
        raise Undecidable(f"{kind}(..)")


# rustc's well-known cfg names no CI target prints but code may test: false on every CI build.
WELL_KNOWN = {"doc", "doctest", "miri", "overflow_checks", "proc_macro", "ub_checks", "fmt_debug", "contract_checks",
              "target_has_atomic", "target_feature", "sanitize", "target_abi", "relocation_model",
              # what one CI target or another prints, so a name another target sets reads false here
              "unix", "windows", "debug_assertions", "panic", "target_arch", "target_endian", "target_env",
              "target_family", "target_os", "target_pointer_width", "target_vendor"}


def manifest(root: Path) -> dict:
    return tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))


def custom_cfgs(cargo: dict) -> set[str]:
    """The cfg names Cargo.toml declares through `unexpected_cfgs`' check-cfg list: false unless a build sets them."""
    lint = cargo.get("lints", {}).get("rust", {}).get("unexpected_cfgs", {})
    names = set()
    for entry in lint.get("check-cfg", []) if isinstance(lint, dict) else []:
        names |= set(re.findall(r"cfg\(\s*([A-Za-z_]\w*)", entry))
    return names


def feature_set(cargo: dict, flags: str) -> set[str]:
    """The features a cargo invocation enables, from its flags: `all` or `--all-features`; otherwise the default list
    unless `--no-default-features`, plus each `--features` name, expanded through feature-to-feature edges."""
    table = cargo.get("features", {})
    words = flags.replace(",", " ").split()
    if flags == "all" or "--all-features" in words:
        return set(table)
    pending = [] if "--no-default-features" in words else ["default"]
    pending += [w for i, w in enumerate(words) if i and words[i - 1] == "--features"]
    out: set[str] = set()
    while pending:
        f = pending.pop()
        if f in table and f not in out:
            out.add(f)
            pending += [x for x in table[f] if "/" not in x and not x.startswith("dep:")]
    return out


def known_names(cargo: dict, print_cfgs: list[str]) -> set[str]:
    """Names some source declares: false where a configuration does not set them, never undecidable."""
    names = custom_cfgs(cargo) | WELL_KNOWN
    for text in print_cfgs:
        names |= {line.split("=", 1)[0].strip() for line in text.splitlines() if line.strip()}
    return names


def chain(crate, ix):
    """The node and its ancestors, innermost first."""
    while ix is not None:
        yield ix
        ix = crate.nodes[ix].parent


def effective_cfgs(crate, ix: int) -> list[str]:
    """Every cfg predicate that gates node `ix`: its own and each ancestor's, plus each file's inner `#![cfg]` along
    the chain (a file's top-level items' parent is the `mod` declaration that mounted the file)."""
    preds, files = [], set()
    for k in chain(crate, ix):
        node = crate.nodes[k]
        preds += node.item.cfgs
        files.add(node.rel)
    for rel in files:
        preds += crate.files[rel].inner_cfgs
    return preds


def part_of(crate, ix) -> int | None:
    for k in chain(crate, ix):
        if crate.nodes[k].item.tags:
            return crate.nodes[k].item.tags[0][0]
    return None


def raw_path(crate, ix: int) -> str:
    return "::".join(crate.nodes[k].item.raw_name or crate.nodes[k].item.name for k in reversed(list(chain(crate, ix))))


def compiled(preds: list[str], facts: Facts) -> bool:
    return all(facts.holds(parse(p)) for p in preds)


def expect(tp, root: Path, target_cfg: str) -> dict[int, list[str]]:
    crate = tp.walk_crate(root)
    cargo = manifest(root)
    known = known_names(cargo, [target_cfg])
    features = feature_set(cargo, "all")
    out: dict[int, set[str]] = {}
    for ix, node in enumerate(crate.nodes):
        part = part_of(crate, ix)
        if part is not None and node.item.is_test_fn and compiled(effective_cfgs(crate, ix),
                                                                   Facts(target_cfg, features, known, part)):
            out.setdefault(part, set()).add(raw_path(crate, ix))
    for name, prefix, part, preds in generated(crate):
        if compiled(preds, Facts(target_cfg, features, known, part)):
            out.setdefault(part, set()).add(f"{prefix}::{name}" if prefix else name)
    return {k: sorted(v) for k, v in sorted(out.items())}


def local_nodes(crate) -> dict[tuple[str, int], int]:
    """(file, item index in that file's walk) -> crate node index (walk_crate adds a file's items in order)."""
    seen: dict[str, int] = {}
    out = {}
    for ix, node in enumerate(crate.nodes):
        k = seen.get(node.rel, 0)
        out[(node.rel, k)] = ix
        seen[node.rel] = k + 1
    return out


def call_owner(crate, local, rel: str, parent: int | None) -> int | None:
    """The node a call sits in: its enclosing inline module, or the `mod` declaration that mounted its file."""
    return local[(rel, parent)] if parent is not None else crate.owners.get(rel)


def generated(crate):
    """(test name, module path, part, gating predicates) for every item-level call of a local test generator."""
    local = local_nodes(crate)
    for rel, walk in crate.files.items():
        for macro, _line, parent, cfgs, first, written in walk.calls:
            if macro not in walk.generators or "::" in written or not first:
                continue
            owner = call_owner(crate, local, rel, parent)
            if owner is None:
                continue
            part = part_of(crate, owner)
            if part is None:
                continue
            preds = effective_cfgs(crate, owner) + list(cfgs)
            if parent is None:
                preds += walk.inner_cfgs
            yield first, raw_path(crate, owner), part, preds


MODULE_ATTRS = {"cfg", "cfg_attr", "path", "doc", "allow", "expect", "warn", "deny"}
BINDS_TEST = re.compile(r"(?:\bas\s+|::\s*|\buse\s+)(?:r#)?(test|tokio)\s*[;,}]")
BINDS_THREAD_LOCAL = re.compile(r"(?:\bas\s+|::\s*|\buse\s+)thread_local\s*[;,}]")


def shape_problem(body: str) -> str | None:
    """Why a generator's body is not one test fn named by its first fragment with no cfg, or None."""
    first = re.search(r"\(\s*\$(\w+)\s*:", body)
    fns = re.findall(r"\bfn\s+(\$?\w+)", body)
    tests = re.findall(r"#\s*\[\s*(?:tokio\s*::\s*)?test\b", body)
    if first is None or len(fns) != 1 or len(tests) != 1:
        return "a test generator must define exactly one test fn"
    if fns[0] != f"${first.group(1)}":
        return f"the generated fn must be named by the first fragment (${first.group(1)}), not {fns[0]}"
    if re.search(r"#\s*\[\s*cfg(?:_attr)?\s*\(", body):
        return "a cfg inside a test generator's body is not supported; put it on the invocation"
    return None


def renamed_tokio(cargo: dict) -> bool:
    tables = [cargo.get(k, {}) for k in ("dependencies", "dev-dependencies")]
    tables += [t.get(k, {}) for t in cargo.get("target", {}).values() for k in ("dependencies", "dev-dependencies")]
    return any(isinstance(t.get("tokio"), dict) and t["tokio"].get("package", "tokio") != "tokio" for t in tables)


def refusals(tp, root: Path, configs) -> list:
    """Findings for every shape `expect` cannot name. `configs`: [(rustc --print cfg text, "all" | "default"), ..]."""
    crate = tp.walk_crate(root)
    cargo = manifest(root)
    known = known_names(cargo, [c[0] for c in configs])
    local = local_nodes(crate)
    nowhere = {r[1] for r in ci_rows(root) if r[0] == "nowhere"}
    out = []

    def add(code, rel, line, msg):
        out.append(tp.Finding(code, rel, line, msg))

    def judge(rel, line, part, preds, what):
        """cfg-undecidable once, else test-nowhere when no CI configuration compiles it."""
        seen = []
        for text, spec, *extra in configs:
            try:
                seen.append(compiled(preds, Facts(text, feature_set(cargo, spec), known, part, *extra)))
            except Undecidable as e:
                add("cfg-undecidable", rel, line, f"{what}: cfg on {e} is set by no target, feature or check-cfg entry")
                return
        if not any(seen) and what not in nowhere:
            add("test-nowhere", rel, line, f"{what} compiles in no CI configuration, so it runs nowhere")

    for ix, node in enumerate(crate.nodes):
        part = part_of(crate, ix)
        if part is None:
            continue
        it = node.item
        if it.is_test_fn:
            judge(node.rel, it.line, part, effective_cfgs(crate, ix), raw_path(crate, ix))
        if it.kind == "mod":
            if it.name in ("test", "tokio"):
                add("test-import", node.rel, it.line, f"a module named {it.name} rebinds a test attribute's path")
            odd = [p for p in it.attr_paths if p not in MODULE_ATTRS]
            if odd:
                add("attr-position", node.rel, it.line, f"{', '.join(odd)} on a lib test module is not supported")
    for name, prefix, part, preds in generated(crate):
        judge("", 0, part, preds, f"{prefix}::{name}")
    for rel, walk in crate.files.items():
        for macro, line, parent, _cfgs, _first, written in walk.calls:
            owner = call_owner(crate, local, rel, parent)
            if owner is None or part_of(crate, owner) is None:
                continue
            if macro == "include":
                add("include-source", rel, line, "include! of Rust source in lib test code: the walk cannot follow it")
            elif macro in walk.generators and "::" not in written:
                problem = shape_problem(walk.gen_bodies.get(macro, ""))
                if problem:
                    add("generator-shape", rel, line, problem)
            elif written not in ("thread_local", "std::thread_local"):
                add("item-macro", rel, line, f"{written}! at item level in lib test code may make tests expect cannot name")
        for text, line, parent in walk.bindings:
            owner = call_owner(crate, local, rel, parent)
            if owner is None or part_of(crate, owner) is None:
                continue
            if BINDS_TEST.search(text) or re.search(r"extern\s+crate\s+\w+\s+as\s+(test|tokio)\b", text):
                add("test-import", rel, line, "this rebinds `test` or `tokio`, which the test attributes resolve through")
            if BINDS_THREAD_LOCAL.search(text):
                add("item-macro", rel, line, "this rebinds thread_local, which the item-macro allowlist trusts")
        if "thread_local" in walk.gen_bodies:
            add("item-macro", rel, 1, "a local macro_rules! thread_local shadows the allowlisted std macro")
    if renamed_tokio(cargo):
        add("test-import", "Cargo.toml", 1, "a dependency keyed tokio is another crate, so #[tokio::test] is not tokio's")
    return out


def ci_rows(root: Path) -> list[list[str]]:
    """The CI table's records (kind first), or none when the tree has no table."""
    path = root / CI_TABLE
    if not path.is_file():
        return []
    return [line.split("\t") for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


def print_cfg(target: str) -> str:
    """`rustc --print cfg` for `target` from the toolchain on PATH (CI's pinned one in the jobs)."""
    return subprocess.run(["rustc", "--print", "cfg", "--target", target], check=True, capture_output=True,
                          text=True).stdout


def ci_configs(root: Path) -> list[tuple[str, str, set[str]]]:
    """(print-cfg text, cargo feature flags, custom cfgs set) for each CI configuration the table records."""
    texts: dict[str, str] = {}
    out = []
    for row in ci_rows(root):
        if row[0] != "config":
            continue
        target, flags = row[1], row[2] if len(row) > 2 else ""
        extra = {c for c in (row[3] if len(row) > 3 else "").split(",") if c.strip()}
        if target not in texts:  # one compiler call per target, not per row
            texts[target] = print_cfg(target)
        out.append((texts[target], flags or "--features default", extra))
    return out


def write_expect(tp, root: Path, target: str, outdir: Path) -> dict[int, int]:
    """Write `pK.txt` (one expected name a line) for each part, for the union job; part -> count."""
    sets = expect(tp, root, print_cfg(target))
    outdir.mkdir(parents=True, exist_ok=True)
    for part, names in sets.items():
        (outdir / f"p{part}.txt").write_text("".join(f"{n}\n" for n in names), encoding="utf-8")
    return {k: len(v) for k, v in sets.items()}

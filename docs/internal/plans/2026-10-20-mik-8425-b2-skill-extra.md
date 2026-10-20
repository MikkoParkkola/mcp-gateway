# MIK-8425 B2: `ImportedSkill.extra` becomes `serde_json::Value`

Status: plan for review, 2026-10-20. Refs MIK-8425. Lead ruling 2026-10-20:
approved for 4.0.0 as its own PR, with the behaviour change documented in
`upgrading.d` and the changelog, and a test for it.

## Problem

`mcp_gateway::skills::ImportedSkill` is public (re-exported from
`skills`), and its field `pub extra: BTreeMap<String, crate::yaml::Value>`
is serde_yaml's own tree type. It is the only YAML type in the crate's
public API: every other `pub` signature and field was checked. Swapping the
YAML backend after 4.0.0 (MIG.2) would change this field's type, which is a
semver break. 4.0.0 is the window, so the type changes now, while the backend
is still serde_yaml.

## What users see today

- Frontmatter is parsed into the adapter tree. Every top-level key that is a
  string and not one of the 7 reserved keys goes into `extra` verbatim.
- The skill registry stores skills as JSON (`~/.mcp-gateway/skills.json`,
  `serde_json::to_vec_pretty`). So the form a user or tool has always seen
  on disk is serde_yaml's tree serialized through serde_json:
  - a tagged node `!t v` is written as the one-entry map `{"!t": v}`;
  - integer, boolean and finite float keys are written as strings;
  - a key that is null, a sequence, a mapping or tagged fails `save` with
    "key must be a string", so such a skill cannot be registered;
  - a non-finite float (`.inf`, `-.inf`, `.nan`) is written as `null`.

Probed on Spark on 2026-10-20 (serde_yaml 0.9.34, serde_json 1.0.151, a
throwaway test, not committed). `serde_json::to_value` and `to_string` of
the serde_yaml tree gave:
- `!custom {a: 1}` as `{"!custom":{"a":1}}`;
- keys `1`, `true` and `1.5` as `"1"`, `"true"` and `"1.5"`;
- keys `[a]`, `~`, `{k: v}` and `!t k` as `Err("key must be a string")`;
- key `.inf` as `Err("float key must be finite")`;
- `[.inf, -.inf, .nan]` as `[null,null,null]`;
- the u64 maximum and i64 minimum unchanged;
- `{1: a, "1": b}` as `{"1":"b"}` (`to_string` writes both keys, and reading
  it back keeps the last).

## Design

`extra` becomes `BTreeMap<String, serde_json::Value>`. The conversion is
one crate-private function in the adapter,
`pub(crate) fn to_json(value: &Value) -> serde_json::Value` in `src/yaml.rs`,
with these rules, chosen so that **the JSON form in `skills.json` stays what
it was**:

1. null, bool and string map to themselves.
2. Integers map to JSON integers over the full `i64` and `u64` range. Finite
   floats map to JSON numbers. Non-finite floats map to `null`.
3. A sequence maps element by element.
4. A tagged node `!t v` maps to `{"!t": to_json(v)}`. The tag is kept as a
   key, which is the on-disk form today, not as a YAML tag.
5. A mapping maps entry by entry:
   - a string key is kept;
   - an integer, boolean or finite float key becomes its string form, as
     serde_json writes it today;
   - an entry whose key is null, a non-finite float, a sequence, a mapping
     or tagged is dropped;
   - if two keys end up the same string (`1:` and `"1":`), the later one in
     the document wins, as reading the old JSON back did.

`parse_skill_md` keeps everything else: the whole frontmatter is still
parsed through the adapter, with the same reserved keys and errors. Each
`extra` value is passed through `to_json`.

MIG.2 contract: `to_json` is the only conversion. MIG.2 re-implements it over
its own tree, and the tests below are its parity fixtures.

Not chosen: dropping tags (`!t v` to `v`). That would change what
`skills.json` holds for a skill imported after the upgrade, compared with
the same skill imported before it. Not chosen: `serde_json::to_value(&v)`
with an error on any failure. It ties the form to serde_yaml's `Serialize`
impl, which MIG.2 removes, and it keeps the save failure.

## Behaviour change (documented in `upgrading.d/8425.md` and `changelog.d/8425.changed.md`)

- **Rust API users:** `ImportedSkill.extra` values are `serde_json::Value`.
  A YAML tag is no longer a `Tagged` value: it is the key of a one-entry
  map. A non-string key is no longer a YAML key: it is a string, or the
  entry is gone (rule 5).
- **CLI and registry users:** a skill whose frontmatter has a null, sequence,
  mapping or tagged key inside an extra field can now be registered. That
  entry is dropped; before, `save` failed. All other skills give the same
  `skills.json` bytes as before.
- `skills.json` files written by earlier versions load unchanged.

## Tests (red first: they do not compile against the old field type)

In `src/skills/parser.rs` tests (639 lines, about 60 added):
- **E1, type and nesting:** `metadata: {openclaw: {category: productivity}}`
  gives `extra["metadata"] == json!({"openclaw": {"category": "productivity"}})`,
  bound as `&BTreeMap<String, serde_json::Value>`.
- **E2, tags:** `x: !custom {a: 1}` and `s: [!t 1, plain]` give
  `{"!custom": {"a": 1}}` and `[{"!t": 1}, "plain"]`.
- **E3, keys:** `m: {1: one, true: t, 1.5: f, two: 2, [a]: z, ~: n, {k: v}: w, !t k: x}`
  gives `{"1": "one", "true": "t", "1.5": "f", "two": 2}`.
- **E4, numbers:** `f: [.inf, -.inf, .nan, 1.5, 18446744073709551615, -9223372036854775808]`
  gives `[null, null, null, 1.5, 18446744073709551615, -9223372036854775808]`.
- **E5, duplicate after stringifying:** `m: {1: a, "1": b}` gives `{"1": "b"}`.

In `src/skills/registry.rs` tests:
- **E6, old registry:** a `skills.json` literal as an earlier version wrote
  it, with `{"!custom": {...}}` and string-ified keys in `extra`, loads, and
  `save` then `load` gives an equal registry.
- **E7, newly registrable:** a skill with a sequence key inside an extra
  field now saves and loads, with that entry absent.

Parity check of the expected literals (run once on Spark in the red phase, a
throwaway test not committed): for E2, E3 without its dropped keys, and E4,
`serde_json::to_value` of the serde_yaml tree equals the literal. That shows
the on-disk form is unchanged.

## Files (about 6)

`src/yaml.rs`, `src/skills/parser.rs`, `src/skills/registry.rs` (tests
only), `upgrading.d/8425.md`, `changelog.d/8425.changed.md`, and this plan.
No new dependency (`serde_json` is already one). No new `pub` item.
`to_json` is `pub(crate)`.

## Process

- Two seats (gpt and grok) review this plan.
- muse writes the tests (red), then the code, with shell disabled.
- Spark runs the tests, clippy on both feature sets, and the gate.
- The seats review the code. The gap-finder runs, then a brief goes to the
  lead.

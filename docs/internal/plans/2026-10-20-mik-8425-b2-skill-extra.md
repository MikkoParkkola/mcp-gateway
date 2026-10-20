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
`pub(crate) fn to_json(value: &Value) -> serde_json::Value` in `src/yaml.rs`.
Its rules are chosen so that **`skills.json` holds the same JSON values as
before, compared after parsing**:

1. null, bool and string map to themselves.
2. Numbers keep their YAML kind:
   - an integer stays a JSON integer, over the full `i64` and `u64` range;
   - a finite float stays a JSON float (`serde_json::Number::from_f64`), so
     `1.0` is still `1.0` and not `1`;
   - a non-finite float maps to `null`.
3. A sequence maps element by element.
4. A tagged node `!t v` maps to `{"!t": to_json(v)}`. The tag is kept as a
   key, which is the on-disk form today, not as a YAML tag. Afterwards it
   cannot be told apart from a one-entry map whose key is `"!t"`.
5. A mapping maps entry by entry:
   - a string key is kept;
   - a boolean key becomes `"true"` or `"false"`;
   - an integer key becomes its decimal string (`1` becomes `"1"`);
   - a finite float key becomes serde_json's float text, which is ryu's
     (`1.0` becomes `"1.0"`, `1e3` becomes `"1000.0"`, `-0.0` becomes
     `"-0.0"`). So `1:` and `1.0:` stay two keys;
   - an entry whose key is null, a non-finite float, a sequence, a mapping
     or tagged is dropped;
   - if two keys end up as the same string (`1:` and `"1":`, in either
     order), the later one in the document wins, as reading the old JSON
     back did. Keys that are identical in the YAML are still refused by the
     parser, as today.

`parse_skill_md` keeps everything else: the whole frontmatter is still
parsed through the adapter, with the same reserved keys and errors. Each
`extra` value is passed through `to_json`.

**Deserializing `ImportedSkill` also goes through the tree.** `extra` gets
`#[serde(default, deserialize_with = ...)]`, through a private function in
`parser.rs`. It reads the map as `BTreeMap<String, crate::yaml::Value>` from
any deserializer and passes each value through `to_json`. Two things follow:
- the registry's JSON load cannot meet serde_json's `raw_value` magic key
  (`$serde_json::private::RawValue`). The crate enables that feature, and
  with it a derived `serde_json::Value` would turn such a map into its raw
  content;
- a caller who deserializes `ImportedSkill` from YAML gets the same rules as
  `parse_skill_md`.

Serializing is the derived `serde_json::Value` serialization.

MIG.2 contract: `to_json` is the only conversion. MIG.2 re-implements it over
its own tree, and the tests below are its parity fixtures. They go through
`parse_skill_md` and registry load, which MIG.2 keeps. No `cfg(test)` code
goes into `src/yaml.rs`, because integration tests compile that file through
`#[path]`.

Not chosen:
- Dropping tags (`!t v` to `v`). That would change what `skills.json` holds
  for a skill imported after the upgrade, compared with the same skill
  imported before it.
- `serde_json::to_value(&v)`, with an error on any failure. It ties the form
  to serde_yaml's `Serialize` impl, which MIG.2 removes, and it keeps the
  save failure.
- Enabling serde_json's `preserve_order`. It is a crate-wide change to every
  JSON map.

## Behaviour change (documented in `upgrading.d/8425.md` and `changelog.d/8425.changed.md`)

- **Rust API users:** `ImportedSkill.extra` values are `serde_json::Value`.
  - A YAML tag is no longer a `Tagged` value: it is the key of a one-entry
    map, the same as a map keyed `"!t"`.
  - A non-string key is no longer a YAML key: it is a string, or the entry
    is gone (rule 5).
  - This field type changes in 4.0.0 as its own change. It is not a
    leftover of the later backend swap.
- **CLI and registry users (a behaviour fix):** a skill whose frontmatter
  has a null, non-finite float, sequence, mapping or tagged key inside an
  extra field can now be registered, with that entry dropped. Before, `save`
  failed with "key must be a string".
- **`skills.json`:**
  - it holds the same JSON values as before, compared after parsing;
  - two textual differences: keys inside an `extra` value are now written
    in sorted order, where before they kept document order, and two keys
    that stringify the same are written once, where before both were
    written and the last was kept on read;
  - files written by earlier versions load with the same values.

## Tests (red first: they do not compile against the old field type)

In `src/skills/parser.rs` tests (639 lines, about 80 added):
- **E1, type and nesting:** `metadata: {openclaw: {category: productivity}}`
  gives `extra["metadata"] == json!({"openclaw": {"category": "productivity"}})`,
  bound as `&BTreeMap<String, serde_json::Value>`.
- **E2, tags:** `x: !custom {a: 1}` and `s: [!t 1, plain]` give
  `{"!custom": {"a": 1}}` and `[{"!t": 1}, "plain"]`.
- **E3, keys:** `m: {1: one, true: t, 1.5: f, 1.0: g, 1e3: h, -0.0: z0, two: 2, [a]: z, ~: n, {k: v}: w, !t k: x, .inf: i}`
  gives `{"1": "one", "true": "t", "1.5": "f", "1.0": "g", "1000.0": "h", "-0.0": "z0", "two": 2}`.
- **E4, numbers:** `f: [.inf, -.inf, .nan, 1.5, 1.0, 18446744073709551615, -9223372036854775808]`
  gives `[null, null, null, 1.5, 1.0, 18446744073709551615, -9223372036854775808]`,
  with `1.0` asserted to be a float (`is_f64`).
- **E5, duplicates after stringifying, both orders:** `m: {1: a, "1": b}`
  gives `{"1": "b"}`, and `m: {"1": a, 1: b}` gives `{"1": "b"}`. A YAML
  map with the same key twice is still refused.
- **E8, deserializing `ImportedSkill`:**
  - from JSON, an `extra` value `{"$serde_json::private::RawValue": "0"}`
    stays that one-entry map;
  - from YAML (`crate::yaml::from_str::<ImportedSkill>`), `x: !t 1` in
    `extra` gives `{"!t": 1}`.

In `src/skills/registry.rs` tests:
- **E6, old registry:**
  - the fixture is a `skills.json` literal that the pre-change code wrote,
    dumped by `SkillRegistry::save` on Spark in the red phase from a skill
    with tagged values, stringified keys, document-ordered nested keys and
    a float;
  - right after `load`, `extra` holds the expected values;
  - `save` then `load` gives an equal registry;
  - the saved text equals the fixture after JSON parsing.
- **E7, newly registrable:** a skill with a sequence key inside an extra
  field now saves and loads, with that entry absent.

Parity check of the expected literals, run once on Spark in the red phase
as a throwaway test that is not committed: for E2, E3 without its dropped
keys, E4 and E5, `serde_json::to_value` of the serde_yaml tree equals the
literal. That shows the JSON values are unchanged.

## Files (about 6)

`src/yaml.rs`, `src/skills/parser.rs`, `src/skills/registry.rs` (tests
only), `upgrading.d/8425.md`, `changelog.d/8425.changed.md`, and this plan.
No new dependency (`serde_json` is already one). No new `pub` item.
`to_json` is `pub(crate)`.

Review folds, 2026-10-20 (gpt SHIP-WITH-FIXES gpt-20261020T014449Z-19710,
grok SHIP-WITH-FIXES grok-20261020T014450Z-19787):
- `extra` deserializes through the tree, which closes the `raw_value`
  magic-key change;
- "same bytes" became "same values after parsing", with the order and
  duplicate differences stated;
- number forms are pinned, `1.0` against `1`;
- the E3 and E5 fixtures are extended;
- E6 uses a real pre-change dump and asserts right after load;
- E8 was added;
- tags are documented as indistinguishable from a `"!t"`-keyed map.

Declined: converter-level fixtures on `to_json` itself. `src/yaml.rs` takes
no `cfg(test)` code, and the adapter's integration test is MIG.2 scope. The
parser and registry tests reach `to_json` on every rule.

## Process

- Two seats (gpt and grok) review this plan.
- muse writes the tests (red), then the code, with shell disabled.
- Spark runs the tests, clippy on both feature sets, and the gate.
- The seats review the code. The gap-finder runs, then a brief goes to the
  lead.

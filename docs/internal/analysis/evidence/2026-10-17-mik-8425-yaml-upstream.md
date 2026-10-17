# MIK-8425 upstream evidence (read 2026-10-17)

Excerpts captured by the MIK-8425 lane for the YAML parser reassessment and
migration design. Each block names its source. All were read 2026-10-17 UTC.

## crates.io registry: latest version, publish date, license, normal dependencies

Source: https://crates.io/api/v1/crates/<name> and /api/v1/crates/<name>/<version>/dependencies (`?` marks an optional dependency).

```
serde_yaml | latest=0.9.34+deprecated | released=2024-03-25T00:50:19.759577Z | license=MIT OR Apache-2.0 | recent_dl=97431655 | repo=https://github.com/dtolnay/serde-yaml | normal_deps=indexmap,itoa,ryu,serde,unsafe-libyaml
unsafe-libyaml | latest=0.2.11 | released=2024-03-17T05:44:18.590756Z | license=MIT | recent_dl=79692251 | repo=https://github.com/dtolnay/unsafe-libyaml | normal_deps=
figment | latest=0.10.19 | released=2024-05-17T02:54:57.543501Z | license=MIT OR Apache-2.0 | recent_dl=12483825 | repo=https://github.com/SergioBenitez/Figment | normal_deps=atomic,serde,uncased,parking_lot?,pear?,serde_json?,serde_yaml?,tempfile?,toml?
serde_yaml_ng | latest=0.10.0 | released=2024-05-26T19:57:45.710414Z | license=MIT | recent_dl=10788216 | repo=https://github.com/acatton/serde-yaml-ng | normal_deps=indexmap,itoa,ryu,serde,unsafe-libyaml
serde_norway | latest=0.9.42 | released=2024-12-21T04:28:45.739429Z | license=MIT OR Apache-2.0 | recent_dl=7211833 | repo=https://github.com/cafkafk/serde-yaml | normal_deps=indexmap,itoa,ryu,serde,unsafe-libyaml-norway
serde_yml | latest=0.0.13 | released=2026-05-27T22:51:08.150617Z | license=MIT OR Apache-2.0 | recent_dl=5228139 | repo=https://github.com/sebastienrousseau/serde_yml | normal_deps=noyalib,serde
saphyr | latest=0.2.2 | released=2026-10-15T07:32:55.769671Z | license=MIT OR Apache-2.0 | recent_dl=951401 | repo=https://github.com/saphyr-rs/saphyr | normal_deps=hashlink,ordered-float,saphyr-parser,thiserror,encoding_rs?
saphyr-parser | latest=0.2.2 | released=2026-10-15T07:32:49.846996Z | license=MIT OR Apache-2.0 | recent_dl=5158796 | repo=https://github.com/saphyr-rs/saphyr | normal_deps=arraydeque,thiserror
serde-saphyr | latest=2.0.0 | released=2026-10-13T15:11:53.735115Z | license=MIT OR Apache-2.0 | recent_dl=8281672 | repo=https://github.com/bourumir-wyngs/serde-saphyr | normal_deps=serde_core,annotate-snippets?,base64?,encoding_rs_io?,figment?,figment2?,garde?,granit-parser?,miette?,nohash-hasher?,num-traits?,serde?,smallvec?,validator?,zmij?
noyalib | latest=0.0.58 | released=2026-10-15T23:12:25.317176Z | license=MIT OR Apache-2.0 | recent_dl=771246 | repo=https://github.com/sebastienrousseau/noyalib | normal_deps=hashbrown,indexmap,libm,memchr,rustc-hash,serde_core,smallvec,arbitrary?,ariadne?,bytes?,figment?,garde?,itoa?,jsonschema?,miette?,rayon?,rustix?,ryu?,schemars?,serde-saphyr?,serde_ignored?,serde_json?,sval?,tokio?,tokio-util?,validator?
yaml-rust2 | latest=0.13.0 | released=2026-09-11T00:00:22.447567Z | license=MIT OR Apache-2.0 | recent_dl=18960389 | repo=https://github.com/Ethiraric/yaml-rust2 | normal_deps=arraydeque,hashlink,encoding_rs?
unsafe-libyaml-norway | latest=0.2.15 | released=2024-12-21T04:23:19.663114Z | license=MIT | recent_dl=7391530 | repo=https://github.com/cafkafk/unsafe-libyaml-norway | normal_deps=
serde_yaml_bw | latest=2.5.8 | released=2026-09-07T16:47:48.408005Z | license=MIT OR Apache-2.0 | recent_dl=163495 | repo=https://github.com/bourumir-wyngs/serde-yaml-bw | normal_deps=base64,granit-parser,indexmap,itoa,num-traits,regex,serde,unsafe-libyaml-norway,zmij
```

figment 0.10.19 published features (crates.io versions[].features; it has no `default` key):

```
{"env":["pear","parse-value"],"json":["serde_json"],"parse-value":["pear"],"test":["tempfile","parking_lot"],"yaml":["serde_yaml"]}
```

serde-saphyr 2.0.0 dependencies on figment and granit-parser:

```
{"crate_id":"figment","req":"^0.10","optional":true,"default_features":true,"features":[]}
{"crate_id":"figment2","req":"^0.11","optional":true,"default_features":true,"features":[]}
{"crate_id":"granit-parser","req":"^2.0.0","optional":true,"default_features":false,"features":["std","error_messages"]}
```

## OSV advisories

Source: https://api.osv.dev/v1/vulns/<id>

```
{"id":"RUSTSEC-2024-0449","published":"2024-03-25T12:00:00Z","modified":"2026-10-12T11:45:02.518189315Z","summary":"unsafe-libyaml is unmaintained","affected":[{"pkg":"unsafe-libyaml","events":[{"introduced":"0.0.0-0"}],"info":"unmaintained"}]}
{"id":"RUSTSEC-2023-0075","published":"2023-12-20T12:00:00Z","modified":"2024-02-10T16:26:48.773264Z","summary":"Unaligned write of u64 on 32-bit and 16-bit platforms","affected":[{"pkg":"unsafe-libyaml","events":[{"introduced":"0.0.0-0"},{"fixed":"0.2.10"}],"info":"unsound"}]}
{"id":"RUSTSEC-2018-0005","published":"2018-09-17T12:00:00Z","modified":"2023-11-08T04:14:33.650192Z","summary":"Uncontrolled recursion leads to abort in deserialization","affected":[{"pkg":"serde_yaml","events":[{"introduced":"0.6.0-rc1"},{"fixed":"0.8.4"}],"info":null}]}
{"id":"RUSTSEC-2025-0068","published":"2025-09-11T12:00:00Z","modified":"2025-10-28T06:29:25.168149Z","summary":"serde_yml crate is unsound and unmaintained","affected":[{"pkg":"serde_yml","events":[{"introduced":"0.0.0-0"}],"info":"unsound"}]}
{"id":"RUSTSEC-2026-0333","published":"2026-10-06T12:00:00Z","modified":"2026-10-08T15:00:03.204356893Z","summary":"Resource budgets not enforced on the typed deserialization path","affected":[{"pkg":"noyalib","events":[{"introduced":"0.0.0-0"},{"fixed":"0.0.53"}],"info":null}]}
```

Source: https://api.osv.dev/v1/query, per crate (ids only): serde_yaml_ng, serde_norway, unsafe-libyaml-norway, saphyr, saphyr-parser, serde-saphyr, granit-parser, yaml-rust2, serde_yaml_bw and figment all returned none.

## GitHub repository state

Source: https://api.github.com/repos/<owner>/<repo>

```
dtolnay/serde-yaml: archived=true pushed=2024-03-25T00:50:35Z stars=1016 open_issues=50 license=Apache-2.0
dtolnay/unsafe-libyaml: archived=true pushed=2024-03-21T06:32:28Z stars=38 open_issues=1 license=MIT
acatton/serde-yaml-ng: archived=false pushed=2025-09-14T22:35:44Z stars=114 open_issues=20 license=MIT
cafkafk/serde-yaml: archived=false pushed=2025-08-04T15:01:36Z stars=58 open_issues=11 license=Apache-2.0
cafkafk/unsafe-libyaml-norway: archived=false pushed=2024-12-21T04:22:36Z stars=3 open_issues=0 license=MIT
sebastienrousseau/serde_yml: archived=true pushed=2026-05-28T22:19:17Z stars=119 open_issues=0 license=Apache-2.0
sebastienrousseau/noyalib: archived=false pushed=2026-10-15T23:03:38Z stars=10 open_issues=0 license=Apache-2.0
saphyr-rs/saphyr: archived=false pushed=2026-10-15T07:33:09Z stars=339 open_issues=30 license=null
bourumir-wyngs/serde-saphyr: archived=false pushed=2026-10-14T21:16:03Z stars=235 open_issues=9 license=Apache-2.0
bourumir-wyngs/granit-parser: archived=false pushed=2026-10-13T16:37:59Z stars=12 open_issues=3 license=NOASSERTION
bourumir-wyngs/serde-yaml-bw: archived=false pushed=2026-09-07T16:47:34Z stars=37 open_issues=0 license=Apache-2.0
SergioBenitez/Figment: archived=false pushed=2026-10-13T04:21:19Z stars=914 open_issues=7 license=Apache-2.0
```

## Figment master Cargo.toml [features] section

Source: https://raw.githubusercontent.com/SergioBenitez/Figment/master/Cargo.toml

```
[features]
default = ["env"]
json = ["serde_json"]
test = ["tempfile", "parking_lot"]
toml = ["toml_edit"]
yaml = ["serde_yaml"]
env = [] # does nothing; here for backwards compat
preserve_order = ["dep:indexmap", "serde_json?/preserve_order"]

```

## serde-saphyr 2.0.0 Options defaults

Source: https://docs.rs/serde-saphyr/2.0.0/serde_saphyr/options/struct.Options.html

```
Default: false (accept under-indented flow collections for compatibility).
Default: [`MergeKeyPolicy::Merge`](../enum.MergeKeyPolicy.html#variant.Merge).
Default: false (accept YAML 1.1 boolean forms).
Default: false (preserve unsupported tags for compatibility with tagged enums
If true (default), public APIs that have access to the original YAML input
If set to `0`, snippet wrapping is disabled (the original, unwrapped error is returned).
```

## Dependency trees (Spark, release line 13590f362)

`spark-cargo tree -i unsafe-libyaml --all-features -e normal,build,dev` (rc 0; the path is the spark-cargo mirror of the lane worktree):

```
unsafe-libyaml v0.2.11
└── serde_yaml v0.9.34+deprecated
    ├── figment v0.10.19
    │   └── mcp-gateway v4.0.0-beta.3 (/home/mikko/mirrors/agent-a28051eb734bb62eb-6d79a254/src)
    └── mcp-gateway v4.0.0-beta.3 (/home/mikko/mirrors/agent-a28051eb734bb62eb-6d79a254/src)
```

`spark-cargo tree -e features -i serde_yaml --all-features` (rc 0, edges that name figment):

```
figment feature "default"
figment feature "env"
figment feature "parse-value"
figment feature "pear"
figment feature "serde_yaml"
figment feature "yaml"
```

## Behaviour probe: serde_yaml 0.9.34 vs serde-saphyr 2.0.0, default settings

`spark-cargo run` of the throwaway crate below (rc 0). The crate was removed after the run and its Spark target cleaned.

```toml
[package]
name = "yaml-probe"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_yaml = "=0.9.34"
serde-saphyr = "=2.0.0"
[workspace]
```

```rust
//! MIK-8425 probe: serde_yaml 0.9.34 vs serde-saphyr 2.0.0 default behaviour.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Agent {
    Any,
    Exact(Id),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
enum Id {
    Bare(String),
    Sourced { source: String, id: String },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Row {
    agent: Agent,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Server {
    port: u16,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Cfg {
    server: Server,
}

fn show<T: std::fmt::Debug, E: std::fmt::Display>(label: &str, r: Result<T, E>) {
    match r {
        Ok(v) => println!("{label}: OK {v:?}"),
        Err(e) => println!("{label}: ERR {}", e.to_string().replace('\n', " | ")),
    }
}

fn main() {
    let dup = "server:\n  port: 1\nserver:\n  port: 2\n";
    show("dup->struct serde_yaml", serde_yaml::from_str::<Cfg>(dup));
    show("dup->struct saphyr", serde_saphyr::from_str::<Cfg>(dup));
    let dupmap = "a: 1\na: 2\n";
    show("dup->map serde_yaml", serde_yaml::from_str::<BTreeMap<String, u8>>(dupmap));
    show("dup->map saphyr", serde_saphyr::from_str::<BTreeMap<String, u8>>(dupmap));

    let rows = vec![
        Row { agent: Agent::Any },
        Row { agent: Agent::Exact(Id::Bare("runner".into())) },
        Row { agent: Agent::Exact(Id::Sourced { source: "mtls".into(), id: "spiffe://x".into() }) },
    ];
    let old = serde_yaml::to_string(&rows).unwrap();
    let new = serde_saphyr::to_string(&rows).unwrap();
    println!("ser serde_yaml:\n{old}---");
    println!("ser saphyr:\n{new}---");
    show("saphyr-written read by serde_yaml", serde_yaml::from_str::<Vec<Row>>(&new).map(|v| v == rows));
    show("serde_yaml-written read by saphyr", serde_saphyr::from_str::<Vec<Row>>(&old).map(|v| v == rows));

    for doc in ["agent: !exact runner\n", "agent: !exact {source: mtls, id: x}\n", "agent: {exact: runner}\n", "agent: any\n"] {
        show(&format!("{doc:?} serde_yaml"), serde_yaml::from_str::<Row>(doc));
        show(&format!("{doc:?} saphyr"), serde_saphyr::from_str::<Row>(doc));
    }

    let merge = "base: &b {x: 1}\nm:\n  <<: *b\n  y: 2\n";
    show("merge serde_yaml", serde_yaml::from_str::<BTreeMap<String, BTreeMap<String, u8>>>(merge));
    show("merge saphyr", serde_saphyr::from_str::<BTreeMap<String, BTreeMap<String, u8>>>(merge));

    let b = "v: yes\n";
    show("yes->bool serde_yaml", serde_yaml::from_str::<BTreeMap<String, bool>>(b));
    show("yes->bool saphyr", serde_saphyr::from_str::<BTreeMap<String, bool>>(b));
    show("yes->String serde_yaml", serde_yaml::from_str::<BTreeMap<String, String>>(b));
    show("yes->String saphyr", serde_saphyr::from_str::<BTreeMap<String, String>>(b));

    let bad = "x: [1, 2\n";
    show("syntax error serde_yaml", serde_yaml::from_str::<serde_yaml::Value>(bad));
    show("syntax error saphyr", serde_saphyr::from_str::<BTreeMap<String, Vec<u8>>>(bad));
    let secret = "port: sk-SECRET-123\n";
    show("type error serde_yaml", serde_yaml::from_str::<Server>(secret));
    show("type error saphyr", serde_saphyr::from_str::<Server>(secret));
}
```

Output:

```
dup->struct serde_yaml: ERR duplicate field `server`
dup->struct saphyr: ERR error: line 3 column 1: duplicate mapping key: server, set DuplicateKeyPolicy in Options if acceptable |  --> <input>:3:1 |   | | 1 | server: | 2 |   port: 1 | 3 | server: |   | ^ duplicate mapping key: server, set DuplicateKeyPolicy in Options if acceptable | 4 |   port: 2 |   |
dup->map serde_yaml: OK {"a": 2}
dup->map saphyr: ERR error: line 2 column 1: duplicate mapping key: a, set DuplicateKeyPolicy in Options if acceptable |  --> <input>:2:1 |   | | 1 | a: 1 | 2 | a: 2 |   | ^ duplicate mapping key: a, set DuplicateKeyPolicy in Options if acceptable
ser serde_yaml:
- agent: any
- agent: !exact runner
- agent: !exact
    source: mtls
    id: spiffe://x
---
ser saphyr:
- agent: any
- agent:
    exact: runner
- agent:
    exact:
      source: mtls
      id: spiffe://x
---
saphyr-written read by serde_yaml: ERR .[1].agent: invalid type: map, expected a YAML tag starting with '!' at line 3 column 5
serde_yaml-written read by saphyr: OK true
"agent: !exact runner\n" serde_yaml: OK Row { agent: Exact(Bare("runner")) }
"agent: !exact runner\n" saphyr: OK Row { agent: Exact(Bare("runner")) }
"agent: !exact {source: mtls, id: x}\n" serde_yaml: OK Row { agent: Exact(Sourced { source: "mtls", id: "x" }) }
"agent: !exact {source: mtls, id: x}\n" saphyr: OK Row { agent: Exact(Sourced { source: "mtls", id: "x" }) }
"agent: {exact: runner}\n" serde_yaml: ERR agent: invalid type: map, expected a YAML tag starting with '!' at line 1 column 8
"agent: {exact: runner}\n" saphyr: OK Row { agent: Exact(Bare("runner")) }
"agent: any\n" serde_yaml: OK Row { agent: Any }
"agent: any\n" saphyr: OK Row { agent: Any }
merge serde_yaml: ERR m.<<: invalid type: map, expected u8 at line 1 column 7
merge saphyr: OK {"base": {"x": 1}, "m": {"x": 1, "y": 2}}
yes->bool serde_yaml: ERR v: invalid type: string "yes", expected a boolean at line 1 column 4
yes->bool saphyr: OK {"v": true}
yes->String serde_yaml: OK {"v": "yes"}
yes->String saphyr: OK {"v": "yes"}
syntax error serde_yaml: ERR did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 4
syntax error saphyr: ERR error: line 1 column 4: unclosed bracket '[' |  --> <input>:1:4 |   | | 1 | x: [1, 2 |   |    ^ unclosed bracket '['
type error serde_yaml: ERR port: invalid type: string "sk-SECRET-123", expected u16 at line 1 column 7
type error saphyr: ERR error: line 1 column 7: invalid u16 |  --> <input>:1:7 |   | | 1 | port: sk-SECRET-123 |   |       ^ invalid u16
rc=0
```

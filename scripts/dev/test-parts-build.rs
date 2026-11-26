// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which parts of the lib test code this build compiles.
//!
//! The lib test binary is too large for one compile on a 16 GB runner, so its test modules are split into `N`
//! parts by a `#[cfg(tpK)]` line (`scripts/dev/test_parts.py` keeps them, `scripts/dev/test-parts.tsv` says which
//! part a directory is in). `MCP_GATEWAY_TEST_PART=K` builds part K only and sets `tp_partial`, under which the
//! crate root allows the dead code a partial build leaves. `0` builds no part: the code every part shares, which is
//! how that floor is measured. Unset, every part compiles, so local `cargo test`, `cargo build` and the release build
//! are unchanged. Nothing else happens here.

fn main() {
    const N: u32 = 5;
    println!("cargo::rerun-if-env-changed=MCP_GATEWAY_TEST_PART");
    for k in 1..=N {
        println!("cargo::rustc-check-cfg=cfg(tp{k})");
    }
    println!("cargo::rustc-check-cfg=cfg(tp_partial)");
    match std::env::var("MCP_GATEWAY_TEST_PART") {
        Ok(value) => {
            // Probe only (never merged): a comma list builds several parts in one compile.
            for one in value.split(',') {
                let k: u32 = one.trim().parse().ok().filter(|k| *k <= N).unwrap_or_else(|| {
                    panic!("MCP_GATEWAY_TEST_PART must be 0..={N} or a list, got {value:?}")
                });
                if k > 0 {
                    println!("cargo::rustc-cfg=tp{k}");
                }
            }
            println!("cargo::rustc-cfg=tp_partial");
        }
        Err(std::env::VarError::NotPresent) => {
            for k in 1..=N {
                println!("cargo::rustc-cfg=tp{k}");
            }
        }
        Err(err) => panic!("MCP_GATEWAY_TEST_PART must be 0..={N}: {err}"),
    }
}

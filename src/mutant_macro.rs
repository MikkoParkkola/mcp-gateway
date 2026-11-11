// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// The `mutant!` macro pair, declared `#[macro_use]` as the first module of
// src/lib.rs, so a site can sit in any library module, including commands.
// Each expansion names the library's own `crate::mutant::on` switch.

/// `mutant!("ID", mutated, original)`: a mutant site for a one-build mutation
/// proof (`src/mutant.rs`). With `--cfg mutants`, `mutated` when the process's
/// `MCP_GATEWAY_MUTANT` names `ID`, else `original`; without it, `original`
/// alone, the mutated tokens dropped unchecked. Defined before every module,
/// so a site can sit in any of them on a scratch commit; the scan in
/// `mutant_scan` keeps every site off the release line.
#[cfg(mutants)]
#[allow(unused_macros)]
macro_rules! mutant {
    ($id:literal, $mutated:expr, $original:expr $(,)?) => {
        if crate::mutant::on($id) {
            $mutated
        } else {
            $original
        }
    };
}

/// See the `cfg(mutants)` definition above: a normal build takes `original`.
#[cfg(not(mutants))]
#[allow(unused_macros)]
macro_rules! mutant {
    ($id:literal, $mutated:expr, $original:expr $(,)?) => {
        $original
    };
}

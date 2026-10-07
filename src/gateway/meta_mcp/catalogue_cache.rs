// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The meta catalogue, shared by identity (MIK-7916). Red stage: the test
//! that a repeat list recomputes nothing, ahead of the cache that makes it so.

#[cfg(test)]
#[path = "catalogue_cache_tests.rs"]
mod tests;

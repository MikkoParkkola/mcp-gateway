// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway binary's global allocator.
//!
//! The system allocator (glibc, or musl in the static Linux builds) pays for
//! the many short-lived per-call allocations freed on other worker threads
//! (MIK-7536). Binary only: the library and its tests keep the system
//! allocator, and the allocation-metering test binary installs its own.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

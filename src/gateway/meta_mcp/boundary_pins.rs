// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B boundary pins (design §4.2, test plan v2 §2-§3): what the
//! registry-ban lint cannot see, read from the crate's own source with `syn`.

mod allow_pins;
mod ci_wiring;
mod guard_tests;
mod packaged;
mod scan;
mod scan_tests;
mod shipped_reads;

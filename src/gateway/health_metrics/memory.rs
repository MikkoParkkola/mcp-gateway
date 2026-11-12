// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The process's resident memory: one reader, built in every configuration,
//! behind `/metrics` (with the `metrics` feature), the health history's
//! sampler and the Gateway Status tile.

/// The process's resident memory in bytes, or `None` when it cannot be read
/// or the system is not Linux. The one reader behind `/metrics`, the health
/// history's sampler and the Gateway Status tile.
pub(crate) fn resident_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        bytes_from(
            std::path::Path::new("/proc/self/statm"),
            rustix::param::page_size() as u64,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The resident bytes `statm` at `path` reports, pages of `page` bytes.
#[cfg(any(target_os = "linux", all(test, feature = "metrics")))]
pub(crate) fn bytes_from(path: &std::path::Path, page: u64) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| resident_bytes(&text, page))
}

/// The second field of a `statm` line (resident pages) times the page size.
#[cfg(any(target_os = "linux", all(test, feature = "metrics")))]
pub(crate) fn resident_bytes(statm: &str, page: u64) -> Option<u64> {
    statm
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(page)
}

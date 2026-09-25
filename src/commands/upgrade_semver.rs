// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The version the upgrade stamp records, ordered by semver precedence.
//!
//! The prerelease is part of the version, not noise to strip: a beta install
//! stamps `4.0.0-beta.1`, which sorts below `4.0.0`, so a migration gated on
//! 4.0.0 still runs when that install moves to the final release, and runs
//! once — an install stamped `4.0.0` is not below the gate.

use std::cmp::Ordering;
use std::fmt;

/// A parsed semantic version. Build metadata (`+...`) is accepted and ignored,
/// as semver precedence ignores it.
#[derive(Debug, Clone)]
pub struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
    /// Dot-separated prerelease identifiers; empty for a release.
    pre: Vec<String>,
}

impl SemVer {
    /// Parse `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.split_once('+').map_or(s, |(version, _)| version);
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut parts = core.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => {
                let ids: Vec<String> = pre.split('.').map(str::to_owned).collect();
                if ids.iter().any(String::is_empty) {
                    return None;
                }
                ids
            }
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// The same version with its prerelease dropped: `4.0.0-beta.1` -> `4.0.0`.
    pub fn release(&self) -> Self {
        Self {
            pre: Vec::new(),
            ..self.clone()
        }
    }
}

/// Semver §11: numeric identifiers compare numerically and sort below
/// alphanumeric ones; with an equal prefix, fewer identifiers sort first.
fn cmp_prerelease(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release outranks every prerelease of the same triple.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => cmp_prerelease(&self.pre, &other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Equality follows precedence, so `==` and `cmp` can never disagree.
impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for SemVer {}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SemVer;

    fn v(s: &str) -> SemVer {
        SemVer::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
    }

    #[test]
    fn the_prerelease_survives_a_round_trip() {
        assert_eq!(v("4.0.0-beta.1").to_string(), "4.0.0-beta.1");
        assert_eq!(v("2.9.1").to_string(), "2.9.1");
        assert_eq!(v("4.0.0-beta.1+build.7").to_string(), "4.0.0-beta.1");
    }

    #[test]
    fn precedence_follows_semver() {
        let order = [
            "3.5.1",
            "4.0.0-alpha",
            "4.0.0-alpha.1",
            "4.0.0-beta.1",
            "4.0.0-beta.2",
            "4.0.0-beta.10",
            "4.0.0-rc.1",
            "4.0.0",
            "4.0.1",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(v("4.0.0+a"), v("4.0.0+b"));
    }

    #[test]
    fn malformed_versions_do_not_parse() {
        for bad in ["not-a-version", "1.2", "", "4.0.0-", "4.0.0-beta..1"] {
            assert!(SemVer::parse(bad).is_none(), "{bad:?} parsed");
        }
    }

    #[test]
    fn release_drops_only_the_prerelease() {
        assert_eq!(v("4.0.0-rc.1").release().to_string(), "4.0.0");
    }
}

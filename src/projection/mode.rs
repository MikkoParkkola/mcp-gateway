//! Projection rollout control (MIK-5877).
//!
//! Projection ships behind a deliberate gate so it can be rolled out as an
//! *experiment*, not a default-on behavior change. [`ProjectionMode`] is the
//! master switch, defaulting to [`ProjectionMode::Off`] so existing deployments
//! are unaffected until an operator opts in — shipping a projection spec on a
//! capability changes no response contract while the mode is `off`.
//!
//! [`projection_decision`] resolves the mode (plus a session id for the A/B
//! split) into a yes/no plus an arm label for telemetry.

use serde::{Deserialize, Serialize};

/// Master switch for canonical response projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectionMode {
    /// Never project, even when a capability declares a spec. **Default** — safe
    /// for live users: shipping a projection spec changes no response contract
    /// until an operator deliberately opts in.
    #[default]
    Off,
    /// Project whenever a capability declares a spec (and the caller did not
    /// pass `_full`). The fully-on behavior.
    On,
    /// A/B experiment: split sessions 50/50 into a `treatment` arm (projected)
    /// and a `control` arm (raw) so projection's effect can be measured before
    /// committing. Assignment is sticky per session.
    Experimental,
}

/// The resolved projection decision for one invocation: whether to project, and
/// the arm label (for telemetry / A/B analysis).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionDecision {
    /// Whether to apply projection to this response.
    pub project: bool,
    /// Arm label: `"off"`, `"on"`, `"treatment"`, or `"control"`.
    pub arm: &'static str,
}

/// Deterministic session-bucketing hash: FNV-1a accumulation followed by the
/// `MurmurHash3` `fmix64` finalizer.
///
/// Stable across process restarts (no random seed, unlike
/// `std::collections::hash_map::DefaultHasher`). The finalizer is essential:
/// FNV-1a alone has **weak avalanche on short, structured inputs** — its low
/// bit reduces to input byte-parity (the prime is odd), and even its high bit
/// skews badly (empirically ~80/20 on `mcp-session-N`-style ids). `fmix64`
/// diffuses every input bit across all 64 output bits, so the low-bit split in
/// [`projection_decision`] is an unbiased ~50/50 for arbitrary session ids.
fn session_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    // MurmurHash3 fmix64 finalizer.
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// Resolve a [`ProjectionMode`] (plus the session id, for the A/B split) into a
/// [`ProjectionDecision`].
///
/// - [`ProjectionMode::Off`] → never project.
/// - [`ProjectionMode::On`] → always project (when a spec exists).
/// - [`ProjectionMode::Experimental`] → sticky 50/50 split by session id; a
///   missing session id is conservatively assigned to `control` (no
///   projection), so an un-sessioned call never silently changes shape.
#[must_use]
pub fn projection_decision(mode: ProjectionMode, session_id: Option<&str>) -> ProjectionDecision {
    match mode {
        ProjectionMode::Off => ProjectionDecision {
            project: false,
            arm: "off",
        },
        ProjectionMode::On => ProjectionDecision {
            project: true,
            arm: "on",
        },
        // Split on the low bit of the fully-avalanched hash (see `session_hash`).
        ProjectionMode::Experimental => match session_id {
            Some(sid) if (session_hash(sid.as_bytes()) & 1) == 0 => ProjectionDecision {
                project: true,
                arm: "treatment",
            },
            _ => ProjectionDecision {
                project: false,
                arm: "control",
            },
        },
    }
}

/// Cache / idempotency key suffix that isolates the A/B arms in experimental
/// mode.
///
/// Under [`ProjectionMode::Experimental`] the projected (treatment) and raw
/// (control) arms must never share a response-cache or idempotency entry — the
/// key is otherwise just `server:tool:hash(args)`, so one arm's shape would be
/// served to the other. This returns `"#arm=treatment"` / `"#arm=control"` to
/// append to those keys, isolating arms while still deduping within an arm.
/// `off` / `on` return an empty string, leaving their keys byte-identical.
#[must_use]
pub fn projection_key_suffix(mode: ProjectionMode, session_id: Option<&str>) -> String {
    match mode {
        ProjectionMode::Experimental => {
            format!("#arm={}", projection_decision(mode, session_id).arm)
        }
        ProjectionMode::Off | ProjectionMode::On => String::new(),
    }
}

/// A/B telemetry classification of a single invocation (MIK-5877, PROJ-ROLLOUT.3).
///
/// Captures which arm the call landed in and whether projection was *attempted*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbRecord {
    /// Arm label: `"treatment"` or `"control"`.
    pub arm: &'static str,
    /// Whether projection was **attempted** — treatment arm AND not a `_full`
    /// bypass. NOTE: this does not guarantee the shape actually changed:
    /// `apply_capability_projection` still returns the payload raw for an
    /// `isError` envelope or when the spec resolves no fields (fail-fast). For a
    /// clean treatment-vs-control shape comparison, filter the emitted events to
    /// `is_error = false` (and treat zero-size-delta treatment rows as no-op
    /// specs).
    pub projected: bool,
}

/// Classify an invocation for A/B telemetry, or `None` when it is not part of
/// the experiment.
///
/// Only `experimental` mode with a projection-capable tool (`spec_present`) is
/// in the experiment — `off`/`on` and spec-less tools return `None` so no event
/// is emitted for them. `projected` is true only for the treatment arm of a
/// non-`_full` call (a `_full` call bypasses projection even in treatment, so it
/// records `projected = false` while keeping its arm label).
#[must_use]
pub fn ab_classification(
    mode: ProjectionMode,
    session_id: Option<&str>,
    want_full: bool,
    spec_present: bool,
) -> Option<AbRecord> {
    if mode != ProjectionMode::Experimental || !spec_present {
        return None;
    }
    let decision = projection_decision(mode, session_id);
    Some(AbRecord {
        arm: decision.arm,
        projected: decision.project && !want_full,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_off() {
        assert_eq!(ProjectionMode::default(), ProjectionMode::Off);
    }

    #[test]
    fn off_never_projects() {
        let d = projection_decision(ProjectionMode::Off, Some("any"));
        assert!(!d.project);
        assert_eq!(d.arm, "off");
    }

    #[test]
    fn on_always_projects_even_without_session() {
        let d = projection_decision(ProjectionMode::On, None);
        assert!(d.project);
        assert_eq!(d.arm, "on");
    }

    #[test]
    fn experimental_is_sticky_per_session() {
        // Same session id -> same arm, every time (deterministic hash).
        let first = projection_decision(ProjectionMode::Experimental, Some("session-abc"));
        for _ in 0..100 {
            let again = projection_decision(ProjectionMode::Experimental, Some("session-abc"));
            assert_eq!(
                again, first,
                "assignment must be sticky for a given session"
            );
        }
    }

    #[test]
    fn experimental_splits_sessions_into_both_arms() {
        // Across many distinct sessions both arms are populated (≈50/50).
        let mut treatment = 0;
        let mut control = 0;
        for i in 0..1000 {
            let sid = format!("session-{i}");
            let d = projection_decision(ProjectionMode::Experimental, Some(&sid));
            if d.project {
                assert_eq!(d.arm, "treatment");
                treatment += 1;
            } else {
                assert_eq!(d.arm, "control");
                control += 1;
            }
        }
        // Both arms non-trivially populated; wide bounds keep it non-flaky.
        assert!(treatment > 300, "treatment arm too small: {treatment}");
        assert!(control > 300, "control arm too small: {control}");
    }

    #[test]
    fn experimental_without_session_is_control() {
        // No session id -> conservative control: never silently changes shape.
        let d = projection_decision(ProjectionMode::Experimental, None);
        assert!(!d.project);
        assert_eq!(d.arm, "control");
    }

    #[test]
    fn experimental_split_is_balanced_for_structured_ids() {
        // Regression guard: a bare FNV-1a split skewed badly on prefix-structured
        // ids (low bit = byte-parity; high bit ~80/20 on "mcp-session-N"). The
        // fmix64 finalizer must restore a ~50/50 split across realistic id shapes.
        for prefix in ["mcp-session-", "sess_", "conv-2026-06-09-", "agent:opus:"] {
            let mut treatment = 0;
            for i in 0..2000 {
                let sid = format!("{prefix}{i}");
                if projection_decision(ProjectionMode::Experimental, Some(&sid)).project {
                    treatment += 1;
                }
            }
            // 2000 samples, expect ~1000. The old biased hash produced ~1600 or
            // ~400 here; require a tight-enough band to catch that regression.
            assert!(
                (850..=1150).contains(&treatment),
                "prefix {prefix:?}: treatment={treatment}/2000 — split is biased"
            );
        }
    }

    #[test]
    fn mode_round_trips_lowercase() {
        for (mode, json) in [
            (ProjectionMode::Off, "\"off\""),
            (ProjectionMode::On, "\"on\""),
            (ProjectionMode::Experimental, "\"experimental\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), json);
            assert_eq!(serde_json::from_str::<ProjectionMode>(json).unwrap(), mode);
        }
    }

    #[test]
    fn key_suffix_empty_for_off_and_on() {
        // Off/On leave cache + idempotency keys byte-identical to pre-rollout.
        assert_eq!(projection_key_suffix(ProjectionMode::Off, Some("s")), "");
        assert_eq!(projection_key_suffix(ProjectionMode::On, Some("s")), "");
        assert_eq!(projection_key_suffix(ProjectionMode::On, None), "");
    }

    #[test]
    fn key_suffix_isolates_and_is_sticky_in_experimental() {
        let s = projection_key_suffix(ProjectionMode::Experimental, Some("session-abc"));
        assert!(
            s == "#arm=treatment" || s == "#arm=control",
            "unexpected suffix: {s}"
        );
        // Same session -> same suffix (sticky), so within-arm dedup still works.
        assert_eq!(
            s,
            projection_key_suffix(ProjectionMode::Experimental, Some("session-abc"))
        );
    }

    #[test]
    fn key_suffix_differs_between_arms() {
        // The two arms must produce distinct suffixes, or they'd still collide.
        let mut treatment = None;
        let mut control = None;
        for i in 0..200 {
            let sid = format!("s{i}");
            let s = projection_key_suffix(ProjectionMode::Experimental, Some(&sid));
            if s.contains("treatment") {
                treatment = Some(s);
            } else {
                control = Some(s);
            }
            if treatment.is_some() && control.is_some() {
                break;
            }
        }
        assert_ne!(
            treatment.expect("a treatment session"),
            control.expect("a control session")
        );
    }

    #[test]
    fn ab_classification_none_outside_experiment() {
        // off/on are not the experiment; spec-less tools are not eligible.
        assert!(ab_classification(ProjectionMode::Off, Some("s"), false, true).is_none());
        assert!(ab_classification(ProjectionMode::On, Some("s"), false, true).is_none());
        assert!(ab_classification(ProjectionMode::Experimental, Some("s"), false, false).is_none());
    }

    #[test]
    fn ab_classification_treatment_projects_unless_full() {
        // Find a treatment-arm session id.
        let sid = (0..1000)
            .map(|i| format!("t{i}"))
            .find(|s| projection_decision(ProjectionMode::Experimental, Some(s)).arm == "treatment")
            .expect("a treatment session exists");

        let rec = ab_classification(ProjectionMode::Experimental, Some(&sid), false, true).unwrap();
        assert_eq!(rec.arm, "treatment");
        assert!(
            rec.projected,
            "treatment + non-full must record projected=true"
        );

        // `_full` bypasses projection even in treatment; arm label is retained.
        let rec_full =
            ab_classification(ProjectionMode::Experimental, Some(&sid), true, true).unwrap();
        assert_eq!(rec_full.arm, "treatment");
        assert!(
            !rec_full.projected,
            "a _full call must record projected=false"
        );
    }

    #[test]
    fn ab_classification_control_never_projects() {
        let sid = (0..1000)
            .map(|i| format!("c{i}"))
            .find(|s| projection_decision(ProjectionMode::Experimental, Some(s)).arm == "control")
            .expect("a control session exists");
        let rec = ab_classification(ProjectionMode::Experimental, Some(&sid), false, true).unwrap();
        assert_eq!(rec.arm, "control");
        assert!(!rec.projected, "control arm must record projected=false");
    }
}

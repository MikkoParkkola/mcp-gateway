//! Evidence-typed render guard apparatus (spike MIK-5854).
//!
//! This module is an **additive, standalone** measurement apparatus. It is wired
//! into the crate (see [`crate`] module tree) but is **not** called from any
//! production routing, invoke, or result-proxy path. Its purpose is to model and
//! measure whether *typed evidence* plus a *non-bypassable render guard* reduces
//! unsupported claims compared to raw tool output.
//!
//! # Design
//!
//! The apparatus is built from four composable pieces, each in its own submodule:
//!
//! 1. [`state`] — the [`EvidenceState`] enum: an exhaustive, eight-variant model
//!    of what happened when a backing source was consulted. No `Option`
//!    smuggling — every outcome (including "could not check" and "not
//!    applicable") is a first-class variant.
//! 2. [`verdict`] — the four-valued [`Verdict`] enum
//!    ([`Verdict::Clean`], [`Verdict::Qualified`], [`Verdict::Adverse`],
//!    [`Verdict::Disclaimer`]) and the pure, deterministic mapping from a set of
//!    backing evidence-states to a verdict. The load-bearing behavior is the
//!    distinction between [`Verdict::Adverse`] (an authoritative negative) and
//!    [`Verdict::Disclaimer`] (we could not check).
//! 3. [`guard`] — the [`render_guard`] function: the only constructor of an
//!    [`EmittableClaim`]. A claim cannot be emitted without passing through the
//!    guard, which tags each surviving claim with its verdict and the evidence
//!    ids that justify it, and drops claims with no backing at all.
//! 4. [`harness`] — the experiment scaffolding (EVGUARD.3 / EVGUARD.4): ground
//!    truth cases, an agent invocation [`harness::Strategy`] trait stub, and a
//!    no-partial-credit scorer comparing the raw-passthrough baseline, the
//!    render guard, and reliability-weighted majority voting.
//!
//! # Scope boundary
//!
//! Pure deterministic logic: the state→verdict mapping ([`verdict`]), the render
//! guard ([`guard`]), and the scorer ([`harness::score_strategy`]). Stubbed
//! behind a trait: the agent / LLM invocation ([`harness::Strategy`]), so the
//! pure logic compiles and is unit-tested with synthetic cases.
//!
//! No formal evidence calculus lives here (no Dempster-Shafer, no Bayesian
//! fusion, no subjective logic, no isotonic calibration). Reliability-weighted
//! majority voting is the only weighting scheme, and it is deliberately simple.

pub mod guard;
pub mod harness;
pub mod state;
pub mod verdict;

pub use guard::{EmittableClaim, RawClaim, render_guard};
pub use state::{EvidenceState, SourceId};
pub use verdict::{Verdict, classify};

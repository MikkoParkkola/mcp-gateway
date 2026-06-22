//! Egress guard for mosaic leakage (MIK-6273).
//!
//! Lightweight dual-risk (direct + mosaic) scoring of outbound queries for
//! web-search/fetch backends. Cumulative per-session history is used for
//! reassembly detection. Decisions are logged and attestable.
//!
//! Placement: post-tool-selection, pre-dispatch.

pub mod mosaic_guard;
pub mod mosaic_receipt;

pub use mosaic_guard::{
    score_mosaic_egress_before_dispatch, MosaicEgressDecision, MosaicRiskScores, QueryRecord,
    reset_logs_for_test, run_classifier_eval,
};
pub use mosaic_receipt::MosaicEgressReceipt;

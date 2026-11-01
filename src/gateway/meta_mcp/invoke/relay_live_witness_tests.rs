// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T2, T3, T4) for the meta, meta-catalogue and stdio
//! witness sites. They need the request's pinned generation, which the
//! caller context does not carry until the generation accessor lands, so
//! each is ignored and its body states what it will do. Every ignored row
//! must be unskipped, and shown red then green, before this change merges.
//!
//! Shape of every row, as the direct route's (`collusion_direct_tests::live`):
//! alice is delivered `PROSE` from `alpha:read` under `block`; bob relays it.
//!  - (a) admitted under `block`; the witness hook publishes `off`. Pinned
//!    code refuses with -32002; code that reads the live config after the
//!    hook sends.
//!  - (b) admitted under `off`; the hook publishes `block`. Pinned code
//!    sends; code that reads the live config after the hook refuses.
//! Each asserts the hook ran and that its reload was the only publish since
//! admission.

use super::live::live_meta;
use crate::security::firewall::CollusionAction::{Block, Off};
use crate::security::firewall::relay_witness_hook;

/// The pinned generation reaches the witness through PR1's accessor on the
/// caller context; until it exists a row cannot pin one.
fn pin_through_the_accessor() -> ! {
    unimplemented!("waits on PR1's meta/stdio generation accessor")
}

/// Arm the witness hook to publish `action` over the live config.
fn arm_publish(lm: &super::live::LiveMeta, action: crate::security::firewall::CollusionAction) {
    let live = std::sync::Arc::clone(lm.live());
    relay_witness_hook::arm(move || {
        let mut config = (*live.get()).clone();
        config.security.firewall.collusion.action = action;
        live.set(config);
    });
}

macro_rules! witness_row {
    ($name:ident, $doc:literal, $admitted:expr, $hook:expr) => {
        #[doc = $doc]
        ///
        /// Unskip when PR1 lands.
        #[test]
        #[ignore = "waits on PR1's meta/stdio generation accessor"]
        fn $name() {
            let lm = live_meta(Block, 600);
            if $admitted == Off {
                lm.publish(Off);
            }
            arm_publish(&lm, $hook);
            pin_through_the_accessor();
        }
    };
}

witness_row!(
    t2a_meta_admitted_under_block_a_later_off_still_refuses,
    "T2a: meta `relay_refusal`, admitted under `block`, `off` published at the seam: refused.",
    Block,
    Off
);
witness_row!(
    t2b_meta_admitted_under_off_a_later_block_still_sends,
    "T2b: meta `relay_refusal`, admitted under `off`, `block` published at the seam: sent. RED on base.",
    Off,
    Block
);
witness_row!(
    t3a_meta_catalogue_admitted_under_block_a_later_off_still_refuses,
    "T3a: meta `catalogue_refusal`, admitted under `block`, `off` published at the seam: refused (403, -32002).",
    Block,
    Off
);
witness_row!(
    t3b_meta_catalogue_admitted_under_off_a_later_block_still_sends,
    "T3b: meta `catalogue_refusal`, admitted under `off`, `block` published at the seam: forwarded. RED on base.",
    Off,
    Block
);
witness_row!(
    t4a_stdio_admitted_under_block_a_later_off_still_refuses,
    "T4a: a stdio line held at the dispatch pause while `off` is published: the frame carries -32002.",
    Block,
    Off
);
witness_row!(
    t4b_stdio_admitted_under_off_a_later_block_still_sends,
    "T4b: a stdio line held at the dispatch pause while `block` is published: dispatched. RED on base.",
    Off,
    Block
);

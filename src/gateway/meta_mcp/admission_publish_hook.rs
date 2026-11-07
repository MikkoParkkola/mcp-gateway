//! The seam where settlement makes a retained answer replayable, so a row
//! can check what is already in place at that moment (the answer's replay
//! snapshot must be).

use crate::security::firewall::collusion_live_rig::Hook;

thread_local! {
    static HOOK: Hook = Hook::default();
}

pub(crate) fn arm(action: impl FnOnce() + 'static) {
    HOOK.with(|h| h.arm(action));
}

pub(super) fn run() {
    HOOK.with(Hook::run);
}

pub(crate) fn reached() -> u32 {
    HOOK.with(Hook::reached)
}

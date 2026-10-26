// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Secret bytes that are overwritten when they are dropped.

/// Secret bytes overwritten on drop. `Debug` shows only the length.
pub(crate) struct WipedBytes(Vec<u8>);

impl WipedBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        // No `zeroize` crate in the tree; `black_box` keeps the stores from
        // being elided as writes to memory about to be freed.
        self.0.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&self.0);
    }
}

impl std::fmt::Debug for WipedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The length only; the bytes are the secret.
        f.debug_struct("WipedBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

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

    /// Overwrite the whole allocation with `zeroize`'s volatile writes, which
    /// the optimiser may not drop as stores to memory about to be freed.
    /// `zeroize` on the `Vec` itself (not a slice of it) wipes the contents,
    /// clears the `Vec`, then wipes the whole buffer through its spare
    /// capacity (which covers bytes a truncated buffer left past `len`); the
    /// allocation is kept until the `Vec` drops.
    fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        self.wipe();
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

#[cfg(test)]
mod tests {
    use super::WipedBytes;

    /// `wipe` (what `Drop` runs) goes through `zeroize`'s `Vec` impl, the one
    /// that also covers the spare capacity: it leaves the buffer cleared with
    /// its allocation kept, where a slice wipe keeps the length and a no-op
    /// keeps the secret. Bytes past `len` cannot be read without `unsafe`;
    /// that `Vec::zeroize` wipes them is `zeroize`'s documented behaviour.
    #[test]
    fn the_wipe_goes_through_the_whole_allocation() {
        let mut bytes = b"s3cret-token-and-more".to_vec();
        bytes.truncate(12);
        let capacity = bytes.capacity();
        assert!(capacity > bytes.len(), "the fixture leaves bytes past len");
        let mut secret = WipedBytes::new(bytes);
        secret.wipe();
        assert!(
            secret.as_bytes().is_empty(),
            "cleared, not just overwritten"
        );
        assert_eq!(
            secret.0.capacity(),
            capacity,
            "the allocation it wiped is kept"
        );
    }
}

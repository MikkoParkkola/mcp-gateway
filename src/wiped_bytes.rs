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

    /// Overwrite the bytes in place with `zeroize`'s volatile writes, which
    /// the optimiser may not drop as stores to memory about to be freed.
    fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(self.0.as_mut_slice());
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

    /// The wipe `Drop` runs overwrites every byte, keeping the buffer's
    /// length: a no-op or a partial wipe leaves a secret byte here.
    #[test]
    fn the_wipe_overwrites_every_byte() {
        let mut secret = WipedBytes::new(b"s3cret-token".to_vec());
        secret.wipe();
        assert_eq!(secret.as_bytes().len(), 12);
        assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
    }
}

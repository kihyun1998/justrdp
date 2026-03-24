#![forbid(unsafe_code)]

use alloc::vec::Vec;

/// A dynamically-sized write buffer.
///
/// Used when the exact output size isn't known ahead of time,
/// or when building up encoded data incrementally.
#[derive(Debug, Clone)]
pub struct WriteBuf {
    inner: Vec<u8>,
}

impl WriteBuf {
    /// Create a new empty write buffer.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create a write buffer with the given capacity pre-allocated.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Ensure the buffer has at least `needed` bytes of capacity.
    ///
    /// If the current length is less than `needed`, the buffer is
    /// resized with zero-fill.
    pub fn ensure_capacity(&mut self, needed: usize) {
        if self.inner.len() < needed {
            self.inner.resize(needed, 0);
        }
    }

    /// Returns the current buffer contents as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Returns the current buffer contents as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the current length of the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear the buffer, setting length to 0 while keeping allocated memory.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Resize the buffer to `new_len`, filling new bytes with zeros.
    pub fn resize(&mut self, new_len: usize) {
        self.inner.resize(new_len, 0);
    }

    /// Consume the buffer and return the inner `Vec<u8>`.
    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }

    /// Fill the entire buffer with zeros.
    pub fn zero_fill(&mut self) {
        self.inner.fill(0);
    }
}

impl Default for WriteBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for WriteBuf {
    fn from(vec: Vec<u8>) -> Self {
        Self { inner: vec }
    }
}

impl core::ops::Index<core::ops::Range<usize>> for WriteBuf {
    type Output = [u8];

    fn index(&self, range: core::ops::Range<usize>) -> &[u8] {
        &self.inner[range]
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for WriteBuf {
    type Output = [u8];

    fn index(&self, range: core::ops::RangeTo<usize>) -> &[u8] {
        &self.inner[range]
    }
}

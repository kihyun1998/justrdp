//! `justrdp-codecs` — RDP graphics codecs behind a stable, sans-IO decode API.
//!
//! **Every codec here is self-owned, and `ironrdp-graphics` is a dev-dependency only.** That
//! is ADR-0003 phase 3 for the whole crate, reached in #189 when zgfx — the last phase-1
//! bootstrap wrapper — was rewritten and the `egfx-bootstrap` feature deleted with it. No
//! `ironrdp` crate is in the runtime graph any more (ADR-0011).
//!
//! How each got here differs, and the difference is the verification basis rather than the
//! code. [`rle`] (interleaved RLE, MS-RDPBCGR 3.1.9), [`planar`] (RDP6 planar,
//! MS-RDPEGDI 2.2.2.5.1) and [`rfx`] (WireToSurface1 RemoteFX, #58) skipped phase 1 outright
//! and are oracle-tested — `rfx` per ADR-0007 against the oracle's transform primitives, since
//! the bootstrap crate has no assembled RemoteFX decoder. [`clearcodec`] left phase 1 in #56,
//! correcting two oracle bit-level defects that reject genuine Server 2022 streams.
//! [`rfx::progressive::Progressive`] (#171, live since #172) is gated on a real-server corpus
//! instead of the oracle, which cannot decode this server's streams at all (ADR-0011, #194);
//! [`capture`] is that corpus's harness. [`zgfx`] (#189) is the one case where the references
//! handed over an *independent* expectation: FreeRDP and `ironrdp-graphics` reproduce the
//! `[MS-RDPEGFX]` sample byte-identically, so the oracle keeps a role here as breadth over
//! generated sequences rather than as the basis. NSCodec arrives with its own phase-2 rewrite.

/// Narrow a byte count to one a `Vec` will actually accept, or `None`.
///
/// **`Vec` refuses any request above `isize::MAX`, not above `usize::MAX`** — and it panics with
/// *capacity overflow* rather than returning, so a `checked_mul` chain that stops at the type's
/// ceiling leaves a band where the guard passes and the allocation dies anyway. On a 32-bit
/// target that band is 2 GiB wide. Measured (#263) on `i686-pc-windows-msvc`:
/// `rle::decompress(&[0u8; 8], 40_000, 20_000, 24)` requests 2_400_000_000 bytes from **8 bytes**
/// of source, passes its `checked_mul`, and panicked.
///
/// One helper rather than one comparison per decoder, because this is a single quantity — the
/// largest buffer any of them may ask for — and
/// [ADR-0012](../../../docs/adr/0012-consumption-site-totality.md) §3 asks a family for one
/// answer to one quantity. The threshold belongs to the *allocator*, which is what
/// [the invariant](../../../docs/map/invariant/decoder-dimension-overflow-32bit.md) states as
/// the rule: a guard's ceiling must be the one the operation that can fail actually enforces.
/// `usize::MAX` is the type's ceiling and belongs to no operation at all.
///
/// Chain it onto whichever `checked_mul` sizes the buffer, before the `ok_or`:
///
/// ```ignore
/// let total = w
///     .checked_mul(h)
///     .and_then(|n| n.checked_mul(4))
///     .and_then(crate::allocatable)
///     .ok_or(Error::DimensionsOverflow { width, height })?;
/// ```
///
/// This does **not** bound magnitude below `isize::MAX`; a decoder has no defensible number for
/// that. `justrdp::egfx` does (`MAX_TOTAL_SURFACE_BYTES`) and bounds the rectangle there.
pub(crate) fn allocatable(bytes: usize) -> Option<usize> {
    (bytes <= isize::MAX as usize).then_some(bytes)
}

/// How many bits a byte slice holds, or `None` when the product does not fit a `usize`.
///
/// The family's second single quantity, and the sibling of [`allocatable`] for the same reason
/// [ADR-0012](../../../docs/adr/0012-consumption-site-totality.md) §3 gives: three bit readers
/// each turned a byte length into a bit count with a bare `len() * 8` and there was **no**
/// recorded answer, in three places (#249).
///
/// **It is not `allocatable`, and the difference is which operation can fail.** `allocatable`
/// answers *may I ask the allocator for this many bytes*, so its ceiling is `isize::MAX`, the
/// one `Vec` enforces. Nothing is allocated here — the product is a **bound**, compared against
/// a cursor — so the only operation that can fail is the multiply itself, and its ceiling is the
/// type's. Chaining `allocatable` onto this would be a second, unrelated refusal at a threshold
/// no operation on this path enforces.
///
/// **Why it matters that this is a bound rather than an allocation.** On a 32-bit target the
/// product wraps above `usize::MAX / 8` — 536 870 911 bytes, ~512 MiB, a slice a 32-bit process
/// can hold. A wrapped bit count is worse than a panic here: `rlgr`'s `read_bits` gates on
/// `remaining()`, so a wrapped value **silently changes which streams are accepted** rather than
/// failing loudly. On 64-bit the multiply cannot fail, which is why the test below is
/// target-gated exactly as `allocatable`'s is (memory `wasm32_overflow_proof_via_i686`).
///
/// Call it once, where the reader is built, and store the result — `zgfx::BitReader` already had
/// that shape (a `budget` field computed at construction) and it is the shape the other two
/// adopted, rather than recomputing the quantity at every use.
pub(crate) fn bit_len(bytes: usize) -> Option<usize> {
    bytes.checked_mul(8)
}

/// Real-server corpus capture (ADR-0011's harness half) — ungated, see the module doc.
pub mod capture;
pub mod clearcodec;
pub mod color;
pub mod nscodec;
pub mod planar;
pub mod pointer;
pub mod rfx;
pub mod rle;
pub mod zgfx;

#[cfg(test)]
mod tests {

    /// The family's threshold, pinned in one place because it is one quantity.
    ///
    /// Target-gated: on 64-bit `isize::MAX` is 8 EiB and no `u16`-derived product comes near
    /// it, so the boundary this asserts only exists where the decoders actually run into it
    /// (memory `wasm32_overflow_proof_via_i686` — x64 structurally cannot reach these guards).
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn allocatable_refuses_exactly_what_vec_refuses() {
        use super::allocatable;

        assert_eq!(allocatable(isize::MAX as usize), Some(isize::MAX as usize));
        assert_eq!(allocatable(isize::MAX as usize + 1), None);
        assert_eq!(allocatable(usize::MAX), None);
        // The measured case: passes `checked_mul` on a 32-bit target, and `Vec` panics on it.
        assert_eq!(allocatable(2_400_000_000), None);
        assert_eq!(allocatable(0), Some(0));
    }

    /// The second quantity's threshold, pinned the same way and for the same reason (#249).
    ///
    /// Target-gated: on 64-bit the multiply cannot fail — `usize::MAX / 8` is 2^61 bytes and no
    /// slice reaches it — so the boundary this asserts only exists where the readers actually
    /// run into it (memory `wasm32_overflow_proof_via_i686`, #151/#155).
    ///
    /// **This pins the helper and not the readers**, which is a real limit and is stated rather
    /// than glossed: reddening a reader would need a live 512 MiB slice inside a 32-bit test
    /// process. The invariant's `planar::decompress` row closed at the same wall on the contract
    /// rather than on a reproduction, and this follows it.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn bit_len_refuses_exactly_what_the_multiply_cannot_hold() {
        use super::bit_len;

        assert_eq!(bit_len(0), Some(0));
        assert_eq!(bit_len(1), Some(8));
        // The last slice whose bit count fits, and the first that does not.
        assert_eq!(bit_len(usize::MAX / 8), Some((usize::MAX / 8) * 8));
        assert_eq!(bit_len(usize::MAX / 8 + 1), None);
        assert_eq!(bit_len(usize::MAX), None);
        // 512 MiB exactly: the smallest round figure in the band, and a slice a 32-bit
        // process can genuinely hold, which is what makes the band reachable rather than
        // theoretical.
        assert_eq!(bit_len(536_870_912), None);
    }
}

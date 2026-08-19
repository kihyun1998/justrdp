//! zgfx — RDP 8.0 bulk data decompression (`[MS-RDPEGFX]` 2.2.5.1, 2.2.5.2, 3.1.8.1).
//!
//! Self-owned, ungated (#189): the last phase-1 `egfx-bootstrap` wrapper, and with it the
//! **runtime** `ironrdp-graphics` dependency, retired here — ADR-0003 phase 3 reached for the
//! EGFX surface, which is [ADR-0011](../../../docs/adr/0011-zero-ironrdp-terminal-state.md)'s
//! terminal state for the runtime graph. The crate keeps the oracle as a dev-dependency.
//!
//! Decompression only. justrdp is a client and never compresses; the compressor half of both
//! reference implementations is out of scope.
//!
//! # Where this sits
//!
//! **Outermost on the EGFX path.** Every byte the server sends on
//! `Microsoft::Windows::RDS::Graphics` arrives as `RDP_SEGMENTED_DATA` and is decompressed
//! here *before* `justrdp_pdu::egfx::decode_all` sees a single command. A defect here does not
//! look like a zgfx defect — it looks like a corrupt surface command, which is the shape
//! [`a-later-stage-can-hide-an-earlier-defect`] names.
//!
//! # The state that spans messages
//!
//! One decompressor per EGFX channel, holding a **2.5 MB LZ77 history window that survives
//! across messages**: a match token in message *N* routinely reaches back into message *N-1*'s
//! bytes (the normative `[MS-RDPEGFX]` sample does exactly this *across segments*). Segments
//! must therefore be fed in arrival order, and a dropped or reordered one corrupts everything
//! after it rather than failing locally.
//!
//! That contract is enforced rather than merely documented: **a failed message poisons the
//! decompressor** and every later call returns [`ZgfxError::Poisoned`]. Both references leave
//! the object usable with a half-written history, which is the silent-corruption direction —
//! the same reasoning #168 applied to the Progressive coefficient store, and for the same
//! reason: the error is not local to the message that produced it.
//!
//! # Bounds
//!
//! Every length here is server-chosen, so
//! [`untrusted-decode-never-panics`](../../../docs/map/invariant/untrusted-decode-never-panics.md)
//! governs the whole module. Two allocation bounds exist that neither reference has, both
//! anticipated by `docs/plan.md` §V.3 (*"malformed sequences could cause OOM; use a
//! max-decompressed-size limit"*):
//!
//! - `MAX_SEGMENT_OUTPUT` caps what one **compressed** segment may expand to. The
//!   uncompressed segment path is deliberately *not* capped: its bytes are copied, not
//!   expanded, so they are already bounded by the input the DVC layer capped.
//! - `MAX_DECOMPRESSED_BYTES` caps a multipart message's declared `uncompressedSize`, which
//!   is a `u32` a hostile server picks freely.
//!
//! [`a-later-stage-can-hide-an-earlier-defect`]: ../../../docs/map/invariant/a-later-stage-can-hide-an-earlier-defect.md

/// The LZ77 sliding window, in bytes (`[MS-RDPEGFX]` 3.1.8.1 — "maximum match distance /
/// minimum history size"). Both references use exactly this value; a decompressor with a
/// smaller window silently mis-decodes a long-distance match rather than failing.
const HISTORY_SIZE: usize = 2_500_000;

/// Cap on what one **compressed** segment may expand to. `[MS-RDPEGFX]` 3.1.8.1 puts the
/// maximum uncompressed bytes in a single segment at 65535; FreeRDP enforces the same number
/// as a fixed `OutputBuffer[65536]`. `ironrdp-graphics` has no such bound at all, which is what
/// makes a ~20-byte segment able to demand gigabytes (a match length is `2^(k+1) + v` for a
/// unary-coded `k` the stream chooses).
const MAX_SEGMENT_OUTPUT: usize = 65_536;

/// Cap on a multipart message's declared `uncompressedSize`. A conforming server's message is
/// bounded by `justrdp`'s 4 MiB dynamic-channel reassembly cap on the *compressed* side; this
/// is the bound on the decompressed side, where the size is a `u32` the server chose and both
/// references will happily allocate all 4 GiB of it (65535 segments x 65536 bytes reaches it
/// from ~400 KiB of input).
const MAX_DECOMPRESSED_BYTES: usize = 64 << 20;

/// Cap on the *input* length of one compressed segment. The bit cursor addresses a segment in
/// bits, so `len * 8` is the one expression in this module a 32-bit target can overflow; the
/// cap removes that expression's reach instead of guarding its result. Its value is the spec's
/// own compressor limits as FreeRDP transcribes them (`libfreerdp/codec/zgfx.c`, *"maximum
/// number of uncompressed bytes in a single segment: 65535"* and *"maximum expansion of a
/// segment (when compressed size exceeds uncompressed): 1000 bytes"*), so no conforming
/// encoder can reach it — the real VM's largest was 10 680 bytes over one session.
const MAX_COMPRESSED_SEGMENT: usize = MAX_SEGMENT_OUTPUT + 1_000;

/// `RDP_SEGMENTED_DATA::descriptor` — one segment follows (`[MS-RDPEGFX]` 2.2.5.1).
const SEGMENTED_SINGLE: u8 = 0xE0;
/// `RDP_SEGMENTED_DATA::descriptor` — a segment count and array follow.
const SEGMENTED_MULTIPART: u8 = 0xE1;
/// `RDP8_BULK_ENCODED_DATA::header` low nibble — `PACKET_COMPR_TYPE_RDP8` (2.2.5.2).
const COMPR_TYPE_RDP8: u8 = 0x04;
/// `RDP8_BULK_ENCODED_DATA::header` high nibble — `PACKET_COMPRESSED`.
const PACKET_COMPRESSED: u8 = 0x02;

/// Why a `RDP_SEGMENTED_DATA` message failed to decompress. Every variant is a *typed error*
/// on a server-supplied value; none of these is reachable from a conforming encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZgfxError {
    /// A header, segment or bitstream read ran past the end of the buffer. Carries which one.
    Truncated(&'static str),
    /// `RDP_SEGMENTED_DATA::descriptor` was neither `0xE0` nor `0xE1`.
    UnknownDescriptor(u8),
    /// `RDP8_BULK_ENCODED_DATA`'s low nibble was not `PACKET_COMPR_TYPE_RDP8` (4).
    UnknownCompressionType(u8),
    /// The trailing "unused bits in the final byte" count exceeded the segment's own bit
    /// length. FreeRDP rejects this (`bits < *pbInputEnd`); `ironrdp-graphics` underflows and
    /// panics on it (#189's probe, case B).
    InvalidUnusedBitCount { unused: usize, available: usize },
    /// A bit pattern matching no entry in the token table. Exactly two exist (`10000` and
    /// `101111111`); FreeRDP silently skips them, we refuse.
    UnknownToken,
    /// A match reached further back than the history window holds, so the bytes it names have
    /// never existed. Both references wrap modulo the window and emit whatever is there.
    DistanceOutsideHistory { distance: usize },
    /// One compressed segment tried to expand past `MAX_SEGMENT_OUTPUT`.
    SegmentOutputTooLarge,
    /// A compressed segment's own bytes exceeded `MAX_COMPRESSED_SEGMENT`.
    SegmentTooLong { len: usize },
    /// A multipart message declared an `uncompressedSize` past `MAX_DECOMPRESSED_BYTES`.
    DeclaredSizeTooLarge { declared: usize },
    /// A multipart message's segments produced a different byte count than it declared.
    DecompressedSizeMismatch { produced: usize, declared: usize },
    /// An earlier message failed, so the history window is desynchronised from the server's
    /// and every later match would decode against the wrong bytes. See the module docs.
    Poisoned,
}

impl core::fmt::Display for ZgfxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "truncated {what}"),
            Self::UnknownDescriptor(d) => write!(f, "unknown segmented descriptor {d:#04x}"),
            Self::UnknownCompressionType(t) => write!(f, "unknown compression type {t:#x}"),
            Self::InvalidUnusedBitCount { unused, available } => write!(
                f,
                "unused bit count {unused} exceeds the segment's {available} bits"
            ),
            Self::UnknownToken => write!(f, "bit pattern matches no token"),
            Self::DistanceOutsideHistory { distance } => {
                write!(f, "match distance {distance} exceeds the history window")
            }
            Self::SegmentOutputTooLarge => write!(f, "segment expands past the output cap"),
            Self::SegmentTooLong { len } => {
                write!(f, "compressed segment of {len} bytes is too long")
            }
            Self::DeclaredSizeTooLarge { declared } => {
                write!(f, "declared uncompressed size {declared} exceeds the cap")
            }
            Self::DecompressedSizeMismatch { produced, declared } => write!(
                f,
                "segments produced {produced} bytes against a declared {declared}"
            ),
            Self::Poisoned => write!(f, "history desynchronised by an earlier failure"),
        }
    }
}

impl core::error::Error for ZgfxError {}

/// One entry of the `[MS-RDPEGFX]` 3.1.8.1 token table. Literals and matches share a shape:
/// a literal's value is `value_base + <value_bits>`, a match's distance is the same sum. The
/// single-bit `0` prefix is the "null literal" — `value_base = 0`, `value_bits = 8` — so it
/// needs no special case here.
struct Token {
    prefix_len: u32,
    prefix_code: u32,
    value_bits: u32,
    is_match: bool,
    value_base: u32,
}

const fn lit(prefix_len: u32, prefix_code: u32, value_bits: u32, value_base: u32) -> Token {
    Token {
        prefix_len,
        prefix_code,
        value_bits,
        is_match: false,
        value_base,
    }
}

const fn mat(prefix_len: u32, prefix_code: u32, value_bits: u32, value_base: u32) -> Token {
    Token {
        prefix_len,
        prefix_code,
        value_bits,
        is_match: true,
        value_base,
    }
}

/// The token table of `[MS-RDPEGFX]` 3.1.8.1, **sorted by prefix length ascending** — the
/// decode loop below depends on that order, because it grows one candidate prefix and compares
/// it against each entry in turn.
///
/// Cross-checked entry-for-entry against both references, which agree with each other and with
/// the spec: FreeRDP `libfreerdp/codec/zgfx.c` `ZGFX_TOKEN_TABLE`, `ironrdp-graphics` 0.9.0
/// `src/zgfx/mod.rs` `TOKEN_TABLE`. The codes are prefix-free but **not complete**: `10000`
/// and `101111111` name no token.
const TOKEN_TABLE: [Token; 39] = [
    lit(1, 0, 8, 0),
    mat(5, 17, 5, 0),
    mat(5, 18, 7, 32),
    mat(5, 19, 9, 160),
    mat(5, 20, 10, 672),
    mat(5, 21, 12, 1_696),
    lit(5, 24, 0, 0x00),
    lit(5, 25, 0, 0x01),
    mat(6, 44, 14, 5_792),
    mat(6, 45, 15, 22_176),
    lit(6, 52, 0, 0x02),
    lit(6, 53, 0, 0x03),
    lit(6, 54, 0, 0xFF),
    mat(7, 92, 18, 54_944),
    mat(7, 93, 20, 317_088),
    lit(7, 110, 0, 0x04),
    lit(7, 111, 0, 0x05),
    lit(7, 112, 0, 0x06),
    lit(7, 113, 0, 0x07),
    lit(7, 114, 0, 0x08),
    lit(7, 115, 0, 0x09),
    lit(7, 116, 0, 0x0A),
    lit(7, 117, 0, 0x0B),
    lit(7, 118, 0, 0x3A),
    lit(7, 119, 0, 0x3B),
    lit(7, 120, 0, 0x3C),
    lit(7, 121, 0, 0x3D),
    lit(7, 122, 0, 0x3E),
    lit(7, 123, 0, 0x3F),
    lit(7, 124, 0, 0x40),
    lit(7, 125, 0, 0x80),
    mat(8, 188, 20, 1_365_664),
    mat(8, 189, 21, 2_414_240),
    lit(8, 252, 0, 0x0C),
    lit(8, 253, 0, 0x38),
    lit(8, 254, 0, 0x39),
    lit(8, 255, 0, 0x66),
    mat(9, 380, 22, 4_511_392),
    mat(9, 381, 23, 8_705_696),
];

/// The 40th table entry, kept out of [`TOKEN_TABLE`] only so the array literal above reads as
/// the spec's table does. It is appended by the decode loop.
const TOKEN_LAST: Token = mat(9, 382, 24, 17_094_304);

/// An MSB-first bit cursor with an explicit budget — the segment's `NumberOfBitsToDecode`,
/// which is shorter than the buffer it reads from (the trailing byte holds the unused-bit
/// count and is never decoded). Same shape as `rfx::rlgr`'s reader; separate because that one
/// spans the whole slice and this one must also hand out **byte-aligned raw runs**.
struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position.
    pos: usize,
    /// Total decodable bits — `(data.len()) * 8 - unused`, never more than `data.len() * 8`.
    budget: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], budget: usize) -> Self {
        debug_assert!(budget <= data.len() * 8);
        Self {
            data,
            pos: 0,
            budget,
        }
    }

    fn remaining(&self) -> usize {
        self.budget - self.pos
    }

    /// Read one bit, or `None` at the budget's end.
    fn bit(&mut self) -> Option<u32> {
        if self.pos >= self.budget {
            return None;
        }
        let byte = self.data[self.pos / 8];
        let value = u32::from((byte >> (7 - (self.pos % 8))) & 1);
        self.pos += 1;
        Some(value)
    }

    /// Read `n` bits (`n <= 24`, the widest value field in the token table) big-endian.
    fn bits(&mut self, n: u32) -> Option<u32> {
        let n = n as usize;
        if self.remaining() < n {
            return None;
        }
        let mut acc = 0u32;
        for _ in 0..n {
            let bit = self.bit()?;
            acc = (acc << 1) | bit;
        }
        Some(acc)
    }

    /// Consume the run of `1` bits before the next `0`, and the `0` itself. Returns the run
    /// length, or `None` if the budget ends before a `0` appears.
    fn unary(&mut self) -> Option<usize> {
        let mut ones = 0usize;
        loop {
            match self.bit()? {
                0 => return Some(ones),
                _ => ones += 1,
            }
        }
    }

    /// Advance to the next byte boundary — what precedes an unencoded run, whose bytes are
    /// read raw rather than bit by bit. `None` when the padding alone would pass the budget,
    /// which must not silently move `pos` beyond it: every other method here maintains
    /// `pos <= budget`, and [`Self::remaining`] subtracts on that assumption.
    fn align_to_byte(&mut self) -> Option<()> {
        let aligned = self.pos.div_ceil(8) * 8;
        if aligned > self.budget {
            return None;
        }
        self.pos = aligned;
        Some(())
    }

    /// Take `n` whole bytes at the current (byte-aligned) position.
    fn take_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        debug_assert_eq!(self.pos % 8, 0);
        if self.remaining() < n.checked_mul(8)? {
            return None;
        }
        let start = self.pos / 8;
        let bytes = self.data.get(start..start + n)?;
        self.pos += n * 8;
        Some(bytes)
    }
}

/// The LZ77 sliding window: a fixed ring of [`HISTORY_SIZE`] bytes plus the write position.
///
/// Zero-filled at construction, which is observable: a match pointing further back than the
/// session has produced reads zeros rather than failing, and both references do the same.
struct History {
    buf: Vec<u8>,
    pos: usize,
}

impl History {
    fn new() -> Self {
        Self {
            buf: vec![0; HISTORY_SIZE],
            pos: 0,
        }
    }

    /// Append `src`, keeping only its last [`HISTORY_SIZE`] bytes if it is longer.
    fn write(&mut self, src: &[u8]) {
        if src.len() >= self.buf.len() {
            // Unreachable while MAX_SEGMENT_OUTPUT < HISTORY_SIZE, handled so the two constants
            // are not silently coupled. The ring's linear layout differs from an incremental
            // write's, but every read is relative to `pos`, so the logical window is identical.
            let tail = &src[src.len() - self.buf.len()..];
            self.buf.copy_from_slice(tail);
            self.pos = 0;
            return;
        }
        for &b in src {
            self.buf[self.pos] = b;
            self.pos += 1;
            if self.pos == self.buf.len() {
                self.pos = 0;
            }
        }
    }

    /// Copy `length` bytes from `distance` back, appending them to both `output` and the
    /// window. Written byte at a time on purpose: `length > distance` is the ordinary
    /// overlapping-match case, and the repeat falls out of the write advancing the read.
    fn copy_match(&mut self, distance: usize, length: usize, output: &mut Vec<u8>) {
        debug_assert!(distance >= 1 && distance <= self.buf.len());
        let mut src = (self.buf.len() + self.pos - distance) % self.buf.len();
        for _ in 0..length {
            let b = self.buf[src];
            output.push(b);
            self.buf[self.pos] = b;
            src += 1;
            if src == self.buf.len() {
                src = 0;
            }
            self.pos += 1;
            if self.pos == self.buf.len() {
                self.pos = 0;
            }
        }
    }
}

/// Stateful zgfx (RDP8 bulk) decompressor — one per EGFX channel. See the module docs for the
/// cross-message history contract and what a failure does to it.
pub struct Zgfx {
    history: History,
    poisoned: bool,
}

impl Zgfx {
    /// A decompressor with a zeroed 2.5 MB history window.
    pub fn new() -> Self {
        Self {
            history: History::new(),
            poisoned: false,
        }
    }

    /// Decompress one `RDP_SEGMENTED_DATA` message (single or multipart) into `output`, which
    /// is cleared first. Callers reuse one buffer across messages, keeping the per-message
    /// allocation off the hot path (#86).
    ///
    /// On error the decompressor is **poisoned**: the history window no longer matches the
    /// server's, so every later call returns [`ZgfxError::Poisoned`] rather than decoding
    /// against the wrong bytes.
    pub fn decompress_into(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<(), ZgfxError> {
        if self.poisoned {
            return Err(ZgfxError::Poisoned);
        }
        output.clear();
        match self.segmented(input, output) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    /// [`Self::decompress_into`] with a freshly allocated buffer per call.
    pub fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>, ZgfxError> {
        let mut output = Vec::new();
        self.decompress_into(input, &mut output)?;
        Ok(output)
    }

    /// `RDP_SEGMENTED_DATA` (`[MS-RDPEGFX]` 2.2.5.1).
    fn segmented(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<(), ZgfxError> {
        let (&descriptor, mut rest) = input
            .split_first()
            .ok_or(ZgfxError::Truncated("segmented descriptor"))?;

        match descriptor {
            SEGMENTED_SINGLE => self.segment(rest, output),
            SEGMENTED_MULTIPART => {
                let header = rest
                    .get(..6)
                    .ok_or(ZgfxError::Truncated("multipart header"))?;
                let segment_count = usize::from(u16::from_le_bytes([header[0], header[1]]));
                let declared = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
                let declared = declared as usize;
                if declared > MAX_DECOMPRESSED_BYTES {
                    return Err(ZgfxError::DeclaredSizeTooLarge { declared });
                }
                rest = &rest[6..];

                for _ in 0..segment_count {
                    let size_bytes = rest.get(..4).ok_or(ZgfxError::Truncated("segment size"))?;
                    let size = u32::from_le_bytes([
                        size_bytes[0],
                        size_bytes[1],
                        size_bytes[2],
                        size_bytes[3],
                    ]) as usize;
                    rest = &rest[4..];
                    let data = rest.get(..size).ok_or(ZgfxError::Truncated("segment"))?;
                    rest = &rest[size..];

                    self.segment(data, output)?;
                    if output.len() > declared {
                        return Err(ZgfxError::DecompressedSizeMismatch {
                            produced: output.len(),
                            declared,
                        });
                    }
                }

                if output.len() != declared {
                    return Err(ZgfxError::DecompressedSizeMismatch {
                        produced: output.len(),
                        declared,
                    });
                }
                Ok(())
            }
            other => Err(ZgfxError::UnknownDescriptor(other)),
        }
    }

    /// `RDP8_BULK_ENCODED_DATA` (`[MS-RDPEGFX]` 2.2.5.2): a type/flags byte and its payload.
    fn segment(&mut self, data: &[u8], output: &mut Vec<u8>) -> Result<(), ZgfxError> {
        let (&header, body) = data
            .split_first()
            .ok_or(ZgfxError::Truncated("segment header"))?;

        let compression_type = header & 0x0F;
        if compression_type != COMPR_TYPE_RDP8 {
            return Err(ZgfxError::UnknownCompressionType(compression_type));
        }

        if (header >> 4) & PACKET_COMPRESSED == 0 {
            // Copied, not expanded — already bounded by the input the caller was handed, so
            // this path carries no output cap. FreeRDP rejects a body past 65536 here; a
            // server that sent one would only be wasting bandwidth, not amplifying anything.
            self.history.write(body);
            output.extend_from_slice(body);
            return Ok(());
        }

        // An empty compressed body carries no tokens. FreeRDP refuses the whole segment
        // (`segmentSize < 2`); accepting it costs nothing and ADR-0009's receive-path posture
        // says a harmless shape is not worth a dead channel.
        if body.is_empty() {
            return Ok(());
        }

        self.compressed_segment(body, output)
    }

    /// The RDP8 token stream of one `PACKET_COMPRESSED` segment (`[MS-RDPEGFX]` 3.1.8.1).
    fn compressed_segment(&mut self, body: &[u8], output: &mut Vec<u8>) -> Result<(), ZgfxError> {
        // "NumberOfBitsToDecode = ((NumberOfBytesToDecode - 1) * 8) - ValueOfLastByte". The
        // final byte is the unused-bit count and is never itself decoded, so it is also
        // outside the range an unencoded run may read from.
        if body.len() > MAX_COMPRESSED_SEGMENT {
            return Err(ZgfxError::SegmentTooLong { len: body.len() });
        }
        let (&unused, decodable) = body
            .split_last()
            .expect("caller rejects an empty compressed body");
        let available = decodable.len() * 8;
        let unused = usize::from(unused);
        if unused > available {
            return Err(ZgfxError::InvalidUnusedBitCount { unused, available });
        }

        let mut bits = BitReader::new(decodable, available - unused);
        let produced_before = output.len();

        while bits.remaining() > 0 {
            let token = Self::next_token(&mut bits)?;
            let value = bits
                .bits(token.value_bits)
                .ok_or(ZgfxError::Truncated("token value"))?;

            if !token.is_match {
                let byte =
                    u8::try_from((token.value_base + value) & 0xFF).expect("masked to one byte");
                Self::guard_output(output.len() - produced_before, 1)?;
                output.push(byte);
                self.history.write(&[byte]);
                continue;
            }

            let distance = (token.value_base + value) as usize;
            if distance == 0 {
                self.unencoded_run(&mut bits, output, produced_before)?;
            } else {
                self.encoded_match(&mut bits, distance, output, produced_before)?;
            }
        }

        Ok(())
    }

    /// Grow a candidate prefix one bit at a time and return the first table entry it equals.
    /// Sound because the table is sorted by prefix length and the codes are prefix-free.
    fn next_token(bits: &mut BitReader<'_>) -> Result<&'static Token, ZgfxError> {
        let mut have = 0u32;
        let mut prefix = 0u32;
        for token in TOKEN_TABLE.iter().chain(core::iter::once(&TOKEN_LAST)) {
            while have < token.prefix_len {
                let bit = bits.bit().ok_or(ZgfxError::Truncated("token prefix"))?;
                prefix = (prefix << 1) | bit;
                have += 1;
            }
            if prefix == token.prefix_code {
                return Ok(token);
            }
        }
        Err(ZgfxError::UnknownToken)
    }

    /// A match distance of zero introduces a raw byte run: a 15-bit count, byte alignment,
    /// then the bytes themselves.
    fn unencoded_run(
        &mut self,
        bits: &mut BitReader<'_>,
        output: &mut Vec<u8>,
        produced_before: usize,
    ) -> Result<(), ZgfxError> {
        let count = bits
            .bits(15)
            .ok_or(ZgfxError::Truncated("unencoded run length"))? as usize;
        bits.align_to_byte()
            .ok_or(ZgfxError::Truncated("unencoded run"))?;
        Self::guard_output(output.len() - produced_before, count)?;
        let run = bits
            .take_bytes(count)
            .ok_or(ZgfxError::Truncated("unencoded run"))?;
        output.extend_from_slice(run);
        self.history.write(run);
        Ok(())
    }

    /// A back-reference: the length follows the distance as `k` one-bits, a zero bit, then
    /// `k + 1` value bits, with `k == 0` meaning the literal length 3.
    fn encoded_match(
        &mut self,
        bits: &mut BitReader<'_>,
        distance: usize,
        output: &mut Vec<u8>,
        produced_before: usize,
    ) -> Result<(), ZgfxError> {
        if distance > HISTORY_SIZE {
            // The bytes this names have never existed. Both references wrap modulo the window
            // and emit whatever happens to be there; no conforming encoder can reach here,
            // because its own history is the same 2.5 MB.
            return Err(ZgfxError::DistanceOutsideHistory { distance });
        }

        let k = bits
            .unary()
            .ok_or(ZgfxError::Truncated("match length prefix"))?;
        let length = if k == 0 {
            3
        } else {
            // `1 << (k + 1)` already exceeds MAX_SEGMENT_OUTPUT at k = 16; refusing here keeps
            // the shift itself in range rather than relying on a later cap to catch it.
            if k > 16 {
                return Err(ZgfxError::SegmentOutputTooLarge);
            }
            let extra = bits
                .bits(u32::try_from(k).expect("k <= 16") + 1)
                .ok_or(ZgfxError::Truncated("match length"))? as usize;
            (1usize << (k + 1)) + extra
        };

        Self::guard_output(output.len() - produced_before, length)?;
        self.history.copy_match(distance, length, output);
        Ok(())
    }

    /// Refuse before producing, so an oversized claim never allocates.
    fn guard_output(produced: usize, adding: usize) -> Result<(), ZgfxError> {
        if produced + adding > MAX_SEGMENT_OUTPUT {
            return Err(ZgfxError::SegmentOutputTooLarge);
        }
        Ok(())
    }
}

impl Default for Zgfx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[MS-RDPEGFX]` sample payload. FreeRDP carries it under the comment
    /// *"Sample from [MS-RDPEGFX]"* (`libfreerdp/codec/test/TestFreeRDPCodecZGfx.c`,
    /// `TEST_FOX_DATA`); `ironrdp-graphics` carries the identical bytes in its own tests. Both
    /// reproductions agree, which is what makes this an expectation derived from the spec
    /// rather than from either implementation (ADR-0011's owned-basis requirement).
    const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

    /// `TEST_FOX_DATA_SINGLE` — one uncompressed segment.
    const FOX_SINGLE: &[u8] = b"\xE0\x04The quick brown fox jumps over the lazy dog";

    /// `TEST_FOX_DATA_MULTIPART` — three segments, the third `PACKET_COMPRESSED`. Its token
    /// stream is annotated in the spec: three literals, then a **match at distance 31 and
    /// length 3** ("he "), which reaches back past this segment's own start into the bytes the
    /// *first* segment wrote. That is the cross-message history contract in one vector.
    const FOX_MULTIPART: &[u8] = &[
        0xE1, // descriptor: multipart
        0x03, 0x00, // segmentCount = 3
        0x2B, 0x00, 0x00, 0x00, // uncompressedSize = 43
        0x11, 0x00, 0x00, 0x00, // segment 1: 17 bytes
        0x04, // RDP8, not compressed
        0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
        0x20, // "The quick brown "
        0x0E, 0x00, 0x00, 0x00, // segment 2: 14 bytes
        0x04, // RDP8, not compressed
        0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76,
        0x65, // "fox jumps ove"
        0x10, 0x00, 0x00, 0x00, // segment 3: 16 bytes
        0x24, // RDP8 + PACKET_COMPRESSED
        0x39, 0x08, 0x0E, 0x91, 0xF8, 0xD8, 0x61, 0x3D, 0x1E, 0x44, 0x06, 0x43, 0x79, 0x9C,
        0x02, // ...and 2 unused bits in 0x9C
    ];

    #[test]
    fn the_spec_sample_decodes_as_a_single_uncompressed_segment() {
        let mut z = Zgfx::new();
        assert_eq!(z.decompress(FOX_SINGLE).unwrap(), FOX);
    }

    #[test]
    fn the_spec_sample_decodes_as_three_segments_with_a_match_across_them() {
        // The decisive half is the third segment: "he " is not in it, it is a back-reference
        // 31 bytes into what the first segment put in the history window. A decoder that
        // rebuilt its window per segment would produce the right length and the wrong bytes.
        let mut z = Zgfx::new();
        assert_eq!(z.decompress(FOX_MULTIPART).unwrap(), FOX);
    }

    #[test]
    fn a_match_reaches_back_into_a_previous_message() {
        // The same property one level up: two `decompress` calls, the second referring to the
        // first's bytes. Built by hand rather than captured, because the window spanning
        // *messages* is the contract that no single-message corpus can see.
        //
        // One token: match, distance 3, length 3 — the last three bytes of FOX, "dog".
        // 10001 (match, 5 value bits) 00011 (distance 3) 0 (length 3), then 5 unused bits.
        let msg = [0xE0, 0x24, 0b1000_1000, 0b1100_0000, 0x05];

        let mut z = Zgfx::new();
        assert_eq!(z.decompress(FOX_SINGLE).unwrap(), FOX);
        assert_eq!(z.decompress(&msg).unwrap(), b"dog");

        // The same bytes against a fresh window decode to zeros, which is what makes the
        // assertion above about the history rather than about the token decoder.
        let mut fresh = Zgfx::new();
        assert_eq!(fresh.decompress(&msg).unwrap(), &[0, 0, 0]);
    }

    #[test]
    fn an_overlapping_match_repeats_its_own_output() {
        // The run-length case, where the bytes being copied are the bytes just written:
        // 0 01100101 (literal 0x65), 10001 00001 (distance 1), 10 00 (length 4).
        let mut z = Zgfx::new();
        let out = z
            .decompress(&[0xE0, 0x24, 0b0011_0010, 0b1100_0100, 0b0011_0000, 0x01])
            .unwrap();
        assert_eq!(out, vec![0x65; 5]);
    }

    #[test]
    fn an_unencoded_run_is_byte_aligned_and_copied_raw() {
        // Match token with distance 0 -> 15-bit length, byte alignment, then raw bytes.
        let mut z = Zgfx::new();
        let mut msg = vec![0xE0u8, 0x24, 0x88, 0x00, 0x15, 0x80];
        msg.extend_from_slice(FOX);
        msg.push(0x00); // no unused bits
        assert_eq!(z.decompress(&msg).unwrap(), FOX);
    }

    // ---- bounds: every one of these panicked in the bootstrap wrapper (#189) ----------------

    #[test]
    fn a_multipart_segment_size_past_the_buffer_is_an_error_not_a_panic() {
        // One segment whose declared size is 0x7FFFFFFF against 0 remaining bytes.
        let msg = [0xE1u8, 1, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut z = Zgfx::new();
        assert_eq!(z.decompress(&msg), Err(ZgfxError::Truncated("segment")));
    }

    #[test]
    fn an_unused_bit_count_past_the_segment_is_an_error_not_a_panic() {
        // One data byte: the segment declares 5 unused bits where it has 0 to spare.
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE0, 0x24, 0x05]),
            Err(ZgfxError::InvalidUnusedBitCount {
                unused: 5,
                available: 0
            })
        );
    }

    #[test]
    fn a_token_value_running_off_the_end_is_an_error_not_a_panic() {
        // Budget 8 bits: the null-literal prefix takes 1 and its value needs 8 more.
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE0, 0x24, 0x00, 0x00]),
            Err(ZgfxError::Truncated("token value"))
        );
    }

    #[test]
    fn an_unencoded_run_claiming_more_than_the_segment_holds_is_an_error() {
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE0, 0x24, 0b1000_1000, 0b0000_0111, 0xFF, 0xFF, 0x00]),
            Err(ZgfxError::Truncated("unencoded run"))
        );
    }

    #[test]
    fn a_match_length_that_would_outgrow_the_segment_cap_is_an_error() {
        // 17 one-bits before the zero: `1 << 18` is past MAX_SEGMENT_OUTPUT, and the guard
        // fires before the shift rather than after the allocation.
        let mut z = Zgfx::new();
        // 10001 00011 (match, distance 3), then seventeen 1 bits, then the terminating 0.
        let msg = [0xE0u8, 0x24, 0x88, 0xFF, 0xFF, 0xE0, 0x04];
        assert_eq!(z.decompress(&msg), Err(ZgfxError::SegmentOutputTooLarge));
    }

    #[test]
    fn an_unencoded_run_whose_alignment_overruns_the_budget_is_an_error_not_a_panic() {
        // Step 5 finding. The 15-bit length leaves the cursor at bit 25; aligning to the next
        // byte boundary puts it at 32, and the segment declares 7 unused bits so its budget
        // ends at 25. Nothing in the token stream is malformed until that alignment.
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE0, 0x24, 0x88, 0x00, 0x00, 0x00, 0x07]),
            Err(ZgfxError::Truncated("unencoded run"))
        );
    }

    #[test]
    fn a_compressed_segment_longer_than_the_spec_allows_is_refused() {
        // Step 5 finding. The bit cursor addresses the segment in bits, so `len * 8` is the
        // one expression here that a 32-bit target can overflow. Capping the segment at the
        // spec's own ceiling removes the expression's reach rather than guarding its result.
        let mut z = Zgfx::new();
        let mut message = vec![0xE0, 0x24];
        message.resize(2 + MAX_COMPRESSED_SEGMENT + 1, 0);
        assert_eq!(
            z.decompress(&message),
            Err(ZgfxError::SegmentTooLong {
                len: MAX_COMPRESSED_SEGMENT + 1
            })
        );
    }

    #[test]
    fn a_declared_uncompressed_size_past_the_cap_is_refused_before_decoding() {
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(ZgfxError::DeclaredSizeTooLarge {
                declared: 0xFFFF_FFFF
            })
        );
    }

    #[test]
    fn a_distance_past_the_history_window_is_an_error() {
        // The last token: 9-bit prefix 101111110, base 17094304, 24 value bits — every
        // distance it can express is outside a 2.5 MB window.
        let mut z = Zgfx::new();
        let msg = [0xE0u8, 0x24, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(
            z.decompress(&msg),
            Err(ZgfxError::DistanceOutsideHistory {
                distance: 17_094_304
            })
        );
    }

    #[test]
    fn a_bit_pattern_matching_no_token_is_an_error() {
        // `10000` names no token; FreeRDP consumes nine bits and silently moves on.
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[0xE0, 0x24, 0b1000_0000, 0b0000_0000, 0x00]),
            Err(ZgfxError::UnknownToken)
        );
    }

    #[test]
    fn an_unknown_descriptor_and_compression_type_are_distinct_errors() {
        assert_eq!(
            Zgfx::new().decompress(&[0x00, 0x04]),
            Err(ZgfxError::UnknownDescriptor(0x00))
        );
        assert_eq!(
            Zgfx::new().decompress(&[0xE0, 0x05]),
            Err(ZgfxError::UnknownCompressionType(0x05))
        );
    }

    #[test]
    fn a_multipart_whose_segments_disagree_with_its_declared_size_is_an_error() {
        let mut z = Zgfx::new();
        assert_eq!(
            z.decompress(&[
                0xE1, 0x01, 0x00, // one segment
                0x05, 0x00, 0x00, 0x00, // declaring 5 bytes
                0x03, 0x00, 0x00, 0x00, 0x04, 0x68, 0x69, // but carrying 2
            ]),
            Err(ZgfxError::DecompressedSizeMismatch {
                produced: 2,
                declared: 5
            })
        );
    }

    // ---- the cross-message contract ---------------------------------------------------------

    #[test]
    fn a_failed_message_poisons_the_decompressor() {
        // The history desynchronises the moment a segment half-writes it, and every later
        // match then decodes against bytes the server does not have. Both references leave the
        // object usable in that state; this one refuses, which is what makes the contract in
        // the module docs observable rather than merely stated.
        let mut z = Zgfx::new();
        assert!(z.decompress(&[0xE0, 0x24, 0x05]).is_err());
        assert_eq!(z.decompress(FOX_SINGLE), Err(ZgfxError::Poisoned));
    }

    #[test]
    fn an_empty_compressed_segment_decodes_to_nothing() {
        // FreeRDP refuses this (`segmentSize < 2`); accepting it costs nothing.
        let mut z = Zgfx::new();
        assert_eq!(z.decompress(&[0xE0, 0x24]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decompress_into_clears_and_reuses_the_buffer() {
        let mut z = Zgfx::new();
        let mut buf = vec![0xAA; 7]; // stale content from a previous message
        z.decompress_into(&[0xE0, 0x04, 1, 2], &mut buf).unwrap();
        assert_eq!(buf, vec![1, 2]);
        z.decompress_into(&[0xE0, 0x04, 3], &mut buf).unwrap();
        assert_eq!(buf, vec![3]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property, which zgfx did not have
        // until #189: the bootstrap wrapper panicked on five of seven hand-crafted messages
        // (`mid > len`, `attempt to subtract with overflow`, `index 8 out of range`), and the
        // panic reached `justrdp::egfx::GraphicsProcessor::process` — the live path, because
        // this decompressor sees every EGFX byte before the PDU parser does. Reaching the end
        // without unwinding IS the assertion; proptest shrinks to a minimal counterexample on
        // any panic, arithmetic overflow or OOB.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decompress_never_panics_on_arbitrary_input(
            data in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = Zgfx::new().decompress(&data);
        }
    }

    proptest! {
        // The same property, *directed*. Two bytes of the message are a descriptor and a
        // compression-type nibble, so only 1 in 2048 undirected inputs reaches the token
        // decoder at all — the shape #200 measured for the connect-sequence parsers and had to
        // seed around for Progressive. Prefixing a valid single compressed-segment header
        // spends the whole budget on the bitstream instead of on the wrapper.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn a_compressed_segment_body_never_panics(
            body in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let mut message = vec![0xE0, 0x24];
            message.extend_from_slice(&body);
            let _ = Zgfx::new().decompress(&message);
        }
    }

    proptest! {
        // And directed at multipart framing, whose segment-size loop is the one field where a
        // `u32` indexes into the buffer — the bootstrap wrapper's `split_at` panic (probe A).
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn a_multipart_body_never_panics(
            body in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let mut message = vec![0xE1];
            message.extend_from_slice(&body);
            let _ = Zgfx::new().decompress(&message);
        }
    }
}

#![forbid(unsafe_code)]

//! RLGR (Run-Length Golomb-Rice) entropy codec (MS-RDPRFX §3.1.8.1.7).
//!
//! Supports RLGR1 and RLGR3 modes for RemoteFX coefficient encoding/decoding.

use alloc::vec::Vec;
use core::fmt;

// ── Constants (MS-RDPRFX §3.1.8.1.7.3) ──

const KPMAX: i32 = 80;
const LSGR: i32 = 3;
const UP_GR: i32 = 4;
const DN_GR: i32 = 6;
const UQ_GR: i32 = 3;
const DQ_GR: i32 = 3;

/// RLGR mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlgrMode {
    /// RLGR1: one value per GR code in GR mode.
    Rlgr1,
    /// RLGR3: two values per GR code in GR mode.
    Rlgr3,
}

/// RLGR decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlgrError {
    /// Bitstream ended unexpectedly.
    TruncatedBitstream,
}

impl fmt::Display for RlgrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RLGR: truncated bitstream")
    }
}

// ── Bit reader (MSB-first) ──

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0-7, 0 = MSB
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    #[inline]
    fn bits_remaining(&self) -> usize {
        if self.byte_pos >= self.data.len() {
            return 0;
        }
        (self.data.len() - self.byte_pos) * 8 - self.bit_pos as usize
    }

    /// Read a single bit. Returns 0 or 1.
    #[inline]
    fn read_bit(&mut self) -> u32 {
        if self.byte_pos >= self.data.len() {
            return 0;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos >= 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        u32::from(bit)
    }

    /// Read `n` bits (MSB-first). Max 32 bits.
    fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let mut result = 0u32;
        for _ in 0..n {
            result = (result << 1) | self.read_bit();
        }
        result
    }
}

// ── Helper functions ──

/// Update adaptive parameter: add delta, clamp to [0, KPMAX], return param >> LSGR.
#[inline]
fn update_param(param: &mut i32, delta: i32) -> i32 {
    *param += delta;
    if *param > KPMAX {
        *param = KPMAX;
    }
    if *param < 0 {
        *param = 0;
    }
    *param >> LSGR
}

/// Convert 2*|x| - sign(x) representation to signed integer.
/// If twoMs is odd → negative: -(twoMs + 1) / 2
/// If twoMs is even → non-negative: twoMs / 2
#[inline]
fn get_int_from_2mag_sign(two_ms: u32) -> i16 {
    if two_ms & 1 != 0 {
        -(((two_ms + 1) >> 1) as i16)
    } else {
        (two_ms >> 1) as i16
    }
}

/// Minimum bits to represent val: ceil(log2(val + 1)).
#[inline]
fn get_min_bits(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    32 - val.leading_zeros()
}

// ── RLGR Decoder ──

/// RLGR entropy decoder (MS-RDPRFX §3.1.8.1.7.3).
#[derive(Debug, Clone)]
pub struct RlgrDecoder {
    mode: RlgrMode,
}

impl RlgrDecoder {
    /// Create a new RLGR decoder.
    pub fn new(mode: RlgrMode) -> Self {
        Self { mode }
    }

    /// Decode RLGR-encoded data into signed coefficients.
    ///
    /// # Arguments
    ///
    /// * `data` - RLGR-encoded byte stream
    /// * `num_values` - Number of values to decode (typically 4096)
    pub fn decode(&self, data: &[u8], num_values: usize) -> Result<Vec<i16>, RlgrError> {
        let mut reader = BitReader::new(data);
        let mut output = Vec::with_capacity(num_values);

        // Initialize state
        let mut kp: i32 = 1 << LSGR; // kp = 8
        let mut krp: i32 = 1 << LSGR; // krp = 8

        while output.len() < num_values {
            let k = kp >> LSGR;

            if k > 0 {
                // RL (Run-Length) mode
                self.decode_rl_mode(&mut reader, &mut output, &mut kp, &mut krp, k, num_values);
            } else {
                // GR (Golomb-Rice) mode
                self.decode_gr_mode(&mut reader, &mut output, &mut kp, &mut krp, num_values);
            }
        }

        output.truncate(num_values);
        Ok(output)
    }

    /// RL mode: decode zero runs followed by a nonzero value.
    fn decode_rl_mode(
        &self,
        reader: &mut BitReader<'_>,
        output: &mut Vec<i16>,
        kp: &mut i32,
        krp: &mut i32,
        mut k: i32,
        max_values: usize,
    ) {
        // Count zero runs: while next bit is 0, emit (1 << k) zeros
        while reader.bits_remaining() > 0 && output.len() < max_values {
            let bit = reader.read_bit();
            if bit == 0 {
                // Emit 1 << k zeros
                let count = core::cmp::min(1usize << k, max_values - output.len());
                for _ in 0..count {
                    output.push(0);
                }
                k = update_param(kp, UP_GR);
            } else {
                // Terminator bit = 1
                break;
            }
        }

        if output.len() >= max_values {
            return;
        }

        // Read k bits as the remaining run of zeros
        let run = reader.read_bits(k as u32) as usize;
        let count = core::cmp::min(run, max_values - output.len());
        for _ in 0..count {
            output.push(0);
        }

        if output.len() >= max_values {
            return;
        }

        // Decode one nonzero value via GetIntFrom2MagSign(GRCode + 1)
        // (MS-RDPRFX §3.1.8.1.7.3: the nonzero value uses 2MagSign encoding)
        let gr_code = self.decode_gr_code(reader, krp);
        let two_ms = gr_code + 1;
        let value = get_int_from_2mag_sign(two_ms);
        output.push(value);

        // Update kp
        update_param(kp, -DN_GR);
    }

    /// GR mode: decode value(s) using Golomb-Rice coding.
    fn decode_gr_mode(
        &self,
        reader: &mut BitReader<'_>,
        output: &mut Vec<i16>,
        kp: &mut i32,
        krp: &mut i32,
        max_values: usize,
    ) {
        if output.len() >= max_values {
            return;
        }

        let mag = self.decode_gr_code(reader, krp);

        match self.mode {
            RlgrMode::Rlgr1 => {
                let value = get_int_from_2mag_sign(mag);
                output.push(value);

                if mag == 0 {
                    update_param(kp, UQ_GR);
                } else {
                    update_param(kp, -DQ_GR);
                }
            }
            RlgrMode::Rlgr3 => {
                let n_idx = get_min_bits(mag);
                let val1 = reader.read_bits(n_idx);
                let val2 = mag - val1;

                output.push(get_int_from_2mag_sign(val1));
                if output.len() < max_values {
                    output.push(get_int_from_2mag_sign(val2));
                }

                if val1 != 0 && val2 != 0 {
                    update_param(kp, -2 * DQ_GR);
                } else if val1 == 0 && val2 == 0 {
                    update_param(kp, 2 * UQ_GR);
                }
                // Mixed: no update
            }
        }
    }

    /// Decode a Golomb-Rice code: count leading 0-bits (vk), then read kr bits.
    /// (MS-RDPRFX §3.1.8.1.7.3: leading 0-bits terminated by a 1-bit.)
    fn decode_gr_code(&self, reader: &mut BitReader<'_>, krp: &mut i32) -> u32 {
        let kr = (*krp >> LSGR) as u32;

        // Count leading 0-bits (terminated by a 1-bit)
        let mut vk: u32 = 0;
        while reader.bits_remaining() > 0 {
            let bit = reader.read_bit();
            if bit == 0 {
                vk += 1;
            } else {
                break; // 1-bit terminates
            }
        }

        // Read kr bits as remainder
        let remainder = reader.read_bits(kr);
        let mag = (vk << kr) | remainder;

        // Update krp (MS-RDPRFX §3.1.8.1.7.3)
        if vk == 0 {
            update_param(krp, -2);
        } else if vk > 1 {
            update_param(krp, (vk as i32) - 1); // increase by vk-1, not vk
        }
        // vk == 1: no change

        mag
    }
}

// ── Bit writer (MSB-first) ──

struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bit_pos: u8, // 0-7, how many bits written in current_byte (from MSB)
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    /// Write a single bit (0 or 1).
    #[inline]
    fn write_bit(&mut self, bit: u32) {
        self.current_byte |= ((bit & 1) as u8) << (7 - self.bit_pos);
        self.bit_pos += 1;
        if self.bit_pos >= 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }

    /// Write `n` bits from `value` (MSB-first).
    fn write_bits(&mut self, n: u32, value: u32) {
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1);
        }
    }

    /// Flush any remaining bits (pad with zeros) and return the byte vector.
    fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.data.push(self.current_byte);
        }
        self.data
    }
}

// ── Helper: Convert signed integer to 2*|x| - sign(x) ──

/// Convert a signed integer to 2MagSign representation.
/// `Get2MagSign(x) = 2*|x| - (x < 0 ? 1 : 0)`
#[inline]
fn get_2mag_sign(x: i16) -> u32 {
    if x >= 0 {
        (x as u32) * 2
    } else {
        ((-x) as u32) * 2 - 1
    }
}

// ── RLGR Encoder ──

/// RLGR entropy encoder (MS-RDPRFX §3.1.8.1.7.3).
#[derive(Debug, Clone)]
pub struct RlgrEncoder {
    mode: RlgrMode,
}

impl RlgrEncoder {
    /// Create a new RLGR encoder.
    pub fn new(mode: RlgrMode) -> Self {
        Self { mode }
    }

    /// Encode signed coefficients into an RLGR bitstream.
    pub fn encode(&self, values: &[i16]) -> Vec<u8> {
        let mut writer = BitWriter::new();
        let mut kp: i32 = 1 << LSGR; // kp = 8
        let mut krp: i32 = 1 << LSGR; // krp = 8
        let mut pos = 0;

        while pos < values.len() {
            let k = kp >> LSGR;

            if k > 0 {
                // RL mode
                pos = self.encode_rl_mode(&mut writer, values, pos, &mut kp, &mut krp, k);
            } else {
                // GR mode
                pos = self.encode_gr_mode(&mut writer, values, pos, &mut kp, &mut krp);
            }
        }

        writer.finish()
    }

    /// RL mode: encode zero runs followed by a nonzero value.
    fn encode_rl_mode(
        &self,
        writer: &mut BitWriter,
        values: &[i16],
        mut pos: usize,
        kp: &mut i32,
        krp: &mut i32,
        mut k: i32,
    ) -> usize {
        // Count leading zeros
        let mut num_zeros = 0usize;
        while pos + num_zeros < values.len() && values[pos + num_zeros] == 0 {
            num_zeros += 1;
        }

        let mut zeros_remaining = num_zeros;

        // Emit full zero runs: each 0-bit represents (1 << k) zeros
        while zeros_remaining >= (1usize << k) {
            writer.write_bit(0); // 0-bit = (1 << k) zeros
            zeros_remaining -= 1 << k;
            k = update_param(kp, UP_GR);
        }

        // Emit terminator 1-bit + remaining zeros in k bits
        writer.write_bit(1);
        writer.write_bits(k as u32, zeros_remaining as u32);

        pos += num_zeros;

        if pos >= values.len() {
            return pos;
        }

        // Encode the nonzero value using 2MagSign via GR code
        let val = values[pos];
        let two_ms = get_2mag_sign(val);
        // The nonzero value is encoded as GRCode(two_ms - 1), then decoded as GetIntFrom2MagSign(GRCode + 1)
        self.encode_gr_code(writer, krp, two_ms - 1);
        pos += 1;

        update_param(kp, -DN_GR);
        pos
    }

    /// GR mode: encode value(s) using Golomb-Rice coding.
    fn encode_gr_mode(
        &self,
        writer: &mut BitWriter,
        values: &[i16],
        mut pos: usize,
        kp: &mut i32,
        krp: &mut i32,
    ) -> usize {
        match self.mode {
            RlgrMode::Rlgr1 => {
                let val = values[pos];
                let two_ms = get_2mag_sign(val);
                self.encode_gr_code(writer, krp, two_ms);

                if two_ms == 0 {
                    update_param(kp, UQ_GR);
                } else {
                    update_param(kp, -DQ_GR);
                }
                pos += 1;
            }
            RlgrMode::Rlgr3 => {
                let val1 = values[pos];
                let val2 = if pos + 1 < values.len() { values[pos + 1] } else { 0 };

                let two_ms1 = get_2mag_sign(val1);
                let two_ms2 = get_2mag_sign(val2);
                let sum = two_ms1 + two_ms2;

                // Encode sum via GR code
                self.encode_gr_code(writer, krp, sum);

                // Encode val1 in GetMinBits(sum) bits
                let n_idx = get_min_bits(sum);
                writer.write_bits(n_idx, two_ms1);

                // Update kp
                if two_ms1 != 0 && two_ms2 != 0 {
                    update_param(kp, -2 * DQ_GR);
                } else if two_ms1 == 0 && two_ms2 == 0 {
                    update_param(kp, 2 * UQ_GR);
                }
                // Mixed: no update

                pos += 2;
            }
        }
        pos
    }

    /// Encode a Golomb-Rice code: emit vk 0-bits, one 1-bit, then kr remainder bits.
    fn encode_gr_code(&self, writer: &mut BitWriter, krp: &mut i32, val: u32) {
        let kr = (*krp >> LSGR) as u32;

        let vk = val >> kr; // unary part
        let remainder = val & ((1u32 << kr).wrapping_sub(1)); // lower kr bits

        // Emit vk 0-bits + one 1-bit
        for _ in 0..vk {
            writer.write_bit(0);
        }
        writer.write_bit(1);

        // Emit kr remainder bits
        if kr > 0 {
            writer.write_bits(kr, remainder);
        }

        // Update krp (same rule as decoder)
        if vk == 0 {
            update_param(krp, -2);
        } else if vk > 1 {
            update_param(krp, (vk as i32) - 1);
        }
        // vk == 1: no change
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn get_min_bits_values() {
        assert_eq!(get_min_bits(0), 0);
        assert_eq!(get_min_bits(1), 1);
        assert_eq!(get_min_bits(2), 2);
        assert_eq!(get_min_bits(3), 2);
        assert_eq!(get_min_bits(4), 3);
        assert_eq!(get_min_bits(7), 3);
        assert_eq!(get_min_bits(8), 4);
        assert_eq!(get_min_bits(255), 8);
    }

    #[test]
    fn int_from_2mag_sign() {
        assert_eq!(get_int_from_2mag_sign(0), 0);   // even → +0
        assert_eq!(get_int_from_2mag_sign(1), -1);  // odd → -(1+1)/2 = -1
        assert_eq!(get_int_from_2mag_sign(2), 1);   // even → 2/2 = 1
        assert_eq!(get_int_from_2mag_sign(3), -2);  // odd → -(3+1)/2 = -2
        assert_eq!(get_int_from_2mag_sign(4), 2);
        assert_eq!(get_int_from_2mag_sign(5), -3);
    }

    #[test]
    fn update_param_clamp_upper() {
        let mut param = 78;
        let k = update_param(&mut param, 4);
        assert_eq!(param, KPMAX); // 78+4=82 → clamped to 80
        assert_eq!(k, KPMAX >> LSGR);
    }

    #[test]
    fn update_param_clamp_lower() {
        let mut param = 2;
        let k = update_param(&mut param, -6);
        assert_eq!(param, 0); // 2-6=-4 → clamped to 0
        assert_eq!(k, 0);
    }

    #[test]
    fn bit_reader_msb_first() {
        let data = [0b10110100, 0b11000000];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bit(), 1);
        assert_eq!(reader.read_bit(), 0);
        assert_eq!(reader.read_bit(), 1);
        assert_eq!(reader.read_bit(), 1);
        assert_eq!(reader.read_bit(), 0);
        assert_eq!(reader.read_bit(), 1);
        assert_eq!(reader.read_bit(), 0);
        assert_eq!(reader.read_bit(), 0);
        // Next byte
        assert_eq!(reader.read_bit(), 1);
        assert_eq!(reader.read_bit(), 1);
    }

    #[test]
    fn bit_reader_read_bits() {
        let data = [0b10110100];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(4), 0b1011);
        assert_eq!(reader.read_bits(4), 0b0100);
    }

    #[test]
    fn bit_reader_read_zero_bits() {
        let data = [0xFF];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(0), 0);
        assert_eq!(reader.bits_remaining(), 8);
    }

    #[test]
    fn rlgr1_decode_all_zeros() {
        // Encode 4 zeros in RLGR1: initial k=1.
        // RL mode: bit 0 → emit 2 zeros, k updates.
        // Then bit 1 (terminator), read k bits for remaining run, then a nonzero...
        // Actually, let's test with a known simple pattern.
        // 4 zeros: RL mode, k=1. To emit 4 zeros:
        //   bit=0 → emit 2 zeros (1<<1=2), k update → k may increase
        //   bit=0 → emit more zeros...
        // This is complex to hand-craft. Test via roundtrip instead.
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr1);
        // A stream of all-zero bits in RL mode should produce zeros
        let data = vec![0x00; 16]; // lots of zero bits
        let result = decoder.decode(&data, 8).unwrap();
        assert_eq!(result.len(), 8);
        // All should be zeros (RL mode emits zeros for 0-bits)
        for &v in &result {
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn rlgr3_decode_all_zeros() {
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr3);
        let data = vec![0x00; 16];
        let result = decoder.decode(&data, 8).unwrap();
        assert_eq!(result.len(), 8);
        for &v in &result {
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn rlgr1_decode_output_length() {
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr1);
        let data = vec![0x00; 512];
        let result = decoder.decode(&data, 4096).unwrap();
        assert_eq!(result.len(), 4096);
    }

    #[test]
    fn rlgr3_decode_output_length() {
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr3);
        let data = vec![0x00; 512];
        let result = decoder.decode(&data, 4096).unwrap();
        assert_eq!(result.len(), 4096);
    }

    // ── Encoder tests ──

    #[test]
    fn get_2mag_sign_values() {
        assert_eq!(get_2mag_sign(0), 0);
        assert_eq!(get_2mag_sign(1), 2);
        assert_eq!(get_2mag_sign(-1), 1);
        assert_eq!(get_2mag_sign(2), 4);
        assert_eq!(get_2mag_sign(-2), 3);
        assert_eq!(get_2mag_sign(3), 6);
        assert_eq!(get_2mag_sign(-3), 5);
    }

    #[test]
    fn two_mag_sign_roundtrip() {
        for val in -100..=100i16 {
            let two_ms = get_2mag_sign(val);
            let back = get_int_from_2mag_sign(two_ms);
            assert_eq!(back, val, "2MagSign roundtrip failed for {val}");
        }
    }

    #[test]
    fn bit_writer_basic() {
        let mut writer = BitWriter::new();
        writer.write_bit(1);
        writer.write_bit(0);
        writer.write_bit(1);
        writer.write_bit(1);
        writer.write_bit(0);
        writer.write_bit(1);
        writer.write_bit(0);
        writer.write_bit(0);
        let data = writer.finish();
        assert_eq!(data, vec![0b10110100]);
    }

    #[test]
    fn bit_writer_write_bits() {
        let mut writer = BitWriter::new();
        writer.write_bits(4, 0b1011);
        writer.write_bits(4, 0b0100);
        let data = writer.finish();
        assert_eq!(data, vec![0b10110100]);
    }

    #[test]
    fn rlgr1_encode_decode_roundtrip_simple() {
        let input: Vec<i16> = vec![0, 0, 0, 5, 0, 0, -3, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let encoder = RlgrEncoder::new(RlgrMode::Rlgr1);
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr1);
        let encoded = encoder.encode(&input);
        let decoded = decoder.decode(&encoded, input.len()).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn rlgr3_encode_decode_roundtrip_simple() {
        let input: Vec<i16> = vec![0, 0, 0, 5, 0, 0, -3, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let encoder = RlgrEncoder::new(RlgrMode::Rlgr3);
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr3);
        let encoded = encoder.encode(&input);
        let decoded = decoder.decode(&encoded, input.len()).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn rlgr1_encode_decode_roundtrip_4096_zeros() {
        let input = vec![0i16; 4096];
        let encoder = RlgrEncoder::new(RlgrMode::Rlgr1);
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr1);
        let encoded = encoder.encode(&input);
        let decoded = decoder.decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn rlgr3_encode_decode_roundtrip_4096_zeros() {
        let input = vec![0i16; 4096];
        let encoder = RlgrEncoder::new(RlgrMode::Rlgr3);
        let decoder = RlgrDecoder::new(RlgrMode::Rlgr3);
        let encoded = encoder.encode(&input);
        let decoded = decoder.decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn rlgr1_encode_decode_single_nonzero() {
        for val in [-100i16, -1, 1, 50, 127] {
            let input = vec![val];
            let encoder = RlgrEncoder::new(RlgrMode::Rlgr1);
            let decoder = RlgrDecoder::new(RlgrMode::Rlgr1);
            let encoded = encoder.encode(&input);
            let decoded = decoder.decode(&encoded, 1).unwrap();
            assert_eq!(decoded, input, "RLGR1 single value {val} failed");
        }
    }

    #[test]
    fn rlgr3_encode_decode_single_nonzero() {
        for val in [-100i16, -1, 1, 50, 127] {
            let input = vec![val, 0]; // RLGR3 pairs
            let encoder = RlgrEncoder::new(RlgrMode::Rlgr3);
            let decoder = RlgrDecoder::new(RlgrMode::Rlgr3);
            let encoded = encoder.encode(&input);
            let decoded = decoder.decode(&encoded, 2).unwrap();
            assert_eq!(decoded, input, "RLGR3 value {val} failed");
        }
    }
}

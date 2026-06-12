//! RLGR entropy decoder (MS-RDPRFX 3.1.8.1.7) — Run-Length / Golomb-Rice coding of one
//! RemoteFX tile component into its 4096 DWT coefficients. Self-owned (ADR-0003 phase-2);
//! byte-equivalence with the `ironrdp-graphics` `rlgr` primitive is proven by the ADR-0007
//! stage-boundary differential tests, for both RLGR1 and RLGR3.
//!
//! The coder is adaptive: `k` (run-length mode selector / zero-run exponent) and `kr`
//! (Golomb-Rice remainder width) evolve per decoded symbol through their scaled shadows
//! `kp`/`krp`. A truncated bitstream is not an error — decoding stops and the remaining
//! coefficients are zero (the spec's implicit-tail behavior); only a value that cannot fit a
//! 16-bit coefficient is a typed error.

use justrdp_pdu::rfx::EntropyAlgorithm;

/// Why an RLGR component stream failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlgrError {
    /// The component data is empty — a tile always codes at least one symbol.
    EmptyInput,
    /// A decoded magnitude exceeds the 16-bit coefficient range (malformed stream).
    ValueOverflow,
}

impl core::fmt::Display for RlgrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RlgrError::EmptyInput => write!(f, "empty RLGR component data"),
            RlgrError::ValueOverflow => write!(f, "RLGR magnitude exceeds i16"),
        }
    }
}

impl core::error::Error for RlgrError {}

const KP_MAX: u32 = 80;
const LS_GR: u32 = 3;
const UP_GR: u32 = 4;
const DN_GR: u32 = 6;
const UQ_GR: u32 = 3;
const DQ_GR: u32 = 3;

/// An MSB-first bit cursor over the component data.
struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position.
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    fn bit_at(&self, pos: usize) -> bool {
        let byte = self.data[pos / 8];
        (byte >> (7 - (pos % 8))) & 1 != 0
    }

    /// Read `n` bits (n ≤ 32) big-endian, or `None` if fewer remain. `n == 0` reads nothing.
    fn read_bits(&mut self, n: usize) -> Option<u32> {
        if self.remaining() < n {
            return None;
        }
        let mut acc: u32 = 0;
        for _ in 0..n {
            acc = (acc << 1) | u32::from(self.bit_at(self.pos));
            self.pos += 1;
        }
        Some(acc)
    }

    /// Count and consume the run of bits equal to `value`, stopping at the stream end.
    fn count_leading(&mut self, value: bool) -> usize {
        let start = self.pos;
        while self.pos < self.data.len() * 8 && self.bit_at(self.pos) == value {
            self.pos += 1;
        }
        self.pos - start
    }
}

/// Map a 2·|magnitude|−sign Golomb-Rice value back to its signed coefficient
/// (odd = negative, even = positive).
fn unfold_magnitude(val: u32) -> Result<i16, RlgrError> {
    if val % 2 == 1 {
        i16::try_from((val + 1) >> 1)
            .map(|v| -v)
            .map_err(|_| RlgrError::ValueOverflow)
    } else {
        i16::try_from(val >> 1).map_err(|_| RlgrError::ValueOverflow)
    }
}

/// Decode one RLGR-coded component stream into `output` coefficients. The stream ending
/// mid-symbol leaves the remaining coefficients zero (never an error); see the module docs.
pub fn decode(mode: EntropyAlgorithm, input: &[u8], output: &mut [i16]) -> Result<(), RlgrError> {
    if input.is_empty() {
        return Err(RlgrError::EmptyInput);
    }

    let mut k: u32 = 1;
    let mut kr: u32 = 1;
    let mut kp: u32 = k << LS_GR;
    let mut krp: u32 = kr << LS_GR;

    let mut bits = BitReader::new(input);
    let mut out = 0usize;

    'symbols: while bits.remaining() > 0 && out < output.len() {
        if k != 0 {
            // Run-length mode: a unary run multiplier, a `k`-bit run remainder, then one
            // sign bit and the GR-coded (magnitude − 1) of the value that ended the run.
            let zeros = bits.count_leading(false);
            if bits.read_bits(1).is_none() {
                break 'symbols;
            }
            let mut run: u32 = 0;
            for _ in 0..zeros {
                run += 1 << k;
                kp = (kp + UP_GR).min(KP_MAX);
                k = kp >> LS_GR;
            }
            let Some(extra) = bits.read_bits(k as usize) else {
                break 'symbols;
            };
            run += extra;

            let Some(sign) = bits.read_bits(1) else {
                break 'symbols;
            };

            let ones = bits.count_leading(true);
            if bits.read_bits(1).is_none() {
                break 'symbols;
            }
            let Some(rem) = bits.read_bits(kr as usize) else {
                break 'symbols;
            };
            let code = rem + ((ones as u32) << kr);

            adapt_kr(ones, &mut kr, &mut krp);
            kp = kp.saturating_sub(DN_GR);
            k = kp >> LS_GR;

            let magnitude = i16::try_from(code + 1).map_err(|_| RlgrError::ValueOverflow)?;
            let magnitude = if sign != 0 { -magnitude } else { magnitude };

            let size = (run as usize).min(output.len() - out);
            output[out..out + size].fill(0);
            out += size;
            if out >= output.len() {
                break 'symbols;
            }
            output[out] = magnitude;
            out += 1;
        } else {
            // Golomb-Rice mode: a unary prefix plus `kr` remainder bits code one value
            // (RLGR1) or the sum of two values, the first re-read explicitly (RLGR3).
            let ones = bits.count_leading(true);
            if bits.read_bits(1).is_none() {
                break 'symbols;
            }
            let Some(rem) = bits.read_bits(kr as usize) else {
                break 'symbols;
            };
            let code = rem + ((ones as u32) << kr);

            adapt_kr(ones, &mut kr, &mut krp);

            match mode {
                EntropyAlgorithm::Rlgr1 => {
                    let value = if code == 0 {
                        kp = (kp + UQ_GR).min(KP_MAX);
                        k = kp >> LS_GR;
                        0
                    } else {
                        kp = kp.saturating_sub(DQ_GR);
                        k = kp >> LS_GR;
                        unfold_magnitude(code)?
                    };
                    output[out] = value;
                    out += 1;
                }
                EntropyAlgorithm::Rlgr3 => {
                    let n = if code == 0 {
                        0
                    } else {
                        (32 - code.leading_zeros()) as usize
                    };
                    let Some(val1) = bits.read_bits(n) else {
                        break 'symbols;
                    };
                    // A malformed stream can claim val1 > code; the oracle wraps here, we
                    // reject — the differential only compares streams both sides accept.
                    let val2 = code.checked_sub(val1).ok_or(RlgrError::ValueOverflow)?;

                    if val1 != 0 && val2 != 0 {
                        kp = kp.saturating_sub(2 * DQ_GR);
                        k = kp >> LS_GR;
                    } else if val1 == 0 && val2 == 0 {
                        kp = (kp + 2 * UQ_GR).min(KP_MAX);
                        k = kp >> LS_GR;
                    }

                    output[out] = unfold_magnitude(val1)?;
                    out += 1;
                    if out >= output.len() {
                        break 'symbols;
                    }
                    output[out] = unfold_magnitude(val2)?;
                    out += 1;
                }
            }
        }
    }

    output[out..].fill(0);
    Ok(())
}

/// Golomb-Rice parameter adaptation shared by every GR-coded value (3.1.8.1.7.2): a
/// zero-prefix shrinks `kr`, a multi-bit prefix grows it, a single `1` leaves it unchanged.
fn adapt_kr(ones: usize, kr: &mut u32, krp: &mut u32) {
    if ones == 0 {
        *krp = krp.saturating_sub(2);
        *kr = *krp >> LS_GR;
    } else if ones > 1 {
        *krp = (*krp + ones as u32).min(KP_MAX);
        *kr = *krp >> LS_GR;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_a_typed_error() {
        let mut out = [0i16; 16];
        assert_eq!(
            decode(EntropyAlgorithm::Rlgr1, &[], &mut out),
            Err(RlgrError::EmptyInput)
        );
    }

    #[test]
    fn truncated_streams_zero_fill_instead_of_erroring() {
        // A single 0xFF byte: in RL mode (k=1 initially) these are leading ones... the
        // initial mode is run-length (k=1), so 0xFF = no zeros, terminator '1', then run
        // bits etc. — whatever the cut, the decoder must end cleanly with zeros.
        let mut out = [7i16; 32];
        decode(EntropyAlgorithm::Rlgr1, &[0xFF], &mut out).expect("truncation is not an error");
        // Tail is zero-filled (the exact prefix depends on where the stream cut).
        assert!(out.iter().rev().take(16).all(|&v| v == 0));
    }

    #[test]
    fn all_zero_bits_decode_to_zero_runs() {
        let mut out = [9i16; 64];
        decode(EntropyAlgorithm::Rlgr3, &[0x00; 8], &mut out).expect("zero runs decode");
        assert!(out.iter().all(|&v| v == 0));
    }
}

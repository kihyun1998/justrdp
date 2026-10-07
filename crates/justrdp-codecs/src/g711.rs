//! G.711 A-law (`WAVE_FORMAT_ALAW`, ITU-T G.711) to signed 16-bit samples. Each byte is one
//! sample: its even bits are inverted on the wire, its top bit is the sign, the next three the
//! segment and the low four the step within it. The 13-bit G.711 value is scaled to 16 bits.

/// The 16-bit sample one A-law byte stands for.
pub fn alaw_to_i16(code: u8) -> i16 {
    let code = code ^ 0x55;
    let step = i16::from(code & 0x0F) << 4;
    let magnitude = match (code & 0x70) >> 4 {
        0 => step + 8,
        1 => step + 0x108,
        segment => (step + 0x108) << (segment - 1),
    };
    if code & 0x80 != 0 {
        magnitude
    } else {
        -magnitude
    }
}

/// Convert A-law `data`, one sample per byte, to signed 16-bit samples in the same order.
pub fn decode_alaw(data: &[u8]) -> Vec<i16> {
    data.iter().map(|&code| alaw_to_i16(code)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every A-law code decoded by CPython 3.12's `audioop.alaw2lin(bytes([code]), 2)`, an
    /// implementation independent of this one (#388). It is the oracle because ITU-T G.711's
    /// Table 1a is drawn in the published PDF rather than set as text, so it could not be read
    /// mechanically; its extremes are 4,032 and 1 in G.711's 13-bit units, 32,256 and 8 here.
    const AUDIOOP_ALAW: [i16; 256] = [
        -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736, -7552, -7296, -8064, -7808, -6528,
        -6272, -7040, -6784, -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368, -3776, -3648,
        -4032, -3904, -3264, -3136, -3520, -3392, -22016, -20992, -24064, -23040, -17920, -16896,
        -19968, -18944, -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136, -11008,
        -10496, -12032, -11520, -8960, -8448, -9984, -9472, -15104, -14592, -16128, -15616, -13056,
        -12544, -14080, -13568, -344, -328, -376, -360, -280, -264, -312, -296, -472, -456, -504,
        -488, -408, -392, -440, -424, -88, -72, -120, -104, -24, -8, -56, -40, -216, -200, -248,
        -232, -152, -136, -184, -168, -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
        -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696, -688, -656, -752, -720, -560, -528,
        -624, -592, -944, -912, -1008, -976, -816, -784, -880, -848, 5504, 5248, 6016, 5760, 4480,
        4224, 4992, 4736, 7552, 7296, 8064, 7808, 6528, 6272, 7040, 6784, 2752, 2624, 3008, 2880,
        2240, 2112, 2496, 2368, 3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392, 22016, 20992,
        24064, 23040, 17920, 16896, 19968, 18944, 30208, 29184, 32256, 31232, 26112, 25088, 28160,
        27136, 11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472, 15104, 14592, 16128, 15616,
        13056, 12544, 14080, 13568, 344, 328, 376, 360, 280, 264, 312, 296, 472, 456, 504, 488,
        408, 392, 440, 424, 88, 72, 120, 104, 24, 8, 56, 40, 216, 200, 248, 232, 152, 136, 184,
        168, 1376, 1312, 1504, 1440, 1120, 1056, 1248, 1184, 1888, 1824, 2016, 1952, 1632, 1568,
        1760, 1696, 688, 656, 752, 720, 560, 528, 624, 592, 944, 912, 1008, 976, 816, 784, 880,
        848,
    ];

    #[test]
    fn every_code_matches_the_independent_decoder() {
        for code in 0..=255u8 {
            assert_eq!(
                alaw_to_i16(code),
                AUDIOOP_ALAW[usize::from(code)],
                "A-law code {code:#04x}"
            );
        }
    }

    /// The smallest magnitudes are the codes whose bits are all inverted away (0x55, 0xD5), and
    /// the largest the all-ones segment (0x2A, 0xAA).
    #[test]
    fn the_extremes_and_the_sign() {
        assert_eq!(
            decode_alaw(&[0xD5, 0x55, 0xAA, 0x2A]),
            [8, -8, 32256, -32256]
        );
    }
}

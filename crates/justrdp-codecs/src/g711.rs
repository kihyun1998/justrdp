//! G.711 A-law (`WAVE_FORMAT_ALAW`, ITU-T G.711) to and from signed 16-bit samples. Each byte is
//! one sample: its even bits are inverted on the wire, its top bit is the sign, the next three the
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

/// The A-law byte for one 16-bit sample: the sample's top 13 bits, quantised.
pub fn i16_to_alaw(sample: i16) -> u8 {
    let value = sample >> 3;
    let (sign, magnitude) = if value >= 0 {
        (0x80, value.unsigned_abs())
    } else {
        (0x00, (-1 - value).unsigned_abs())
    };
    let segment = (u16::BITS - magnitude.leading_zeros()).saturating_sub(5) as u8;
    let step = (magnitude >> segment.max(1)) as u8 & 0x0F;
    (sign | segment << 4 | step) ^ 0x55
}

/// Convert signed 16-bit `samples` to A-law, one byte per sample in the same order.
pub fn encode_alaw(samples: &[i16]) -> Vec<u8> {
    samples.iter().map(|&sample| i16_to_alaw(sample)).collect()
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

    /// Where each A-law code starts, in ascending 16-bit samples, from CPython 3.12's
    /// `audioop.lin2alaw` run over every 16-bit sample (#402), the independent encoder that
    /// produced [`AUDIOOP_ALAW`]. Each code covers one run of samples, up to where the next starts.
    const AUDIOOP_ALAW_FROM: [(i16, u8); 256] = [
        (-32768, 0x2A),
        (-31744, 0x2B),
        (-30720, 0x28),
        (-29696, 0x29),
        (-28672, 0x2E),
        (-27648, 0x2F),
        (-26624, 0x2C),
        (-25600, 0x2D),
        (-24576, 0x22),
        (-23552, 0x23),
        (-22528, 0x20),
        (-21504, 0x21),
        (-20480, 0x26),
        (-19456, 0x27),
        (-18432, 0x24),
        (-17408, 0x25),
        (-16384, 0x3A),
        (-15872, 0x3B),
        (-15360, 0x38),
        (-14848, 0x39),
        (-14336, 0x3E),
        (-13824, 0x3F),
        (-13312, 0x3C),
        (-12800, 0x3D),
        (-12288, 0x32),
        (-11776, 0x33),
        (-11264, 0x30),
        (-10752, 0x31),
        (-10240, 0x36),
        (-9728, 0x37),
        (-9216, 0x34),
        (-8704, 0x35),
        (-8192, 0x0A),
        (-7936, 0x0B),
        (-7680, 0x08),
        (-7424, 0x09),
        (-7168, 0x0E),
        (-6912, 0x0F),
        (-6656, 0x0C),
        (-6400, 0x0D),
        (-6144, 0x02),
        (-5888, 0x03),
        (-5632, 0x00),
        (-5376, 0x01),
        (-5120, 0x06),
        (-4864, 0x07),
        (-4608, 0x04),
        (-4352, 0x05),
        (-4096, 0x1A),
        (-3968, 0x1B),
        (-3840, 0x18),
        (-3712, 0x19),
        (-3584, 0x1E),
        (-3456, 0x1F),
        (-3328, 0x1C),
        (-3200, 0x1D),
        (-3072, 0x12),
        (-2944, 0x13),
        (-2816, 0x10),
        (-2688, 0x11),
        (-2560, 0x16),
        (-2432, 0x17),
        (-2304, 0x14),
        (-2176, 0x15),
        (-2048, 0x6A),
        (-1984, 0x6B),
        (-1920, 0x68),
        (-1856, 0x69),
        (-1792, 0x6E),
        (-1728, 0x6F),
        (-1664, 0x6C),
        (-1600, 0x6D),
        (-1536, 0x62),
        (-1472, 0x63),
        (-1408, 0x60),
        (-1344, 0x61),
        (-1280, 0x66),
        (-1216, 0x67),
        (-1152, 0x64),
        (-1088, 0x65),
        (-1024, 0x7A),
        (-992, 0x7B),
        (-960, 0x78),
        (-928, 0x79),
        (-896, 0x7E),
        (-864, 0x7F),
        (-832, 0x7C),
        (-800, 0x7D),
        (-768, 0x72),
        (-736, 0x73),
        (-704, 0x70),
        (-672, 0x71),
        (-640, 0x76),
        (-608, 0x77),
        (-576, 0x74),
        (-544, 0x75),
        (-512, 0x4A),
        (-496, 0x4B),
        (-480, 0x48),
        (-464, 0x49),
        (-448, 0x4E),
        (-432, 0x4F),
        (-416, 0x4C),
        (-400, 0x4D),
        (-384, 0x42),
        (-368, 0x43),
        (-352, 0x40),
        (-336, 0x41),
        (-320, 0x46),
        (-304, 0x47),
        (-288, 0x44),
        (-272, 0x45),
        (-256, 0x5A),
        (-240, 0x5B),
        (-224, 0x58),
        (-208, 0x59),
        (-192, 0x5E),
        (-176, 0x5F),
        (-160, 0x5C),
        (-144, 0x5D),
        (-128, 0x52),
        (-112, 0x53),
        (-96, 0x50),
        (-80, 0x51),
        (-64, 0x56),
        (-48, 0x57),
        (-32, 0x54),
        (-16, 0x55),
        (0, 0xD5),
        (16, 0xD4),
        (32, 0xD7),
        (48, 0xD6),
        (64, 0xD1),
        (80, 0xD0),
        (96, 0xD3),
        (112, 0xD2),
        (128, 0xDD),
        (144, 0xDC),
        (160, 0xDF),
        (176, 0xDE),
        (192, 0xD9),
        (208, 0xD8),
        (224, 0xDB),
        (240, 0xDA),
        (256, 0xC5),
        (272, 0xC4),
        (288, 0xC7),
        (304, 0xC6),
        (320, 0xC1),
        (336, 0xC0),
        (352, 0xC3),
        (368, 0xC2),
        (384, 0xCD),
        (400, 0xCC),
        (416, 0xCF),
        (432, 0xCE),
        (448, 0xC9),
        (464, 0xC8),
        (480, 0xCB),
        (496, 0xCA),
        (512, 0xF5),
        (544, 0xF4),
        (576, 0xF7),
        (608, 0xF6),
        (640, 0xF1),
        (672, 0xF0),
        (704, 0xF3),
        (736, 0xF2),
        (768, 0xFD),
        (800, 0xFC),
        (832, 0xFF),
        (864, 0xFE),
        (896, 0xF9),
        (928, 0xF8),
        (960, 0xFB),
        (992, 0xFA),
        (1024, 0xE5),
        (1088, 0xE4),
        (1152, 0xE7),
        (1216, 0xE6),
        (1280, 0xE1),
        (1344, 0xE0),
        (1408, 0xE3),
        (1472, 0xE2),
        (1536, 0xED),
        (1600, 0xEC),
        (1664, 0xEF),
        (1728, 0xEE),
        (1792, 0xE9),
        (1856, 0xE8),
        (1920, 0xEB),
        (1984, 0xEA),
        (2048, 0x95),
        (2176, 0x94),
        (2304, 0x97),
        (2432, 0x96),
        (2560, 0x91),
        (2688, 0x90),
        (2816, 0x93),
        (2944, 0x92),
        (3072, 0x9D),
        (3200, 0x9C),
        (3328, 0x9F),
        (3456, 0x9E),
        (3584, 0x99),
        (3712, 0x98),
        (3840, 0x9B),
        (3968, 0x9A),
        (4096, 0x85),
        (4352, 0x84),
        (4608, 0x87),
        (4864, 0x86),
        (5120, 0x81),
        (5376, 0x80),
        (5632, 0x83),
        (5888, 0x82),
        (6144, 0x8D),
        (6400, 0x8C),
        (6656, 0x8F),
        (6912, 0x8E),
        (7168, 0x89),
        (7424, 0x88),
        (7680, 0x8B),
        (7936, 0x8A),
        (8192, 0xB5),
        (8704, 0xB4),
        (9216, 0xB7),
        (9728, 0xB6),
        (10240, 0xB1),
        (10752, 0xB0),
        (11264, 0xB3),
        (11776, 0xB2),
        (12288, 0xBD),
        (12800, 0xBC),
        (13312, 0xBF),
        (13824, 0xBE),
        (14336, 0xB9),
        (14848, 0xB8),
        (15360, 0xBB),
        (15872, 0xBA),
        (16384, 0xA5),
        (17408, 0xA4),
        (18432, 0xA7),
        (19456, 0xA6),
        (20480, 0xA1),
        (21504, 0xA0),
        (22528, 0xA3),
        (23552, 0xA2),
        (24576, 0xAD),
        (25600, 0xAC),
        (26624, 0xAF),
        (27648, 0xAE),
        (28672, 0xA9),
        (29696, 0xA8),
        (30720, 0xAB),
        (31744, 0xAA),
    ];

    #[test]
    fn every_sample_encodes_as_the_independent_encoder_does() {
        for sample in i16::MIN..=i16::MAX {
            let at = AUDIOOP_ALAW_FROM.partition_point(|&(from, _)| from <= sample) - 1;
            assert_eq!(
                i16_to_alaw(sample),
                AUDIOOP_ALAW_FROM[at].1,
                "sample {sample}"
            );
        }
    }

    /// A decoded code is the middle of its step, so a sample comes back within half a step.
    #[test]
    fn every_sample_round_trips_within_half_a_step() {
        for sample in i16::MIN..=i16::MAX {
            let code = i16_to_alaw(sample);
            let segment = ((code ^ 0x55) >> 4) & 0x07;
            let step = 16 << segment.saturating_sub(1);
            let error = (i32::from(alaw_to_i16(code)) - i32::from(sample)).abs();
            assert!(
                error <= step / 2,
                "sample {sample}: code {code:#04x}, off by {error}"
            );
        }
    }

    #[test]
    fn samples_encode_in_order() {
        assert_eq!(
            encode_alaw(&[0, -1, 32767, -32768]),
            [0xD5, 0x55, 0xAA, 0x2A]
        );
    }
}

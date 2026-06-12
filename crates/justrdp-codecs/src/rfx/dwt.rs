//! RemoteFX inverse DWT (MS-RDPRFX 3.1.8.1.4) — the three-level 5/3 integer wavelet
//! reconstruction taking a tile component from its subband coefficients to pixel-domain
//! samples. Self-owned (ADR-0003 phase-2); equivalence with the `ironrdp-graphics` `dwt`
//! primitive is proven by the ADR-0007 stage-boundary tests.
//!
//! Each level reconstructs a `2sw × 2sw` block from four `sw × sw` subbands stored in
//! `HL LH HH LL` order: the horizontal pass combines `LL+HL → L` and `LH+HH → H` rows into
//! the scratch buffer, the vertical pass interleaves `L`/`H` back into the component buffer.
//! Level 3 (8→16) reconstructs in place over the `HL3..LL3` range, becoming the next level's
//! lowpass; then 16→32 and 32→64. Arithmetic is the spec's exact integer form (the odd-tap
//! `coefficient << 1` deliberately wraps in 16 bits, matching every interoperable decoder).

use super::quant::COMPONENT_LEN;

/// Reconstruct one 64×64 component in place. `temp` is caller-provided scratch (reused
/// across the three components of a tile to keep the hot path allocation-free).
pub fn decode(buffer: &mut [i16], temp: &mut [i16]) {
    debug_assert_eq!(buffer.len(), COMPONENT_LEN);
    debug_assert!(temp.len() >= COMPONENT_LEN);
    decode_level(&mut buffer[3840..], temp, 8);
    decode_level(&mut buffer[3072..], temp, 16);
    decode_level(buffer, temp, 32);
}

fn decode_level(buffer: &mut [i16], temp: &mut [i16], sw: usize) {
    inverse_horizontal(buffer, temp, sw);
    inverse_vertical(buffer, temp, sw);
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the 5/3 lifting taps truncate to 16 bits by definition"
)]
fn trunc16(value: i32) -> i16 {
    value as i16
}

/// Horizontal synthesis: `LL+HL` rows become the lowpass (`L`) half of `temp`, `LH+HH` rows
/// the highpass (`H`) half, each row widening `sw` to `2sw` samples.
fn inverse_horizontal(buffer: &[i16], temp: &mut [i16], sw: usize) {
    let tw = sw * 2;
    let ssw = sw * sw;
    let (hl, rest) = buffer.split_at(ssw);
    let (lh, rest) = rest.split_at(ssw);
    let (hh, ll) = rest.split_at(ssw);
    let (l_dst, h_dst) = temp.split_at_mut(2 * ssw);

    for r in 0..sw {
        let band = r * sw;
        let row = r * tw;
        // Even taps: low[2n] = ll[n] − ⌊(hl[n−1] + hl[n] + 1) / 2⌋, mirroring at the edge.
        for n in 0..sw {
            let prev = if n == 0 { n } else { n - 1 };
            l_dst[row + 2 * n] = trunc16(
                i32::from(ll[band + n])
                    - ((i32::from(hl[band + prev]) + i32::from(hl[band + n]) + 1) >> 1),
            );
            h_dst[row + 2 * n] = trunc16(
                i32::from(lh[band + n])
                    - ((i32::from(hh[band + prev]) + i32::from(hh[band + n]) + 1) >> 1),
            );
        }
        // Odd taps: low[2n+1] = 2·hl[n] + ⌊(low[2n] + low[2n+2]) / 2⌋, clamped at the edge.
        for n in 0..sw - 1 {
            let x = 2 * n;
            l_dst[row + x + 1] = trunc16(
                i32::from(hl[band + n] << 1)
                    + ((i32::from(l_dst[row + x]) + i32::from(l_dst[row + x + 2])) >> 1),
            );
            h_dst[row + x + 1] = trunc16(
                i32::from(hh[band + n] << 1)
                    + ((i32::from(h_dst[row + x]) + i32::from(h_dst[row + x + 2])) >> 1),
            );
        }
        l_dst[row + tw - 1] =
            trunc16(i32::from(hl[band + sw - 1] << 1) + i32::from(l_dst[row + tw - 2]));
        h_dst[row + tw - 1] =
            trunc16(i32::from(hh[band + sw - 1] << 1) + i32::from(h_dst[row + tw - 2]));
    }
}

/// Vertical synthesis: interleave the `L` rows (top half of `temp`) and `H` rows (bottom
/// half) column by column back into `buffer` as the reconstructed `2sw × 2sw` block.
fn inverse_vertical(buffer: &mut [i16], temp: &[i16], sw: usize) {
    let tw = sw * 2;
    let (l_src, h_src) = temp[..2 * tw * sw].split_at(tw * sw);

    for x in 0..tw {
        // Even rows: out[2n] = l[n] − ⌊(h[n−1] + h[n] + 1) / 2⌋, mirroring at the top edge.
        buffer[x] = trunc16(i32::from(l_src[x]) - ((i32::from(h_src[x]) * 2 + 1) >> 1));
        for n in 1..sw {
            buffer[2 * n * tw + x] = trunc16(
                i32::from(l_src[n * tw + x])
                    - ((i32::from(h_src[(n - 1) * tw + x]) + i32::from(h_src[n * tw + x]) + 1)
                        >> 1),
            );
        }
        // Odd rows: out[2n+1] = 2·h[n] + ⌊(out[2n] + out[2n+2]) / 2⌋, clamped at the bottom.
        for n in 1..sw {
            buffer[(2 * n - 1) * tw + x] = trunc16(
                i32::from(h_src[(n - 1) * tw + x] << 1)
                    + ((i32::from(buffer[(2 * n - 2) * tw + x])
                        + i32::from(buffer[2 * n * tw + x]))
                        >> 1),
            );
        }
        buffer[(tw - 1) * tw + x] = trunc16(
            i32::from(h_src[(sw - 1) * tw + x] << 1) + i32::from(buffer[(tw - 2) * tw + x]),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_all_zero_spectrum_reconstructs_to_an_all_zero_tile() {
        let mut buffer = vec![0i16; COMPONENT_LEN];
        let mut temp = vec![0i16; COMPONENT_LEN];
        decode(&mut buffer, &mut temp);
        assert!(buffer.iter().all(|&v| v == 0));
    }

    #[test]
    fn a_pure_dc_spectrum_reconstructs_to_a_flat_tile() {
        // Only LL3 carries energy: a constant lowpass must synthesize a constant tile
        // (the 5/3 highpass taps all see zero coefficients).
        let mut buffer = vec![0i16; COMPONENT_LEN];
        for v in &mut buffer[4032..] {
            *v = 100;
        }
        let mut temp = vec![0i16; COMPONENT_LEN];
        decode(&mut buffer, &mut temp);
        assert!(
            buffer.iter().all(|&v| v == 100),
            "DC-only spectrum must stay flat, got {:?}…",
            &buffer[..8]
        );
    }
}

//! Differential oracle for the pointer decoder (ADR-0003, issue #41): identical pointer
//! attribute bytes must produce **byte-identical** RGBA from `justrdp_codecs::pointer` and
//! `ironrdp-graphics`' pointer decoder (accelerated target: straight alpha, checkerboard
//! inversion — the convention our decoder adopts).
//!
//! Coverage is 16/24/32 bpp. The two oracle gaps are pinned by hand vectors in the unit tests
//! instead: 8 bpp (palettized — the oracle rejects it as unsupported) and 1 bpp (the oracle
//! skips the spec's bottom-up scan-line flip for monochrome shapes; MS-RDPBCGR 2.2.9.1.1.4.4
//! says "bottom-up" for every xorBpp, so we flip and deliberately diverge).

use ironrdp_graphics::pointer::{DecodedPointer, PointerBitmapTarget};
use ironrdp_pdu::pointer::{ColorPointerAttribute, Point16, PointerAttribute};
use justrdp_codecs::color::Palette;
use justrdp_codecs::pointer::decode_pointer;

/// Deterministic byte stream (no `rand` dependency): a plain LCG.
struct Lcg(u32);

impl Lcg {
    fn next_byte(&mut self) -> u8 {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (self.0 >> 16) as u8
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

fn strides(width: usize, xor_bpp: usize) -> (usize, usize) {
    let and_stride = width.div_ceil(16) * 2;
    let xor_stride = (width * xor_bpp).div_ceil(16) * 2;
    (and_stride, xor_stride)
}

/// Random masks at every size/depth combination must decode byte-identically. Random AND bits
/// over random XOR colors also exercise the transparent (AND=1 over black) and inverted
/// (AND=1 over white) special cases whenever the stream happens to produce them; the
/// dedicated test below forces both.
#[test]
fn random_shapes_decode_byte_identically_at_16_24_32_bpp() {
    let mut lcg = Lcg(0x4151_3CFE);
    for &(width, height) in &[(2u16, 2u16), (3, 3), (8, 5), (31, 17), (32, 32), (96, 96)] {
        for &xor_bpp in &[16u16, 24, 32] {
            let (and_stride, xor_stride) = strides(usize::from(width), usize::from(xor_bpp));
            let xor_mask = lcg.bytes(xor_stride * usize::from(height));
            let and_mask = lcg.bytes(and_stride * usize::from(height));

            let ours = decode_pointer(
                width,
                height,
                xor_bpp,
                &xor_mask,
                &and_mask,
                &Palette::default(),
            )
            .unwrap();

            let attribute = PointerAttribute {
                xor_bpp,
                color_pointer: ColorPointerAttribute {
                    cache_index: 0,
                    hot_spot: Point16 { x: 0, y: 0 },
                    width,
                    height,
                    xor_mask: &xor_mask,
                    and_mask: &and_mask,
                },
            };
            let oracle = DecodedPointer::decode_pointer_attribute(
                &attribute,
                PointerBitmapTarget::Accelerated,
            )
            .unwrap();

            assert_eq!(
                ours, oracle.bitmap_data,
                "RGBA mismatch at {width}x{height} @{xor_bpp}bpp"
            );
        }
    }
}

/// The 24-bpp Color Pointer message decodes through the oracle's dedicated entry point and
/// must also agree — with the transparent and inverted special cases forced explicitly.
#[test]
fn color_pointer_with_forced_special_cases_matches_the_oracle() {
    // 4×2 @24bpp: row of black/white/black/white XOR under an all-ones AND mask (alternating
    // transparent / inverted), above a row of arbitrary colors under AND=0.
    let width = 4u16;
    let height = 2u16;
    let (_, xor_stride) = strides(4, 24);
    let mut xor_mask = Vec::new();
    // Source row 0 (output bottom): arbitrary colors.
    xor_mask.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    // Source row 1 (output top): black, white, black, white.
    xor_mask.extend_from_slice(&[0, 0, 0, 255, 255, 255, 0, 0, 0, 255, 255, 255]);
    assert_eq!(xor_mask.len(), xor_stride * usize::from(height));
    let and_mask = vec![
        0x00, 0x00, // source row 0: all AND=0
        0xF0, 0x00, // source row 1: all AND=1
    ];

    let ours =
        decode_pointer(width, height, 24, &xor_mask, &and_mask, &Palette::default()).unwrap();

    let attribute = ColorPointerAttribute {
        cache_index: 0,
        hot_spot: Point16 { x: 0, y: 0 },
        width,
        height,
        xor_mask: &xor_mask,
        and_mask: &and_mask,
    };
    let oracle = DecodedPointer::decode_color_pointer_attribute(
        &attribute,
        PointerBitmapTarget::Accelerated,
    )
    .unwrap();

    assert_eq!(ours, oracle.bitmap_data);
    // And the special cases really happened: top row alternates transparent / inverted.
    assert_eq!(&ours[0..4], &[0, 0, 0, 0], "expected transparent at (0,0)");
    assert_eq!(
        &ours[4..8],
        &[0, 0, 0, 255],
        "expected check-pattern inversion at (0,1)"
    );
}

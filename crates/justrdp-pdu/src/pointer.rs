//! Pointer update PDUs (MS-RDPBCGR 2.2.9.1.1.4 slow-path `TS_POINTER_PDU` and the fast-path
//! pointer `updateCode`s) — the five cursor messages a server sends: System (hidden/default),
//! Position, Color (24-bpp shape), New (variable-bpp shape) and Cached (cache index). Decode
//! only: these flow server → client. Shape decoding to RGBA lives in `justrdp-codecs`; this
//! module only separates the wire fields.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `messageType`: system pointer (hidden or default).
pub const PTRMSGTYPE_SYSTEM: u16 = 0x0001;
/// `messageType`: server-set pointer position.
pub const PTRMSGTYPE_POSITION: u16 = 0x0003;
/// `messageType`: 24-bpp color pointer shape.
pub const PTRMSGTYPE_COLOR: u16 = 0x0006;
/// `messageType`: cached pointer (re-select a previously sent shape).
pub const PTRMSGTYPE_CACHED: u16 = 0x0007;
/// `messageType`: new pointer shape with explicit `xorBpp`.
pub const PTRMSGTYPE_POINTER: u16 = 0x0008;

/// `systemPointerType`: the pointer is hidden.
pub const SYSPTR_NULL: u32 = 0x0000_0000;
/// `systemPointerType`: the host's default pointer.
pub const SYSPTR_DEFAULT: u32 = 0x0000_7F00;

/// The MS-RDPBCGR cap on color/new pointer dimensions (2.2.9.1.1.4.4): shapes are at most
/// 96×96. Enforced before any decoder allocates from the wire-declared size (plan.md §11c —
/// the same hostile-dimensions guard as bitmap rectangles). LargePointer (384×384) is a
/// separate, opt-in capability this client does not advertise.
pub const MAX_POINTER_DIMENSION: u16 = 96;

/// TS_COLORPOINTERATTRIBUTE (2.2.9.1.1.4.4): one pointer shape as XOR color data plus a 1-bpp
/// AND mask, both stored bottom-up with scan lines padded to 2 bytes. Note the famous field
/// asymmetry: the **length** fields are AND-first, the **data** is XOR-first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorPointerAttribute {
    /// `cacheIndex` — the slot this shape occupies in the pointer cache.
    pub cache_index: u16,
    /// `hotSpot` as (x, y).
    pub hot_spot: (u16, u16),
    /// `width` in pixels (≤ [`MAX_POINTER_DIMENSION`]).
    pub width: u16,
    /// `height` in pixels (≤ [`MAX_POINTER_DIMENSION`]).
    pub height: u16,
    /// `xorMaskData` — bottom-up scan lines, 2-byte aligned.
    pub xor_mask: Vec<u8>,
    /// `andMaskData` — bottom-up 1-bpp scan lines, 2-byte aligned.
    pub and_mask: Vec<u8>,
}

impl ColorPointerAttribute {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let cache_index = cur.read_u16_le()?;
        let hot_spot = (cur.read_u16_le()?, cur.read_u16_le()?);
        let width = cur.read_u16_le()?;
        let height = cur.read_u16_le()?;
        if width > MAX_POINTER_DIMENSION || height > MAX_POINTER_DIMENSION {
            return Err(DecodeError::InvalidField {
                field: "TS_COLORPOINTERATTRIBUTE",
                reason: "pointer dimensions exceed the 96-pixel cap",
            });
        }
        let length_and_mask = cur.read_u16_le()? as usize;
        let length_xor_mask = cur.read_u16_le()? as usize;
        let xor_mask = cur.read_slice(length_xor_mask)?.to_vec();
        let and_mask = cur.read_slice(length_and_mask)?.to_vec();
        Ok(Self {
            cache_index,
            hot_spot,
            width,
            height,
            xor_mask,
            and_mask,
        })
    }
}

/// One decoded pointer update, from either transport (the slow-path `TS_POINTER_PDU` body or a
/// fast-path pointer update section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerUpdate {
    /// System pointer: [`SYSPTR_NULL`] (hidden) or [`SYSPTR_DEFAULT`].
    System {
        /// `systemPointerType` (`SYSPTR_*`).
        pointer_type: u32,
    },
    /// The server moved the pointer (only sent when the client allows it via the Input
    /// capability set; surfaced so the host can mirror it).
    Position {
        /// X in desktop coordinates.
        x: u16,
        /// Y in desktop coordinates.
        y: u16,
    },
    /// A 24-bpp color pointer shape (`TS_COLORPOINTERATTRIBUTE`).
    Color(ColorPointerAttribute),
    /// A variable-bpp pointer shape (`TS_POINTERATTRIBUTE` — the modern message).
    New {
        /// `xorBpp`: 1, 8, 16, 24 or 32.
        xor_bpp: u16,
        /// The shape fields (shared with the Color message).
        color: ColorPointerAttribute,
    },
    /// Re-select the cached shape at `cacheIndex`.
    Cached {
        /// `cacheIndex` into the pointer cache.
        cache_index: u16,
    },
}

impl PointerUpdate {
    /// Decode a slow-path `TS_POINTER_PDU` body (the Share Data PDU payload, starting at its
    /// `messageType` field).
    pub fn decode_slowpath(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let message_type = cur.read_u16_le()?;
        cur.read_u16_le()?; // pad2Octets
        match message_type {
            PTRMSGTYPE_SYSTEM => Ok(PointerUpdate::System {
                pointer_type: cur.read_u32_le()?,
            }),
            PTRMSGTYPE_POSITION => Ok(PointerUpdate::Position {
                x: cur.read_u16_le()?,
                y: cur.read_u16_le()?,
            }),
            PTRMSGTYPE_COLOR => Ok(PointerUpdate::Color(ColorPointerAttribute::decode(cur)?)),
            PTRMSGTYPE_POINTER => Ok(PointerUpdate::New {
                xor_bpp: cur.read_u16_le()?,
                color: ColorPointerAttribute::decode(cur)?,
            }),
            PTRMSGTYPE_CACHED => Ok(PointerUpdate::Cached {
                cache_index: cur.read_u16_le()?,
            }),
            _ => Err(DecodeError::InvalidField {
                field: "TS_POINTER_PDU.messageType",
                reason: "unknown pointer message type",
            }),
        }
    }

    /// Decode a fast-path pointer update section body for `code` (one of the
    /// `FP_UPDATE_PTR_*` / pointer `FP_UPDATE_*` constants). The bodies are the same
    /// attribute layouts the slow-path messages carry; the hidden/default distinction rides
    /// the update code itself.
    pub fn decode_fastpath(code: u8, cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        match code {
            crate::fastpath::FP_UPDATE_PTR_NULL => Ok(PointerUpdate::System {
                pointer_type: SYSPTR_NULL,
            }),
            crate::fastpath::FP_UPDATE_PTR_DEFAULT => Ok(PointerUpdate::System {
                pointer_type: SYSPTR_DEFAULT,
            }),
            crate::fastpath::FP_UPDATE_PTR_POSITION => Ok(PointerUpdate::Position {
                x: cur.read_u16_le()?,
                y: cur.read_u16_le()?,
            }),
            crate::fastpath::FP_UPDATE_COLOR_POINTER => {
                Ok(PointerUpdate::Color(ColorPointerAttribute::decode(cur)?))
            }
            crate::fastpath::FP_UPDATE_NEW_POINTER => Ok(PointerUpdate::New {
                xor_bpp: cur.read_u16_le()?,
                color: ColorPointerAttribute::decode(cur)?,
            }),
            crate::fastpath::FP_UPDATE_CACHED_POINTER => Ok(PointerUpdate::Cached {
                cache_index: cur.read_u16_le()?,
            }),
            _ => Err(DecodeError::InvalidField {
                field: "TS_FP_UPDATE.updateCode",
                reason: "not a pointer update code",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodeError;
    use crate::cursor::ReadCursor;
    use proptest::prelude::*;

    // ADR-0008 / issue #230 — the no-panic robustness properties for this module. Both entry
    // points are `pub fn`s the session loop drives straight off server bytes
    // (`justrdp/src/session.rs:374` fast-path, `:554` slow-path) and neither carried a property or
    // a fuzz target until now: `fuzz/fuzz_targets/pointer.rs` targets
    // `justrdp_codecs::pointer::decode_pointer`, which takes `width`/`height`/`xor_bpp` and both
    // masks *already parsed*, so the `TS_*POINTERATTRIBUTE` header parse that produces them was
    // driven by nothing. Same module name, different code — see
    // `docs/map/invariant/untrusted-decode-never-panics.md`.
    //
    // ## Why the generators are structured, which is measured rather than stylistic
    //
    // The attacker-controlled arithmetic lives in `ColorPointerAttribute::decode`: two `u16`
    // length fields size the slices the codec then walks, and nothing on the wire makes them
    // agree with `width`/`height`. **Undirected bytes do not reach it.** A first version of these
    // properties generated `vec(any::<u8>(), 0..=512)` and was green over an out-of-bounds read
    // injected into the AND-mask `read_slice` — while `malformed_pointers_are_typed_errors`, the
    // hand-written test beside it, went red on the same mutation.
    //
    // The reason is arithmetic, and it differs per entry point rather than being one number for
    // all three. Both dimensions must land inside the 96-pixel cap — (97/65536)^2, about 2.2e-6,
    // which is roughly 0.45% of a 2048-case run — and `decode_slowpath` additionally needs
    // `messageType` on one of two values, taking it to about **6.7e-11** per case. So the slow
    // path could not reach the masks at all and the other two reached them a few times per run,
    // which was enough to be green on a bad day and is not a property anyone should rely on.
    //
    // So the header fields are **weighted** into the range the parser admits, not bounded to it:
    // every strategy below keeps an `any::<...>()` arm, so the reject arms — an unknown
    // `messageType`, an unknown `updateCode`, an over-cap dimension — stay driven. A generator
    // bounded to what the parser accepts would assert the parser rather than the function under
    // test, which is the mirror-image failure #211 measured in `nscodec`'s property.
    //
    // **Weighting is something you add, never something you substitute**, and the first version
    // of this block got that wrong in the other direction: replacing the unstructured body with a
    // structured one made the deep reads reachable and the shallow ones unreachable. See
    // `truncate_to` on the slow-path property below for the read that cost.
    /// The five `messageType`s `decode_slowpath` dispatches, weighted against arbitrary values.
    fn slowpath_message_type() -> impl Strategy<Value = u16> {
        prop_oneof![
            5 => proptest::sample::select(vec![
                PTRMSGTYPE_SYSTEM,
                PTRMSGTYPE_POSITION,
                PTRMSGTYPE_COLOR,
                PTRMSGTYPE_CACHED,
                PTRMSGTYPE_POINTER,
            ]),
            1 => any::<u16>(),
        ]
    }

    /// The six `updateCode`s the session loop dispatches into this module
    /// (`justrdp/src/session.rs:368`), weighted against arbitrary bytes.
    fn pointer_update_code() -> impl Strategy<Value = u8> {
        prop_oneof![
            6 => proptest::sample::select(vec![
                crate::fastpath::FP_UPDATE_PTR_NULL,
                crate::fastpath::FP_UPDATE_PTR_DEFAULT,
                crate::fastpath::FP_UPDATE_PTR_POSITION,
                crate::fastpath::FP_UPDATE_COLOR_POINTER,
                crate::fastpath::FP_UPDATE_CACHED_POINTER,
                crate::fastpath::FP_UPDATE_NEW_POINTER,
            ]),
            1 => any::<u8>(),
        ]
    }

    /// A mask length: weighted into the neighbourhood of how many bytes the generator below
    /// actually appends, against a fully arbitrary `u16`.
    ///
    /// The arbitrary arm alone leaves the *second* read thinly covered, and the difference is
    /// measured. `lengthXorMask` is read first, so an arbitrary `u16` (mean 32768) against a tail
    /// of at most 512 bytes errors before the AND read in almost every case. Injecting an
    /// out-of-bounds read into the AND mask, three runs each with the rebuild verified:
    ///
    /// | | `decode_fastpath` red | `decode_slowpath` red | attribute property red |
    /// |---|---|---|---|
    /// | arbitrary length only | **1 of 3** | 3 of 3 | 3 of 3 |
    /// | weighted (this fn) | 3 of 3 | 3 of 3 | 3 of 3 |
    ///
    /// So the effect is flaky-to-reliable rather than green-to-red, which is worth stating
    /// precisely: an earlier revision of this comment claimed the entry-point properties were
    /// *green* without the weighting, and that number came from a mutation harness whose rebuild
    /// had been skipped (`lessons.md` §Step 3, the #189 trap). Two sequential reads from one
    /// hostile-length family still need satisfiable lengths, or the second one is only reached by
    /// accident.
    fn mask_length() -> impl Strategy<Value = u16> {
        prop_oneof![
            1 => 0u16..=600,
            1 => any::<u16>(),
        ]
    }

    /// `TS_COLORPOINTERATTRIBUTE` bytes with the header weighted into the admitted range and the
    /// two length fields hostile — nothing here makes `lengthXorMask` / `lengthAndMask` agree with
    /// the dimensions, with each other, or with how many bytes follow.
    fn color_pointer_attribute_bytes() -> impl Strategy<Value = Vec<u8>> {
        (
            any::<u16>(),                                                      // cacheIndex
            (any::<u16>(), any::<u16>()),                                      // hotSpot
            prop_oneof![4 => 0u16..=MAX_POINTER_DIMENSION, 1 => any::<u16>()], // width
            prop_oneof![4 => 0u16..=MAX_POINTER_DIMENSION, 1 => any::<u16>()], // height
            (mask_length(), mask_length()), // lengthAndMask, lengthXorMask
            proptest::collection::vec(any::<u8>(), 0..=512), // the mask bytes, however many
        )
            .prop_map(|(cache_index, hot, width, height, lengths, masks)| {
                let mut out = Vec::with_capacity(14 + masks.len());
                for v in [
                    cache_index,
                    hot.0,
                    hot.1,
                    width,
                    height,
                    lengths.0,
                    lengths.1,
                ] {
                    out.extend_from_slice(&v.to_le_bytes());
                }
                out.extend_from_slice(&masks);
                out
            })
    }

    /// A message body for either entry point: unstructured bytes, a shape attribute, or a `u16`
    /// `xorBpp` in front of one (the New-pointer layout, whose extra field would otherwise shift
    /// every attribute field by two bytes and put the cap back out of reach).
    fn pointer_message_body() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            2 => proptest::collection::vec(any::<u8>(), 0..=512),
            3 => color_pointer_attribute_bytes(),
            3 => (any::<u16>(), color_pointer_attribute_bytes()).prop_map(|(bpp, attr)| {
                let mut out = bpp.to_le_bytes().to_vec();
                out.extend_from_slice(&attr);
                out
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        // The private shape parser, driven with no dispatch prefix at all — the same reason #203
        // gave `gcc`'s six per-block decoders their own properties rather than only driving the
        // root that calls them. This is the one that goes red on an injected out-of-bounds read
        // in either mask; the two entry-point properties below reach it through their dispatch.
        #[test]
        fn color_pointer_attribute_decode_never_panics_on_arbitrary_input(
            body in pointer_message_body(),
        ) {
            let mut cur = ReadCursor::new(&body, "proptest pointer attribute");
            let _ = ColorPointerAttribute::decode(&mut cur);
        }

        // `truncate_to` is the correction to the correction, and it is the reason weighting is
        // stated above as something you *add*. Prefixing every body with `messageType` and
        // `pad2Octets` made the shape parser reachable and made a body shorter than four bytes
        // **impossible to generate**, so the `pad2Octets` read at :116 was covered by nothing —
        // measured, 3 runs of an unchecked read injected there, no test in this module red.
        // `Vec::truncate` past the end is a no-op, so the `usize::MAX` arm is the ordinary case.
        #[test]
        fn decode_slowpath_never_panics_on_arbitrary_input(
            message_type in slowpath_message_type(),
            pad in any::<u16>(),
            rest in pointer_message_body(),
            truncate_to in prop_oneof![9 => Just(usize::MAX), 1 => 0usize..=8],
        ) {
            let mut body = message_type.to_le_bytes().to_vec();
            body.extend_from_slice(&pad.to_le_bytes());
            body.extend_from_slice(&rest);
            body.truncate(truncate_to);
            let mut cur = ReadCursor::new(&body, "proptest pointer slow-path");
            let _ = PointerUpdate::decode_slowpath(&mut cur);
        }

        #[test]
        fn decode_fastpath_never_panics_on_arbitrary_input(
            code in pointer_update_code(),
            body in pointer_message_body(),
        ) {
            let mut cur = ReadCursor::new(&body, "proptest pointer fast-path");
            let _ = PointerUpdate::decode_fastpath(code, &mut cur);
        }
    }

    /// TS_COLORPOINTERATTRIBUTE bytes (2.2.9.1.1.4.4). Mind the trap the format is famous
    /// for: the *length* fields are AND-first, the *data* is XOR-first.
    fn color_pointer_bytes(xor: &[u8], and: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [
            7u16,             // cacheIndex
            3,                // hotSpot.x
            2,                // hotSpot.y
            2,                // width
            2,                // height
            and.len() as u16, // lengthAndMask
            xor.len() as u16, // lengthXorMask
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(xor); // xorMaskData first…
        out.extend_from_slice(and); // …andMaskData second
        out
    }

    fn slowpath_body(message_type: u16, attribute: &[u8]) -> Vec<u8> {
        let mut out = message_type.to_le_bytes().to_vec();
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
        out.extend_from_slice(attribute);
        out
    }

    #[test]
    fn slowpath_color_pointer_separates_the_masks_correctly() {
        let xor = [0xAA; 16]; // 2×2 @24bpp, scan lines padded to 2 bytes: 2 rows × 8
        let and = [0xBB; 4]; // 2 rows × 2 (1bpp padded to 2 bytes)
        let body = slowpath_body(PTRMSGTYPE_COLOR, &color_pointer_bytes(&xor, &and));

        let mut cur = ReadCursor::new(&body, "test");
        let update = PointerUpdate::decode_slowpath(&mut cur).unwrap();

        let PointerUpdate::Color(attr) = update else {
            panic!("expected Color, got {update:?}");
        };
        assert_eq!(attr.cache_index, 7);
        assert_eq!(attr.hot_spot, (3, 2));
        assert_eq!((attr.width, attr.height), (2, 2));
        // The length fields are AND-first but the data is XOR-first — the masks must not be
        // swapped (a swapped decode renders garbage cursors).
        assert_eq!(attr.xor_mask, xor);
        assert_eq!(attr.and_mask, and);
    }

    #[test]
    fn slowpath_system_pointer_is_hidden_or_default() {
        let hidden = slowpath_body(PTRMSGTYPE_SYSTEM, &SYSPTR_NULL.to_le_bytes());
        let mut cur = ReadCursor::new(&hidden, "test");
        assert_eq!(
            PointerUpdate::decode_slowpath(&mut cur).unwrap(),
            PointerUpdate::System {
                pointer_type: SYSPTR_NULL
            }
        );

        let default = slowpath_body(PTRMSGTYPE_SYSTEM, &SYSPTR_DEFAULT.to_le_bytes());
        let mut cur = ReadCursor::new(&default, "test");
        assert_eq!(
            PointerUpdate::decode_slowpath(&mut cur).unwrap(),
            PointerUpdate::System {
                pointer_type: SYSPTR_DEFAULT
            }
        );
    }

    #[test]
    fn slowpath_position_decodes() {
        let mut attr = 640u16.to_le_bytes().to_vec();
        attr.extend_from_slice(&480u16.to_le_bytes());
        let body = slowpath_body(PTRMSGTYPE_POSITION, &attr);
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            PointerUpdate::decode_slowpath(&mut cur).unwrap(),
            PointerUpdate::Position { x: 640, y: 480 }
        );
    }

    #[test]
    fn slowpath_cached_decodes() {
        let body = slowpath_body(PTRMSGTYPE_CACHED, &5u16.to_le_bytes());
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            PointerUpdate::decode_slowpath(&mut cur).unwrap(),
            PointerUpdate::Cached { cache_index: 5 }
        );
    }

    #[test]
    fn slowpath_new_pointer_carries_its_xor_bpp() {
        // TS_POINTERATTRIBUTE = xorBpp (u16) + TS_COLORPOINTERATTRIBUTE. 2×2 @32bpp:
        // scan line = 8 bytes, already 2-byte aligned.
        let xor = [0xCC; 16];
        let and = [0xDD; 4];
        let mut attr = 32u16.to_le_bytes().to_vec();
        attr.extend_from_slice(&color_pointer_bytes(&xor, &and));
        let body = slowpath_body(PTRMSGTYPE_POINTER, &attr);

        let mut cur = ReadCursor::new(&body, "test");
        let update = PointerUpdate::decode_slowpath(&mut cur).unwrap();
        let PointerUpdate::New { xor_bpp, color } = update else {
            panic!("expected New, got {update:?}");
        };
        assert_eq!(xor_bpp, 32);
        assert_eq!(color.xor_mask, xor);
        assert_eq!(color.and_mask, and);
    }

    #[test]
    fn a_trailing_pad_byte_is_tolerated() {
        // The attribute's optional `pad` byte: present in some servers' encodings, absent in
        // others — both must decode.
        let mut attr = color_pointer_bytes(&[0xAA; 16], &[0xBB; 4]);
        attr.push(0xEE); // pad
        let body = slowpath_body(PTRMSGTYPE_COLOR, &attr);
        let mut cur = ReadCursor::new(&body, "test");
        let update = PointerUpdate::decode_slowpath(&mut cur).unwrap();
        assert!(matches!(update, PointerUpdate::Color(_)));
    }

    #[test]
    fn fastpath_ptr_null_and_default_map_to_system() {
        let mut cur = ReadCursor::new(&[], "test");
        assert_eq!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_PTR_NULL, &mut cur).unwrap(),
            PointerUpdate::System {
                pointer_type: SYSPTR_NULL
            }
        );
        let mut cur = ReadCursor::new(&[], "test");
        assert_eq!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_PTR_DEFAULT, &mut cur)
                .unwrap(),
            PointerUpdate::System {
                pointer_type: SYSPTR_DEFAULT
            }
        );
    }

    #[test]
    fn fastpath_bodies_reuse_the_slowpath_attribute_layouts() {
        // Position.
        let mut pos = 10u16.to_le_bytes().to_vec();
        pos.extend_from_slice(&20u16.to_le_bytes());
        let mut cur = ReadCursor::new(&pos, "test");
        assert_eq!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_PTR_POSITION, &mut cur)
                .unwrap(),
            PointerUpdate::Position { x: 10, y: 20 }
        );

        // Color.
        let color = color_pointer_bytes(&[0xAA; 16], &[0xBB; 4]);
        let mut cur = ReadCursor::new(&color, "test");
        assert!(matches!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_COLOR_POINTER, &mut cur)
                .unwrap(),
            PointerUpdate::Color(_)
        ));

        // Cached.
        let cached = 9u16.to_le_bytes();
        let mut cur = ReadCursor::new(&cached, "test");
        assert_eq!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_CACHED_POINTER, &mut cur)
                .unwrap(),
            PointerUpdate::Cached { cache_index: 9 }
        );

        // New.
        let mut newp = 16u16.to_le_bytes().to_vec();
        newp.extend_from_slice(&color_pointer_bytes(&[0x11; 8], &[0x22; 4]));
        let mut cur = ReadCursor::new(&newp, "test");
        assert!(matches!(
            PointerUpdate::decode_fastpath(crate::fastpath::FP_UPDATE_NEW_POINTER, &mut cur)
                .unwrap(),
            PointerUpdate::New { xor_bpp: 16, .. }
        ));
    }

    #[test]
    fn malformed_pointers_are_typed_errors() {
        // Truncated mask data.
        let mut short = color_pointer_bytes(&[0xAA; 16], &[0xBB; 4]);
        short.truncate(short.len() - 3);
        let body = slowpath_body(PTRMSGTYPE_COLOR, &short);
        let mut cur = ReadCursor::new(&body, "test");
        assert!(PointerUpdate::decode_slowpath(&mut cur).is_err());

        // A hostile width over the 96-pixel cap (MS-RDPBCGR 2.2.9.1.1.4.4) must be refused
        // before any decoder allocates from it.
        let mut oversize = Vec::new();
        for v in [0u16, 0, 0, 30_000, 30_000, 4, 16] {
            oversize.extend_from_slice(&v.to_le_bytes());
        }
        oversize.extend_from_slice(&[0; 20]);
        let body = slowpath_body(PTRMSGTYPE_COLOR, &oversize);
        let mut cur = ReadCursor::new(&body, "test");
        assert!(matches!(
            PointerUpdate::decode_slowpath(&mut cur),
            Err(DecodeError::InvalidField { .. })
        ));

        // An unknown message type is a typed error, not a panic.
        let body = slowpath_body(0x00FF, &[]);
        let mut cur = ReadCursor::new(&body, "test");
        assert!(matches!(
            PointerUpdate::decode_slowpath(&mut cur),
            Err(DecodeError::InvalidField { .. })
        ));
    }
}

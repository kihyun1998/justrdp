//! Controlling Server Graphics Output (`[MS-RDPBCGR]` 2.2.11): the Refresh Rect PDU, the
//! Share Data body of [`crate::share::PDU_TYPE2_REFRESH_RECT`], and the Suppress Output PDU,
//! the body of [`crate::share::PDU_TYPE2_SUPPRESS_OUTPUT`]. A server announces each in its
//! General capability set (`refreshRectSupport` / `suppressOutputSupport`, 2.2.7.1.1).
//!
//! Encode only: justrdp is a client and both PDUs are client-to-server.

/// Inclusive Rectangle (`TS_RECTANGLE16`, 2.2.11.1): `right` and `bottom` are the last
/// column and row inside the rectangle, not one past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InclusiveRect {
    /// `left`.
    pub left: u16,
    /// `top`.
    pub top: u16,
    /// `right` (inclusive).
    pub right: u16,
    /// `bottom` (inclusive).
    pub bottom: u16,
}

impl InclusiveRect {
    fn write(&self, out: &mut Vec<u8>) {
        for v in [self.left, self.top, self.right, self.bottom] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// `allowDisplayUpdates`: `SUPPRESS_DISPLAY_UPDATES` (2.2.11.3.1).
pub const SUPPRESS_DISPLAY_UPDATES: u8 = 0x00;
/// `allowDisplayUpdates`: `ALLOW_DISPLAY_UPDATES` (2.2.11.3.1).
pub const ALLOW_DISPLAY_UPDATES: u8 = 0x01;

/// Encode a Refresh Rect PDU body (`TS_REFRESH_RECT_PDU`, 2.2.11.2.1): `numberOfAreas`,
/// three zero pad bytes, then `areasToRefresh`. `None` when `areas` holds more than the 255
/// rectangles `numberOfAreas` can count.
pub fn encode_refresh_rect(areas: &[InclusiveRect]) -> Option<Vec<u8>> {
    let count = u8::try_from(areas.len()).ok()?;
    let mut out = Vec::with_capacity(4 + areas.len() * 8);
    out.push(count);
    out.extend_from_slice(&[0; 3]);
    for area in areas {
        area.write(&mut out);
    }
    Some(out)
}

/// Encode a Suppress Output PDU body (`TS_SUPPRESS_OUTPUT_PDU`, 2.2.11.3.1). `None` suppresses
/// display updates; `Some(desktop)` allows them, and `desktop` is the `desktopRect` that
/// 2.2.11.3.1 carries only then.
pub fn encode_suppress_output(desktop: Option<InclusiveRect>) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    match desktop {
        None => {
            out.push(SUPPRESS_DISPLAY_UPDATES);
            out.extend_from_slice(&[0; 3]);
        }
        Some(rect) => {
            out.push(ALLOW_DISPLAY_UPDATES);
            out.extend_from_slice(&[0; 3]);
            rect.write(&mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_rect_is_count_pad_then_inclusive_rectangles() {
        let areas = [
            InclusiveRect {
                left: 0,
                top: 0,
                right: 1023,
                bottom: 767,
            },
            InclusiveRect {
                left: 0x0102,
                top: 0x0304,
                right: 0x0506,
                bottom: 0x0708,
            },
        ];
        assert_eq!(
            encode_refresh_rect(&areas).unwrap(),
            [
                0x02, 0x00, 0x00, 0x00, // numberOfAreas 2, pad3Octects
                0x00, 0x00, 0x00, 0x00, 0xFF, 0x03, 0xFF, 0x02, // 0,0 – 1023,767
                0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07, // little-endian fields
            ]
        );
    }

    #[test]
    fn refresh_rect_counts_at_most_255_areas() {
        let area = InclusiveRect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let body = encode_refresh_rect(&[area; 255]).expect("255 fits numberOfAreas");
        assert_eq!((body[0], body.len()), (255, 4 + 255 * 8));
        assert_eq!(encode_refresh_rect(&[area; 256]), None);
    }

    #[test]
    fn suppress_carries_no_desktop_rect() {
        assert_eq!(encode_suppress_output(None), [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn allow_carries_the_desktop_rect() {
        let desktop = InclusiveRect {
            left: 0,
            top: 0,
            right: 1919,
            bottom: 1079,
        };
        assert_eq!(
            encode_suppress_output(Some(desktop)),
            [
                0x01, 0x00, 0x00, 0x00, // ALLOW_DISPLAY_UPDATES, pad3Octets
                0x00, 0x00, 0x00, 0x00, 0x7F, 0x07, 0x37, 0x04, // 0,0 – 1919,1079
            ]
        );
    }
}

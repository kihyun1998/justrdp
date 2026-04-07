#![forbid(unsafe_code)]

//! Display Control PDU types -- MS-RDPEDISP 2.2
//!
//! This module defines the wire-format PDUs for the Display Control
//! Virtual Channel Extension.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

// =============================================================================
// Constants (MS-RDPEDISP 2.2.1.1)
// =============================================================================

/// PDU type for DISPLAYCONTROL_CAPS_PDU (server → client).
/// MS-RDPEDISP 2.2.2.1
pub const PDU_TYPE_CAPS: u32 = 0x0000_0005;

/// PDU type for DISPLAYCONTROL_MONITOR_LAYOUT_PDU (client → server).
/// MS-RDPEDISP 2.2.2.2
pub const PDU_TYPE_MONITOR_LAYOUT: u32 = 0x0000_0002;

/// Size of DISPLAYCONTROL_HEADER in bytes.
/// MS-RDPEDISP 2.2.1.1
const HEADER_SIZE: usize = 8;

/// Fixed size of each DISPLAYCONTROL_MONITOR_LAYOUT entry.
/// MS-RDPEDISP 2.2.2.2.1
pub const MONITOR_LAYOUT_SIZE: u32 = 40;

/// Maximum number of monitors we accept in a single PDU.
const MAX_MONITORS: u32 = 64;

// ── MonitorFlags (MS-RDPEDISP 2.2.2.2.1) ──

/// This monitor is the primary display.
/// MS-RDPEDISP 2.2.2.2.1
pub const MONITOR_PRIMARY: u32 = 0x0000_0001;

// ── Orientation values (MS-RDPEDISP 2.2.2.2.1) ──

/// Landscape (no rotation).
pub const ORIENTATION_LANDSCAPE: u32 = 0;
/// Portrait (90 degrees clockwise).
pub const ORIENTATION_PORTRAIT: u32 = 90;
/// Landscape flipped (180 degrees).
pub const ORIENTATION_LANDSCAPE_FLIPPED: u32 = 180;
/// Portrait flipped (270 degrees clockwise).
pub const ORIENTATION_PORTRAIT_FLIPPED: u32 = 270;

// ── Width/Height constraints (MS-RDPEDISP 2.2.2.2.1) ──

/// Minimum monitor width/height in pixels.
pub const MIN_MONITOR_DIMENSION: u32 = 200;
/// Maximum monitor width/height in pixels.
pub const MAX_MONITOR_DIMENSION: u32 = 8192;

// =============================================================================
// CapsPdu (MS-RDPEDISP 2.2.2.1) — server → client, decode only
// =============================================================================

/// Server capabilities PDU.
///
/// Received from the server when the DVC channel is opened.
/// MS-RDPEDISP 2.2.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsPdu {
    /// Maximum number of monitors the server supports.
    pub max_num_monitors: u32,
    /// Factor A for maximum monitor area computation.
    pub max_monitor_area_factor_a: u32,
    /// Factor B for maximum monitor area computation.
    pub max_monitor_area_factor_b: u32,
}

impl CapsPdu {
    /// Total PDU size (header + 3 fields).
    pub const WIRE_SIZE: usize = 20;

    /// Decode a capabilities PDU from raw DVC payload.
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);

        let pdu_type = src.read_u32_le("CapsPdu::Type")?;
        if pdu_type != PDU_TYPE_CAPS {
            return Err(DecodeError::unexpected_value(
                "CapsPdu",
                "Type",
                "expected DISPLAYCONTROL_PDU_TYPE_CAPS (0x00000005)",
            ));
        }

        let length = src.read_u32_le("CapsPdu::Length")?;
        if length != Self::WIRE_SIZE as u32 {
            return Err(DecodeError::unexpected_value(
                "CapsPdu",
                "Length",
                "expected 20",
            ));
        }

        let max_num_monitors = src.read_u32_le("CapsPdu::MaxNumMonitors")?;
        let max_monitor_area_factor_a = src.read_u32_le("CapsPdu::MaxMonitorAreaFactorA")?;
        let max_monitor_area_factor_b = src.read_u32_le("CapsPdu::MaxMonitorAreaFactorB")?;

        Ok(Self {
            max_num_monitors,
            max_monitor_area_factor_a,
            max_monitor_area_factor_b,
        })
    }

    /// Compute the maximum total monitor area in pixels.
    pub fn max_total_area(&self) -> u64 {
        (self.max_num_monitors as u64)
            .saturating_mul(self.max_monitor_area_factor_a as u64)
            .saturating_mul(self.max_monitor_area_factor_b as u64)
    }
}

// =============================================================================
// MonitorLayoutEntry (MS-RDPEDISP 2.2.2.2.1) — 40 bytes each
// =============================================================================

/// A single monitor layout entry.
///
/// MS-RDPEDISP 2.2.2.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLayoutEntry {
    /// Monitor flags (`MONITOR_PRIMARY`).
    pub flags: u32,
    /// X coordinate of upper-left corner (signed, relative to primary).
    pub left: i32,
    /// Y coordinate of upper-left corner (signed, relative to primary).
    pub top: i32,
    /// Width in pixels (must be even, 200–8192).
    pub width: u32,
    /// Height in pixels (200–8192).
    pub height: u32,
    /// Physical width in millimeters.
    pub physical_width: u32,
    /// Physical height in millimeters.
    pub physical_height: u32,
    /// Orientation: 0, 90, 180, or 270 degrees.
    pub orientation: u32,
    /// Desktop scale factor (percentage, typically 100–500).
    pub desktop_scale_factor: u32,
    /// Device scale factor (percentage: 100, 140, or 180).
    pub device_scale_factor: u32,
}

impl MonitorLayoutEntry {
    /// Wire size of a single entry.
    pub const WIRE_SIZE: usize = 40;

    /// Create a primary monitor entry with common defaults.
    pub fn primary(width: u32, height: u32) -> Self {
        Self {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width,
            height,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }
    }
}

impl Encode for MonitorLayoutEntry {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.flags, "MonitorLayout::Flags")?;
        dst.write_i32_le(self.left, "MonitorLayout::Left")?;
        dst.write_i32_le(self.top, "MonitorLayout::Top")?;
        dst.write_u32_le(self.width, "MonitorLayout::Width")?;
        dst.write_u32_le(self.height, "MonitorLayout::Height")?;
        dst.write_u32_le(self.physical_width, "MonitorLayout::PhysicalWidth")?;
        dst.write_u32_le(self.physical_height, "MonitorLayout::PhysicalHeight")?;
        dst.write_u32_le(self.orientation, "MonitorLayout::Orientation")?;
        dst.write_u32_le(self.desktop_scale_factor, "MonitorLayout::DesktopScaleFactor")?;
        dst.write_u32_le(self.device_scale_factor, "MonitorLayout::DeviceScaleFactor")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MonitorLayoutEntry"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> justrdp_core::Decode<'de> for MonitorLayoutEntry {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = src.read_u32_le("MonitorLayout::Flags")?;
        let left = src.read_i32_le("MonitorLayout::Left")?;
        let top = src.read_i32_le("MonitorLayout::Top")?;
        let width = src.read_u32_le("MonitorLayout::Width")?;
        let height = src.read_u32_le("MonitorLayout::Height")?;
        let physical_width = src.read_u32_le("MonitorLayout::PhysicalWidth")?;
        let physical_height = src.read_u32_le("MonitorLayout::PhysicalHeight")?;
        let orientation = src.read_u32_le("MonitorLayout::Orientation")?;
        let desktop_scale_factor = src.read_u32_le("MonitorLayout::DesktopScaleFactor")?;
        let device_scale_factor = src.read_u32_le("MonitorLayout::DeviceScaleFactor")?;

        Ok(Self {
            flags,
            left,
            top,
            width,
            height,
            physical_width,
            physical_height,
            orientation,
            desktop_scale_factor,
            device_scale_factor,
        })
    }
}

// =============================================================================
// MonitorLayoutPdu (MS-RDPEDISP 2.2.2.2) — client → server, encode only
// =============================================================================

/// Monitor layout PDU sent from client to server.
///
/// MS-RDPEDISP 2.2.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLayoutPdu {
    /// Monitor layout entries.
    pub monitors: Vec<MonitorLayoutEntry>,
}

impl MonitorLayoutPdu {
    /// Create a new monitor layout PDU.
    pub fn new(monitors: Vec<MonitorLayoutEntry>) -> Self {
        Self { monitors }
    }

    /// Decode from raw DVC payload (for testing roundtrips).
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);

        let pdu_type = src.read_u32_le("MonitorLayoutPdu::Type")?;
        if pdu_type != PDU_TYPE_MONITOR_LAYOUT {
            return Err(DecodeError::unexpected_value(
                "MonitorLayoutPdu",
                "Type",
                "expected DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT (0x00000002)",
            ));
        }

        let length = src.read_u32_le("MonitorLayoutPdu::Length")?;
        let monitor_layout_size = src.read_u32_le("MonitorLayoutPdu::MonitorLayoutSize")?;
        if monitor_layout_size != MONITOR_LAYOUT_SIZE {
            return Err(DecodeError::unexpected_value(
                "MonitorLayoutPdu",
                "MonitorLayoutSize",
                "expected 40",
            ));
        }

        let num_monitors = src.read_u32_le("MonitorLayoutPdu::NumMonitors")?;
        if num_monitors > MAX_MONITORS {
            return Err(DecodeError::unexpected_value(
                "MonitorLayoutPdu",
                "NumMonitors",
                "exceeds maximum (64)",
            ));
        }

        // Safe: num_monitors <= MAX_MONITORS (64), so 16 + 64*40 = 2576, within u32.
        let expected_length = 16 + num_monitors * MONITOR_LAYOUT_SIZE; // guarded by MAX_MONITORS check above
        if length != expected_length {
            return Err(DecodeError::unexpected_value(
                "MonitorLayoutPdu",
                "Length",
                "does not match NumMonitors",
            ));
        }

        let mut monitors = Vec::with_capacity(num_monitors as usize);
        for _ in 0..num_monitors {
            monitors.push(MonitorLayoutEntry::decode(&mut src)?);
        }

        Ok(Self { monitors })
    }
}

impl Encode for MonitorLayoutPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let num_monitors = u32::try_from(self.monitors.len())
            .map_err(|_| justrdp_core::EncodeError::invalid_value("MonitorLayoutPdu::NumMonitors", "exceeds u32"))?;
        let total_length = num_monitors
            .checked_mul(MONITOR_LAYOUT_SIZE)
            .and_then(|v| v.checked_add(16))
            .ok_or_else(|| justrdp_core::EncodeError::invalid_value("MonitorLayoutPdu::Length", "overflow"))?;

        // Header
        dst.write_u32_le(PDU_TYPE_MONITOR_LAYOUT, "MonitorLayoutPdu::Type")?;
        dst.write_u32_le(total_length, "MonitorLayoutPdu::Length")?;

        // Body
        dst.write_u32_le(MONITOR_LAYOUT_SIZE, "MonitorLayoutPdu::MonitorLayoutSize")?;
        dst.write_u32_le(num_monitors, "MonitorLayoutPdu::NumMonitors")?;

        for monitor in &self.monitors {
            monitor.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MonitorLayoutPdu"
    }

    fn size(&self) -> usize {
        HEADER_SIZE + 4 + 4 + (self.monitors.len() * MonitorLayoutEntry::WIRE_SIZE)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Caps PDU tests ──

    #[test]
    fn caps_pdu_decode() {
        #[rustfmt::skip]
        let buf: [u8; 20] = [
            0x05, 0x00, 0x00, 0x00, // Type = CAPS
            0x14, 0x00, 0x00, 0x00, // Length = 20
            0x01, 0x00, 0x00, 0x00, // MaxNumMonitors = 1
            0x80, 0x07, 0x00, 0x00, // MaxMonitorAreaFactorA = 1920
            0xB0, 0x04, 0x00, 0x00, // MaxMonitorAreaFactorB = 1200
        ];

        let caps = CapsPdu::decode_from(&buf).unwrap();
        assert_eq!(caps.max_num_monitors, 1);
        assert_eq!(caps.max_monitor_area_factor_a, 1920);
        assert_eq!(caps.max_monitor_area_factor_b, 1200);
        assert_eq!(caps.max_total_area(), 1920 * 1200);
    }

    #[test]
    fn caps_pdu_wrong_type() {
        #[rustfmt::skip]
        let buf: [u8; 20] = [
            0x02, 0x00, 0x00, 0x00, // Type = MONITOR_LAYOUT (wrong)
            0x14, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x80, 0x07, 0x00, 0x00,
            0xB0, 0x04, 0x00, 0x00,
        ];
        assert!(CapsPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn caps_pdu_wrong_length() {
        #[rustfmt::skip]
        let buf: [u8; 20] = [
            0x05, 0x00, 0x00, 0x00, // Type = CAPS
            0x18, 0x00, 0x00, 0x00, // Length = 24 (wrong)
            0x01, 0x00, 0x00, 0x00,
            0x80, 0x07, 0x00, 0x00,
            0xB0, 0x04, 0x00, 0x00,
        ];
        assert!(CapsPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn caps_max_total_area_overflow_safe() {
        let caps = CapsPdu {
            max_num_monitors: u32::MAX,
            max_monitor_area_factor_a: u32::MAX,
            max_monitor_area_factor_b: u32::MAX,
        };
        // Must not panic — uses u64 arithmetic.
        let _ = caps.max_total_area();
    }

    // ── MonitorLayoutEntry tests ──

    #[test]
    fn monitor_entry_encode_decode_roundtrip() {
        let entry = MonitorLayoutEntry::primary(1920, 1080);

        let mut buf = [0u8; 40];
        let mut dst = WriteCursor::new(&mut buf);
        entry.encode(&mut dst).unwrap();

        let mut src = ReadCursor::new(&buf);
        let decoded = MonitorLayoutEntry::decode(&mut src).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn monitor_entry_wire_format() {
        let entry = MonitorLayoutEntry::primary(1920, 1080);

        let mut buf = [0u8; 40];
        let mut dst = WriteCursor::new(&mut buf);
        entry.encode(&mut dst).unwrap();

        #[rustfmt::skip]
        let expected: [u8; 40] = [
            0x01, 0x00, 0x00, 0x00, // Flags = PRIMARY
            0x00, 0x00, 0x00, 0x00, // Left = 0
            0x00, 0x00, 0x00, 0x00, // Top = 0
            0x80, 0x07, 0x00, 0x00, // Width = 1920
            0x38, 0x04, 0x00, 0x00, // Height = 1080
            0x00, 0x00, 0x00, 0x00, // PhysicalWidth = 0
            0x00, 0x00, 0x00, 0x00, // PhysicalHeight = 0
            0x00, 0x00, 0x00, 0x00, // Orientation = LANDSCAPE (0)
            0x64, 0x00, 0x00, 0x00, // DesktopScaleFactor = 100
            0x64, 0x00, 0x00, 0x00, // DeviceScaleFactor = 100
        ];
        assert_eq!(buf, expected);
    }

    #[test]
    fn monitor_entry_negative_coordinates() {
        let entry = MonitorLayoutEntry {
            flags: 0,
            left: -1920,
            top: -1080,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        };

        let mut buf = [0u8; 40];
        let mut dst = WriteCursor::new(&mut buf);
        entry.encode(&mut dst).unwrap();

        let mut src = ReadCursor::new(&buf);
        let decoded = MonitorLayoutEntry::decode(&mut src).unwrap();
        assert_eq!(decoded.left, -1920);
        assert_eq!(decoded.top, -1080);
    }

    #[test]
    fn monitor_entry_size_matches_encode() {
        let entry = MonitorLayoutEntry::primary(1920, 1080);
        assert_eq!(entry.size(), MonitorLayoutEntry::WIRE_SIZE);
        assert_eq!(entry.size(), 40);
    }

    // ── MonitorLayoutPdu tests ──

    #[test]
    fn monitor_layout_pdu_single_monitor_roundtrip() {
        let pdu = MonitorLayoutPdu::new(alloc::vec![MonitorLayoutEntry::primary(1920, 1080)]);

        assert_eq!(pdu.size(), 56); // 8 + 4 + 4 + 40

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        let decoded = MonitorLayoutPdu::decode_from(&buf).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn monitor_layout_pdu_wire_format() {
        let pdu = MonitorLayoutPdu::new(alloc::vec![MonitorLayoutEntry::primary(1920, 1080)]);

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        // Check header
        assert_eq!(&buf[0..4], &[0x02, 0x00, 0x00, 0x00]); // Type
        assert_eq!(&buf[4..8], &[0x38, 0x00, 0x00, 0x00]); // Length = 56
        assert_eq!(&buf[8..12], &[0x28, 0x00, 0x00, 0x00]); // MonitorLayoutSize = 40
        assert_eq!(&buf[12..16], &[0x01, 0x00, 0x00, 0x00]); // NumMonitors = 1
    }

    #[test]
    fn monitor_layout_pdu_two_monitors() {
        let monitors = alloc::vec![
            MonitorLayoutEntry::primary(1920, 1080),
            MonitorLayoutEntry {
                flags: 0, // not primary
                left: 1920,
                top: 0,
                width: 1920,
                height: 1080,
                physical_width: 0,
                physical_height: 0,
                orientation: ORIENTATION_LANDSCAPE,
                desktop_scale_factor: 100,
                device_scale_factor: 100,
            },
        ];

        let pdu = MonitorLayoutPdu::new(monitors);
        assert_eq!(pdu.size(), 96); // 16 + 2*40

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        let decoded = MonitorLayoutPdu::decode_from(&buf).unwrap();
        assert_eq!(decoded.monitors.len(), 2);
        assert_eq!(decoded.monitors[0].flags, MONITOR_PRIMARY);
        assert_eq!(decoded.monitors[1].flags, 0);
        assert_eq!(decoded.monitors[1].left, 1920);
    }

    #[test]
    fn monitor_layout_pdu_wrong_type() {
        #[rustfmt::skip]
        let buf: [u8; 56] = [
            0x05, 0x00, 0x00, 0x00, // Type = CAPS (wrong for layout)
            0x38, 0x00, 0x00, 0x00,
            0x28, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            // 40 bytes of monitor data...
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00,
            0x38, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        ];
        assert!(MonitorLayoutPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn monitor_layout_pdu_wrong_layout_size() {
        #[rustfmt::skip]
        let buf: [u8; 56] = [
            0x02, 0x00, 0x00, 0x00,
            0x38, 0x00, 0x00, 0x00,
            0x30, 0x00, 0x00, 0x00, // MonitorLayoutSize = 48 (wrong, must be 40)
            0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00,
            0x38, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        ];
        assert!(MonitorLayoutPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn monitor_layout_pdu_length_mismatch() {
        #[rustfmt::skip]
        let buf: [u8; 56] = [
            0x02, 0x00, 0x00, 0x00,
            0x60, 0x00, 0x00, 0x00, // Length = 96 but NumMonitors = 1 (expects 56)
            0x28, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00,
            0x38, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        ];
        assert!(MonitorLayoutPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn monitor_layout_pdu_size_matches_encode() {
        let pdu = MonitorLayoutPdu::new(alloc::vec![
            MonitorLayoutEntry::primary(1920, 1080),
            MonitorLayoutEntry {
                flags: 0,
                left: 1920,
                top: 0,
                width: 2560,
                height: 1440,
                physical_width: 600,
                physical_height: 340,
                orientation: ORIENTATION_PORTRAIT,
                desktop_scale_factor: 150,
                device_scale_factor: 140,
            },
        ]);

        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0, "size() must match encode() output exactly");
    }

    #[test]
    fn monitor_entry_all_orientations() {
        for &orientation in &[
            ORIENTATION_LANDSCAPE,
            ORIENTATION_PORTRAIT,
            ORIENTATION_LANDSCAPE_FLIPPED,
            ORIENTATION_PORTRAIT_FLIPPED,
        ] {
            let entry = MonitorLayoutEntry {
                flags: MONITOR_PRIMARY,
                left: 0,
                top: 0,
                width: 1920,
                height: 1080,
                physical_width: 0,
                physical_height: 0,
                orientation,
                desktop_scale_factor: 100,
                device_scale_factor: 100,
            };

            let mut buf = [0u8; 40];
            let mut dst = WriteCursor::new(&mut buf);
            entry.encode(&mut dst).unwrap();

            let mut src = ReadCursor::new(&buf);
            let decoded = MonitorLayoutEntry::decode(&mut src).unwrap();
            assert_eq!(decoded.orientation, orientation);
        }
    }
}

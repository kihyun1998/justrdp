//! Display Control virtual channel PDUs (MS-RDPEDISP) — client-initiated resize / monitor
//! layout, carried over the dynamic channel [`CHANNEL_NAME`]. The server speaks first with a
//! Caps PDU (its monitor-count and area limits); after that the **client** may send Monitor
//! Layout PDUs. The server never sends a Monitor Layout — a server-driven size change arrives
//! as Deactivation–Reactivation (or an EGFX reset), not on this channel (MS-RDPEDISP 1.3).

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The dynamic channel name the server uses in its drdynvc Create Request.
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::DisplayControl";

/// `DISPLAYCONTROL_PDU_TYPE_CAPS` (server→client, MS-RDPEDISP 2.2.2.1).
pub const TYPE_CAPS: u32 = 0x0000_0005;
/// `DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT` (client→server, 2.2.2.2).
pub const TYPE_MONITOR_LAYOUT: u32 = 0x0000_0002;

/// `DISPLAYCONTROL_MONITOR_LAYOUT.Flags` — this monitor is the primary.
pub const MONITOR_PRIMARY: u32 = 0x0000_0001;

/// The smallest legal monitor width/height (MS-RDPEDISP 2.2.2.2.1).
pub const MIN_MONITOR_DIMENSION: u32 = 200;
/// The largest legal monitor width/height.
pub const MAX_MONITOR_DIMENSION: u32 = 8192;

/// The size of one `DISPLAYCONTROL_MONITOR_LAYOUT` entry on the wire (`MonitorLayoutSize`
/// MUST be 40 — 2.2.2.2).
const MONITOR_LAYOUT_SIZE: u32 = 40;

/// The server's Display Control capabilities (2.2.2.1). The total area of all monitors in a
/// Monitor Layout must not exceed `max_num_monitors × max_monitor_area_factor_a ×
/// max_monitor_area_factor_b` pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// The maximum number of monitors the server supports.
    pub max_num_monitors: u32,
    /// First factor of the maximum total monitor area.
    pub max_monitor_area_factor_a: u32,
    /// Second factor of the maximum total monitor area.
    pub max_monitor_area_factor_b: u32,
}

impl Caps {
    /// The maximum total monitor area in pixels.
    ///
    /// The three factors are server-supplied `u32`s, so their product can reach
    /// `u32`³ ≈ 2^96 — well past `u64`. A hostile server advertising large factors
    /// must not overflow (a debug-build panic, or a silent release-build wrap) when
    /// the client validates a resize against this limit, so the product **saturates**
    /// at [`u64::MAX`]. Saturation is the right behaviour: an enormous advertised
    /// limit means "effectively unbounded", and the real per-monitor dimension caps
    /// (200–8192, MS-RDPEDISP 2.2.2.2.1) still gate the request.
    pub fn max_area(&self) -> u64 {
        u64::from(self.max_num_monitors)
            .saturating_mul(u64::from(self.max_monitor_area_factor_a))
            .saturating_mul(u64::from(self.max_monitor_area_factor_b))
    }
}

/// One server→client Display Control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayControlPdu {
    /// The server's limits; resize requests are valid only after this arrives.
    Caps(Caps),
    /// A type this client does not consume — well-formed-but-unknown, skipped upstream.
    Unknown {
        /// The header's `Type` field.
        pdu_type: u32,
    },
}

impl DisplayControlPdu {
    /// Decode one complete (DVC-reassembled) Display Control message.
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "DISPLAYCONTROL_HEADER");
        let pdu_type = cur.read_u32_le()?;
        let length = cur.read_u32_le()?;
        if (length as usize) < 8 || (length as usize) > message.len() {
            return Err(DecodeError::InvalidField {
                field: "DISPLAYCONTROL_HEADER.Length",
                reason: "length does not cover the header or exceeds the message",
            });
        }
        match pdu_type {
            TYPE_CAPS => Ok(DisplayControlPdu::Caps(Caps {
                max_num_monitors: cur.read_u32_le()?,
                max_monitor_area_factor_a: cur.read_u32_le()?,
                max_monitor_area_factor_b: cur.read_u32_le()?,
            })),
            pdu_type => Ok(DisplayControlPdu::Unknown { pdu_type }),
        }
    }
}

/// One `DISPLAYCONTROL_MONITOR_LAYOUT` entry (2.2.2.2.1). Every field reaches the wire
/// verbatim — range rules (even width, 200–8192 bounds, caps area) are the caller's policy,
/// enforced where the resize request is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitor {
    /// `Flags` ([`MONITOR_PRIMARY`]).
    pub flags: u32,
    /// X offset of the monitor in the session space.
    pub left: i32,
    /// Y offset of the monitor.
    pub top: i32,
    /// Monitor width in pixels (the spec requires an even value, 200–8192).
    pub width: u32,
    /// Monitor height in pixels (200–8192).
    pub height: u32,
    /// Physical width in millimetres (10–10000, ignored by the server otherwise).
    pub physical_width: u32,
    /// Physical height in millimetres.
    pub physical_height: u32,
    /// Orientation in degrees (0, 90, 180 or 270).
    pub orientation: u32,
    /// Desktop scale factor in percent (100–500).
    pub desktop_scale_factor: u32,
    /// Device scale factor in percent (100, 140 or 180).
    pub device_scale_factor: u32,
}

impl Monitor {
    /// A single primary monitor at the origin with neutral physical/scale metadata — the
    /// shape of a plain "resize the desktop" request.
    pub fn primary(width: u32, height: u32) -> Self {
        Self {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width,
            height,
            physical_width: 0, // outside 10–10000: the server ignores it
            physical_height: 0,
            orientation: 0,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }
    }
}

/// Encode a client→server Monitor Layout PDU (2.2.2.2) for `monitors`.
pub fn encode_monitor_layout(monitors: &[Monitor]) -> Vec<u8> {
    let length = 8 + 8 + monitors.len() * MONITOR_LAYOUT_SIZE as usize;
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&TYPE_MONITOR_LAYOUT.to_le_bytes());
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.extend_from_slice(&MONITOR_LAYOUT_SIZE.to_le_bytes());
    out.extend_from_slice(&(monitors.len() as u32).to_le_bytes());
    for m in monitors {
        out.extend_from_slice(&m.flags.to_le_bytes());
        out.extend_from_slice(&m.left.to_le_bytes());
        out.extend_from_slice(&m.top.to_le_bytes());
        out.extend_from_slice(&m.width.to_le_bytes());
        out.extend_from_slice(&m.height.to_le_bytes());
        out.extend_from_slice(&m.physical_width.to_le_bytes());
        out.extend_from_slice(&m.physical_height.to_le_bytes());
        out.extend_from_slice(&m.orientation.to_le_bytes());
        out.extend_from_slice(&m.desktop_scale_factor.to_le_bytes());
        out.extend_from_slice(&m.device_scale_factor.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_pdu_decodes() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&TYPE_CAPS.to_le_bytes());
        pdu.extend_from_slice(&20u32.to_le_bytes());
        for v in [1u32, 3840, 2160] {
            pdu.extend_from_slice(&v.to_le_bytes());
        }
        let DisplayControlPdu::Caps(caps) = DisplayControlPdu::decode(&pdu).unwrap() else {
            panic!("expected caps");
        };
        assert_eq!(caps.max_num_monitors, 1);
        assert_eq!(caps.max_area(), 3840 * 2160);
    }

    #[test]
    fn max_area_saturates_instead_of_overflowing() {
        // u32³ ≈ 2^96 overflows u64; a hostile server's caps must saturate, not
        // panic (debug) or wrap (release).
        let caps = Caps {
            max_num_monitors: u32::MAX,
            max_monitor_area_factor_a: u32::MAX,
            max_monitor_area_factor_b: u32::MAX,
        };
        assert_eq!(caps.max_area(), u64::MAX);
    }

    #[test]
    fn unknown_type_is_surfaced_not_fatal() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&0x99u32.to_le_bytes());
        pdu.extend_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            DisplayControlPdu::decode(&pdu).unwrap(),
            DisplayControlPdu::Unknown { pdu_type: 0x99 }
        );
    }

    #[test]
    fn bad_header_length_is_a_typed_error() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&TYPE_CAPS.to_le_bytes());
        pdu.extend_from_slice(&200u32.to_le_bytes()); // longer than the message
        pdu.extend_from_slice(&[0; 12]);
        assert!(matches!(
            DisplayControlPdu::decode(&pdu).unwrap_err(),
            DecodeError::InvalidField { .. }
        ));
    }

    #[test]
    fn monitor_layout_wire_shape() {
        let pdu = encode_monitor_layout(&[Monitor::primary(1280, 1024)]);
        assert_eq!(pdu.len(), 56); // 8 header + 8 + 40
        assert_eq!(&pdu[0..4], &TYPE_MONITOR_LAYOUT.to_le_bytes());
        assert_eq!(&pdu[4..8], &56u32.to_le_bytes());
        assert_eq!(&pdu[8..12], &40u32.to_le_bytes()); // MonitorLayoutSize
        assert_eq!(&pdu[12..16], &1u32.to_le_bytes()); // NumMonitors
        assert_eq!(&pdu[16..20], &MONITOR_PRIMARY.to_le_bytes());
        assert_eq!(&pdu[24..28], &0u32.to_le_bytes()); // top
        assert_eq!(&pdu[28..32], &1280u32.to_le_bytes());
        assert_eq!(&pdu[32..36], &1024u32.to_le_bytes());
        assert_eq!(&pdu[48..52], &100u32.to_le_bytes()); // desktop scale
    }
}

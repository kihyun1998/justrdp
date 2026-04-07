#![forbid(unsafe_code)]

//! Display Control DVC client -- MS-RDPEDISP 3.2

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Encode, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    CapsPdu, MonitorLayoutEntry, MonitorLayoutPdu, MAX_MONITOR_DIMENSION, MIN_MONITOR_DIMENSION,
    MONITOR_PRIMARY, PDU_TYPE_CAPS,
};

/// DVC channel name for Display Control.
/// MS-RDPEDISP 1.0
const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::DisplayControl";

/// Display Control DVC client.
///
/// Implements `DvcProcessor` for the `Microsoft::Windows::RDS::DisplayControl`
/// dynamic virtual channel. Receives server capabilities and provides an API
/// for sending monitor layout updates.
pub struct DisplayControlClient {
    /// Server capabilities (set after receiving CapsPdu).
    server_caps: Option<CapsPdu>,
    /// Pending monitor layout to send on next process() call.
    pending_layout: Option<MonitorLayoutPdu>,
}

impl DisplayControlClient {
    /// Create a new Display Control client.
    pub fn new() -> Self {
        Self {
            server_caps: None,
            pending_layout: None,
        }
    }

    /// Returns the server capabilities, if received.
    pub fn server_caps(&self) -> Option<&CapsPdu> {
        self.server_caps.as_ref()
    }

    /// Queue a monitor layout to send to the server.
    ///
    /// The layout will be sent as a DVC message on the next `process()` call,
    /// or can be retrieved via `take_pending_message()` and sent directly.
    ///
    /// Returns an error string if validation fails.
    pub fn set_monitor_layout(&mut self, monitors: Vec<MonitorLayoutEntry>) -> Result<(), String> {
        let caps = self.server_caps.as_ref().ok_or_else(|| {
            String::from("cannot send layout before receiving server capabilities")
        })?;

        self.validate_layout(&monitors, caps)?;
        self.pending_layout = Some(MonitorLayoutPdu::new(monitors));
        Ok(())
    }

    /// Take the pending layout message (if any) as encoded bytes.
    ///
    /// This allows the application to send the layout outside of the
    /// `process()` callback.
    pub fn take_pending_message(&mut self) -> Option<DvcMessage> {
        let pdu = self.pending_layout.take()?;
        encode_pdu(&pdu).ok()
    }

    /// Validate monitor layout against server capabilities and spec constraints.
    fn validate_layout(
        &self,
        monitors: &[MonitorLayoutEntry],
        caps: &CapsPdu,
    ) -> Result<(), String> {
        if monitors.is_empty() {
            return Err(String::from("monitor layout must contain at least one monitor"));
        }

        let count = u32::try_from(monitors.len())
            .map_err(|_| String::from("monitor count exceeds u32 maximum"))?;
        if count > caps.max_num_monitors {
            return Err(String::from("monitor count exceeds server maximum"));
        }

        // Check exactly one primary monitor (MS-RDPEDISP 2.2.2.2.1)
        let primary_count = monitors.iter().filter(|m| m.flags & MONITOR_PRIMARY != 0).count();
        if primary_count != 1 {
            return Err(String::from("exactly one monitor must have PRIMARY flag"));
        }

        // Check primary is at (0, 0)
        for m in monitors {
            if m.flags & MONITOR_PRIMARY != 0 && (m.left != 0 || m.top != 0) {
                return Err(String::from("primary monitor must be at (0, 0)"));
            }
        }

        let mut total_area: u64 = 0;

        for m in monitors {
            // Width: 200–8192, must be even
            if m.width < MIN_MONITOR_DIMENSION || m.width > MAX_MONITOR_DIMENSION {
                return Err(String::from("monitor width must be 200–8192"));
            }
            if m.width & 1 != 0 {
                return Err(String::from("monitor width must be even"));
            }

            // Height: 200–8192
            if m.height < MIN_MONITOR_DIMENSION || m.height > MAX_MONITOR_DIMENSION {
                return Err(String::from("monitor height must be 200–8192"));
            }

            // Orientation: must be 0, 90, 180, or 270 (MS-RDPEDISP 2.2.2.2.1)
            if !matches!(m.orientation, 0 | 90 | 180 | 270) {
                return Err(String::from("orientation must be 0, 90, 180, or 270"));
            }

            // DesktopScaleFactor: 100–500 (MS-RDPEDISP 2.2.2.2.1)
            if m.desktop_scale_factor < 100 || m.desktop_scale_factor > 500 {
                return Err(String::from("desktop scale factor must be 100–500"));
            }

            // DeviceScaleFactor: must be 100, 140, or 180 (MS-RDPEDISP 2.2.2.2.1)
            if !matches!(m.device_scale_factor, 100 | 140 | 180) {
                return Err(String::from("device scale factor must be 100, 140, or 180"));
            }

            total_area += (m.width as u64) * (m.height as u64);
        }

        // Total area must not exceed server limit.
        // If max_total_area() is 0 (server sent zero for any factor), the server
        // effectively advertises no usable area — reject the layout rather than
        // silently treating 0 as "unlimited".
        let max_area = caps.max_total_area();
        if max_area == 0 {
            return Err(String::from("server reported zero maximum monitor area"));
        }
        if total_area > max_area {
            return Err(String::from("total monitor area exceeds server maximum"));
        }

        Ok(())
    }
}

impl Default for DisplayControlClient {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for DisplayControlClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DisplayControlClient")
            .field("server_caps", &self.server_caps.is_some())
            .field("pending_layout", &self.pending_layout.is_some())
            .finish()
    }
}

impl AsAny for DisplayControlClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for DisplayControlClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Client waits for server's DISPLAYCONTROL_CAPS_PDU.
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // Peek at header type to dispatch.
        let mut src = justrdp_core::ReadCursor::new(payload);
        let pdu_type = src.read_u32_le("DisplayControl::Type").map_err(DvcError::Decode)?;

        match pdu_type {
            PDU_TYPE_CAPS => {
                let caps = CapsPdu::decode_from(payload).map_err(DvcError::Decode)?;
                self.server_caps = Some(caps);
                Ok(Vec::new())
            }
            _ => {
                // MS-RDPEDISP: silently ignore unknown PDU types.
                Ok(Vec::new())
            }
        }
    }

    fn close(&mut self, _channel_id: u32) {
        self.server_caps = None;
        self.pending_layout = None;
    }
}

/// Encode a MonitorLayoutPdu into a DvcMessage.
fn encode_pdu(pdu: &MonitorLayoutPdu) -> DvcResult<DvcMessage> {
    let size = pdu.size();
    let mut buf = alloc::vec![0u8; size];
    let mut dst = WriteCursor::new(&mut buf);
    pdu.encode(&mut dst).map_err(DvcError::Encode)?;
    Ok(DvcMessage::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::ORIENTATION_LANDSCAPE;

    fn make_caps_payload(max_monitors: u32, factor_a: u32, factor_b: u32) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 20];
        buf[0..4].copy_from_slice(&PDU_TYPE_CAPS.to_le_bytes());
        buf[4..8].copy_from_slice(&20u32.to_le_bytes());
        buf[8..12].copy_from_slice(&max_monitors.to_le_bytes());
        buf[12..16].copy_from_slice(&factor_a.to_le_bytes());
        buf[16..20].copy_from_slice(&factor_b.to_le_bytes());
        buf
    }

    #[test]
    fn start_returns_empty() {
        let mut client = DisplayControlClient::new();
        let msgs = client.start(1).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn process_caps_sets_server_caps() {
        let mut client = DisplayControlClient::new();
        assert!(client.server_caps().is_none());

        let caps = make_caps_payload(4, 2560, 1600);
        let msgs = client.process(1, &caps).unwrap();
        assert!(msgs.is_empty());

        let sc = client.server_caps().unwrap();
        assert_eq!(sc.max_num_monitors, 4);
        assert_eq!(sc.max_monitor_area_factor_a, 2560);
        assert_eq!(sc.max_monitor_area_factor_b, 1600);
    }

    #[test]
    fn set_layout_before_caps_fails() {
        let mut client = DisplayControlClient::new();
        let result = client.set_monitor_layout(alloc::vec![MonitorLayoutEntry::primary(1920, 1080)]);
        assert!(result.is_err());
    }

    #[test]
    fn set_layout_after_caps_succeeds() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let result = client.set_monitor_layout(alloc::vec![MonitorLayoutEntry::primary(1920, 1080)]);
        assert!(result.is_ok());
    }

    #[test]
    fn take_pending_message_encodes_layout() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();
        client
            .set_monitor_layout(alloc::vec![MonitorLayoutEntry::primary(1920, 1080)])
            .unwrap();

        let msg = client.take_pending_message().unwrap();
        // Verify it decodes back.
        let decoded = MonitorLayoutPdu::decode_from(&msg.data).unwrap();
        assert_eq!(decoded.monitors.len(), 1);
        assert_eq!(decoded.monitors[0].width, 1920);

        // Second take returns None.
        assert!(client.take_pending_message().is_none());
    }

    #[test]
    fn validate_empty_monitors() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();
        assert!(client.set_monitor_layout(alloc::vec![]).is_err());
    }

    #[test]
    fn validate_too_many_monitors() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(1, 2560, 1600)).unwrap();

        let monitors = alloc::vec![
            MonitorLayoutEntry::primary(1920, 1080),
            MonitorLayoutEntry {
                flags: 0,
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
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_no_primary() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: 0, // no PRIMARY
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_two_primaries() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![
            MonitorLayoutEntry::primary(1920, 1080),
            MonitorLayoutEntry {
                flags: MONITOR_PRIMARY,
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
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_primary_not_at_origin() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 100,
            top: 50,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_odd_width() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1921, // odd
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_width_below_min() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(198, 1080)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_width_above_max() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 8200, 8200)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(8194, 1080)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_height_below_min() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(1920, 198)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_height_above_max() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 8200, 8200)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(1920, 8193)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_total_area_exceeds_max() {
        let mut client = DisplayControlClient::new();
        // Max area = 1 * 1920 * 1080 = 2,073,600
        client.process(1, &make_caps_payload(1, 1920, 1080)).unwrap();

        // 2560 * 1440 = 3,686,400 > 2,073,600
        let monitors = alloc::vec![MonitorLayoutEntry::primary(2560, 1440)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_boundary_width_200() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(200, 200)];
        assert!(client.set_monitor_layout(monitors).is_ok());
    }

    #[test]
    fn validate_boundary_width_8192() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 8200, 8200)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(8192, 8192)];
        assert!(client.set_monitor_layout(monitors).is_ok());
    }

    #[test]
    fn close_resets_state() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();
        assert!(client.server_caps().is_some());

        client.close(1);
        assert!(client.server_caps().is_none());
    }

    #[test]
    fn unknown_pdu_type_ignored() {
        let mut client = DisplayControlClient::new();
        // Send a PDU with unknown type.
        let mut buf = alloc::vec![0u8; 20];
        buf[0..4].copy_from_slice(&0xFFu32.to_le_bytes()); // unknown type
        buf[4..8].copy_from_slice(&20u32.to_le_bytes());
        let msgs = client.process(1, &buf).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn validate_multi_monitor_area_exceeds_max() {
        let mut client = DisplayControlClient::new();
        // Max area = 2 * 1920 * 1080 = 4,147,200
        client.process(1, &make_caps_payload(2, 1920, 1080)).unwrap();

        // Two 1920x1080 monitors: total = 2 * 2,073,600 = 4,147,200 (exactly at limit)
        let monitors = alloc::vec![
            MonitorLayoutEntry::primary(1920, 1080),
            MonitorLayoutEntry {
                flags: 0,
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
        assert!(client.set_monitor_layout(monitors).is_ok());

        // Two 2560x1440 monitors: total = 2 * 3,686,400 = 7,372,800 > 4,147,200
        let monitors = alloc::vec![
            MonitorLayoutEntry::primary(2560, 1440),
            MonitorLayoutEntry {
                flags: 0,
                left: 2560,
                top: 0,
                width: 2560,
                height: 1440,
                physical_width: 0,
                physical_height: 0,
                orientation: ORIENTATION_LANDSCAPE,
                desktop_scale_factor: 100,
                device_scale_factor: 100,
            },
        ];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn process_short_payload_returns_error() {
        let mut client = DisplayControlClient::new();
        let short = [0x05, 0x00, 0x00]; // only 3 bytes, need at least 4 for Type
        assert!(client.process(1, &short).is_err());
    }

    #[test]
    fn validate_invalid_orientation() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: 45, // invalid
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_valid_orientations() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        for &orientation in &[0u32, 90, 180, 270] {
            let monitors = alloc::vec![MonitorLayoutEntry {
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
            }];
            assert!(client.set_monitor_layout(monitors).is_ok(), "orientation {orientation} should be valid");
        }
    }

    #[test]
    fn validate_desktop_scale_factor_below_min() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 99, // below 100
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_desktop_scale_factor_above_max() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 501, // above 500
            device_scale_factor: 100,
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_invalid_device_scale_factor() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width: 0,
            physical_height: 0,
            orientation: ORIENTATION_LANDSCAPE,
            desktop_scale_factor: 100,
            device_scale_factor: 120, // not 100/140/180
        }];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn validate_valid_device_scale_factors() {
        let mut client = DisplayControlClient::new();
        client.process(1, &make_caps_payload(4, 2560, 1600)).unwrap();

        for &dsf in &[100u32, 140, 180] {
            let monitors = alloc::vec![MonitorLayoutEntry {
                flags: MONITOR_PRIMARY,
                left: 0,
                top: 0,
                width: 1920,
                height: 1080,
                physical_width: 0,
                physical_height: 0,
                orientation: ORIENTATION_LANDSCAPE,
                desktop_scale_factor: 100,
                device_scale_factor: dsf,
            }];
            assert!(client.set_monitor_layout(monitors).is_ok(), "device_scale_factor {dsf} should be valid");
        }
    }

    #[test]
    fn validate_zero_area_caps_rejected() {
        let mut client = DisplayControlClient::new();
        // Server advertises factor_a=0 → max_total_area() = 0
        client.process(1, &make_caps_payload(4, 0, 1600)).unwrap();

        let monitors = alloc::vec![MonitorLayoutEntry::primary(1920, 1080)];
        assert!(client.set_monitor_layout(monitors).is_err());
    }

    #[test]
    fn channel_name_matches_spec() {
        let client = DisplayControlClient::new();
        assert_eq!(client.channel_name(), "Microsoft::Windows::RDS::DisplayControl");
    }
}

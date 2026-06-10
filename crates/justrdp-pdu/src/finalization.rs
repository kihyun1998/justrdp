//! Connection finalization PDUs (MS-RDPBCGR 2.2.1.14–2.2.1.22): Synchronize, Control, Font
//! List / Font Map — the `activation` stage. The client pipelines Synchronize →
//! Control(Cooperate) → Control(Request Control) → Font List in one batch; the server's Font
//! Map is the session-active gate. These are Share **Data** PDU bodies — frame them with
//! [`crate::share::encode_share_data`].

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `messageType` of the Synchronize PDU — always 1 (SYNCMSGTYPE_SYNC).
const SYNC_MSG_TYPE: u16 = 1;

/// `action`: Request Control.
pub const CTRLACTION_REQUEST_CONTROL: u16 = 0x0001;
/// `action`: Granted Control.
pub const CTRLACTION_GRANTED_CONTROL: u16 = 0x0002;
/// `action`: Detach.
pub const CTRLACTION_DETACH: u16 = 0x0003;
/// `action`: Cooperate.
pub const CTRLACTION_COOPERATE: u16 = 0x0004;

/// A Synchronize PDU (TS_SYNCHRONIZE_PDU). `target_user` echoes the server's user channel ID
/// in the client copy; the server's copy targets the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Synchronize {
    /// `targetUser` — an MCS user channel ID.
    pub target_user: u16,
}

impl Synchronize {
    /// Encode the Share Data body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&SYNC_MSG_TYPE.to_le_bytes());
        out.extend_from_slice(&self.target_user.to_le_bytes());
        out
    }

    /// Decode the Share Data body.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u16_le()?; // messageType (ignored per spec)
        let target_user = cur.read_u16_le()?;
        Ok(Self { target_user })
    }
}

/// A Control PDU (TS_CONTROL_PDU) — used for Cooperate, Request Control, and Granted Control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    /// `action` (one of the `CTRLACTION_*` constants).
    pub action: u16,
    /// `grantId` — the granted user's channel ID in Granted Control; 0 in client copies.
    pub grant_id: u16,
    /// `controlId` — the granting user's ID in Granted Control; 0 in client copies.
    pub control_id: u32,
}

impl Control {
    /// A client-side Control PDU: only the action is meaningful.
    pub fn new(action: u16) -> Self {
        Self {
            action,
            grant_id: 0,
            control_id: 0,
        }
    }

    /// Encode the Share Data body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.action.to_le_bytes());
        out.extend_from_slice(&self.grant_id.to_le_bytes());
        out.extend_from_slice(&self.control_id.to_le_bytes());
        out
    }

    /// Decode the Share Data body.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let action = cur.read_u16_le()?;
        let grant_id = cur.read_u16_le()?;
        let control_id = cur.read_u32_le()?;
        Ok(Self {
            action,
            grant_id,
            control_id,
        })
    }
}

/// `listFlags` / `mapFlags`: this PDU is the first in the sequence.
const FONTLIST_FIRST: u16 = 0x0001;
/// `listFlags` / `mapFlags`: this PDU is the last in the sequence.
const FONTLIST_LAST: u16 = 0x0002;

/// Encode a Font List PDU body (TS_FONT_LIST_PDU). All fields carry the fixed values
/// MS-RDPBCGR mandates for the (only) single-PDU form: no actual font entries, FIRST|LAST,
/// entry size 0x0032.
pub fn encode_font_list() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&0u16.to_le_bytes()); // numberFonts (SHOULD 0)
    out.extend_from_slice(&0u16.to_le_bytes()); // totalNumFonts (SHOULD 0)
    out.extend_from_slice(&(FONTLIST_FIRST | FONTLIST_LAST).to_le_bytes());
    out.extend_from_slice(&0x0032u16.to_le_bytes()); // entrySize (SHOULD 0x0032)
    out
}

/// A Font Map PDU (TS_FONT_MAP_PDU) — the server's last finalization message. Arrival (and
/// successful decode) is the session-active gate; the field values are ignored per spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FontMap {
    /// `mapFlags` — FIRST|LAST (0x0003) in practice.
    pub map_flags: u16,
}

impl FontMap {
    /// Decode the Share Data body. Windows sends 8 bytes; all but `mapFlags` are ignored.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u16_le()?; // numberEntries (ignored)
        cur.read_u16_le()?; // totalNumEntries (ignored)
        let map_flags = cur.read_u16_le()?;
        cur.read_u16_le()?; // entrySize (ignored)
        Ok(Self { map_flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronize_round_trips() {
        let body = Synchronize { target_user: 1002 }.encode();
        assert_eq!(body, [0x01, 0x00, 0xEA, 0x03]);
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            Synchronize::decode(&mut cur).unwrap(),
            Synchronize { target_user: 1002 }
        );
    }

    #[test]
    fn control_round_trips() {
        let body = Control::new(CTRLACTION_COOPERATE).encode();
        assert_eq!(body, [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let granted = [0x02, 0x00, 0xEB, 0x03, 0xEA, 0x03, 0x00, 0x00];
        let mut cur = ReadCursor::new(&granted, "test");
        let control = Control::decode(&mut cur).unwrap();
        assert_eq!(control.action, CTRLACTION_GRANTED_CONTROL);
        assert_eq!(control.grant_id, 1003);
        assert_eq!(control.control_id, 1002);
    }

    #[test]
    fn font_list_pins_mandated_values() {
        assert_eq!(
            encode_font_list(),
            [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00]
        );
    }

    #[test]
    fn font_map_decodes() {
        let body = [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00];
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(FontMap::decode(&mut cur).unwrap().map_flags, 0x0003);
    }
}

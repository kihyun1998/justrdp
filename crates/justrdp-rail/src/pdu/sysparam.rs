#![forbid(unsafe_code)]

//! System Parameters PDU -- MS-RDPERP 2.2.2.4

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{read_unicode_string, write_unicode_string, RailHeader, RailOrderType, RailRect16, RAIL_HEADER_SIZE};

// ── SystemParam constants -- MS-RDPERP 2.2.2.4 ──

pub const SPI_SETDRAGFULLWINDOWS: u32 = 0x0000_0025;
pub const SPI_SETKEYBOARDCUES: u32 = 0x0000_100B;
pub const SPI_SETKEYBOARDPREF: u32 = 0x0000_0045;
pub const SPI_SETMOUSEBUTTONSWAP: u32 = 0x0000_0021;
pub const SPI_SETWORKAREA: u32 = 0x0000_002F;
pub const SPI_SETHIGHCONTRAST: u32 = 0x0000_0043;
pub const SPI_SETCARETWIDTH: u32 = 0x0000_2007;
pub const SPI_SETSTICKYKEYS: u32 = 0x0000_003B;
pub const SPI_SETTOGGLEKEYS: u32 = 0x0000_0035;
pub const SPI_SETFILTERKEYS: u32 = 0x0000_0033;
pub const RAIL_SPI_DISPLAYCHANGE: u32 = 0x0000_F001;
pub const RAIL_SPI_TASKBARPOS: u32 = 0x0000_F000;

// ── TS_HIGHCONTRAST flags -- MS-RDPERP 2.2.1.2.5 ──

pub const HCF_HIGHCONTRASTON: u32 = 0x0000_0001;
pub const HCF_AVAILABLE: u32 = 0x0000_0002;
pub const HCF_HOTKEYACTIVE: u32 = 0x0000_0004;
pub const HCF_CONFIRMHOTKEY: u32 = 0x0000_0008;
pub const HCF_HOTKEYSOUND: u32 = 0x0000_0010;

/// TS_HIGHCONTRAST -- MS-RDPERP 2.2.1.2.5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighContrast {
    pub flags: u32,
    /// Color scheme (UNICODE_STRING body, UTF-16LE).
    pub color_scheme: Vec<u8>,
}

impl HighContrast {
    pub fn size(&self) -> usize {
        // Flags(4) + ColorSchemeLength(4) + ColorScheme(variable via UNICODE_STRING cbString+body)
        4 + 4 + 2 + self.color_scheme.len()
    }
}

/// System parameter body variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysParamBody {
    /// Boolean parameter (1 byte).
    Bool(bool),
    /// Rectangle parameter (8 bytes).
    Rect(RailRect16),
    /// High contrast settings (variable).
    HighContrast(HighContrast),
    /// u32 parameter (4 bytes, e.g., SPI_SETCARETWIDTH).
    Dword(u32),
    /// Filter keys (20 bytes).
    FilterKeys {
        flags: u32,
        wait_ms: u32,
        delay_ms: u32,
        repeat_ms: u32,
        bounce_ms: u32,
    },
}

/// System Parameters Update PDU -- MS-RDPERP 2.2.2.4.1 / 2.2.2.4.2
///
/// Bidirectional: same format for client→server and server→client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysParamPdu {
    /// The system parameter type.
    pub system_param: u32,
    /// The parameter body.
    pub body: SysParamBody,
}

impl SysParamPdu {
    pub fn new_bool(param: u32, value: bool) -> Self {
        Self {
            system_param: param,
            body: SysParamBody::Bool(value),
        }
    }

    pub fn new_rect(param: u32, rect: RailRect16) -> Self {
        Self {
            system_param: param,
            body: SysParamBody::Rect(rect),
        }
    }

    pub fn new_high_contrast(flags: u32, color_scheme: Vec<u8>) -> Self {
        Self {
            system_param: SPI_SETHIGHCONTRAST,
            body: SysParamBody::HighContrast(HighContrast { flags, color_scheme }),
        }
    }

    fn body_size(&self) -> usize {
        match &self.body {
            SysParamBody::Bool(_) => 1,
            SysParamBody::Rect(_) => 8,
            SysParamBody::HighContrast(hc) => hc.size(),
            SysParamBody::Dword(_) => 4,
            SysParamBody::FilterKeys { .. } => 20,
        }
    }
}

impl Encode for SysParamPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(
            RailOrderType::SysParam,
            u16::try_from(self.size()).map_err(|_| EncodeError::other("SysParamPdu", "size"))?,
        );
        header.encode(dst)?;
        dst.write_u32_le(self.system_param, "Sysparam::SystemParam")?;

        match &self.body {
            SysParamBody::Bool(v) => {
                dst.write_u8(u8::from(*v), "Sysparam::BoolBody")?;
            }
            SysParamBody::Rect(r) => {
                r.encode(dst)?;
            }
            SysParamBody::HighContrast(hc) => {
                dst.write_u32_le(hc.flags, "HighContrast::Flags")?;
                let cs_len = u32::try_from(2_usize + hc.color_scheme.len())
                    .map_err(|_| EncodeError::other("HighContrast", "ColorSchemeLength"))?;
                dst.write_u32_le(cs_len, "HighContrast::ColorSchemeLength")?;
                write_unicode_string(dst, &hc.color_scheme, "HighContrast::ColorScheme")?;
            }
            SysParamBody::Dword(v) => {
                dst.write_u32_le(*v, "Sysparam::DwordBody")?;
            }
            SysParamBody::FilterKeys {
                flags,
                wait_ms,
                delay_ms,
                repeat_ms,
                bounce_ms,
            } => {
                dst.write_u32_le(*flags, "FilterKeys::Flags")?;
                dst.write_u32_le(*wait_ms, "FilterKeys::WaitMs")?;
                dst.write_u32_le(*delay_ms, "FilterKeys::DelayMs")?;
                dst.write_u32_le(*repeat_ms, "FilterKeys::RepeatMs")?;
                dst.write_u32_le(*bounce_ms, "FilterKeys::BounceMs")?;
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SysParamPdu"
    }

    fn size(&self) -> usize {
        RAIL_HEADER_SIZE + 4 + self.body_size()
    }
}

impl<'de> Decode<'de> for SysParamPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let system_param = src.read_u32_le("Sysparam::SystemParam")?;

        let body = match system_param {
            SPI_SETDRAGFULLWINDOWS | SPI_SETKEYBOARDCUES | SPI_SETKEYBOARDPREF
            | SPI_SETMOUSEBUTTONSWAP => {
                let v = src.read_u8("Sysparam::BoolBody")?;
                SysParamBody::Bool(v != 0)
            }
            SPI_SETWORKAREA | RAIL_SPI_DISPLAYCHANGE | RAIL_SPI_TASKBARPOS => {
                let rect = RailRect16::decode(src)?;
                SysParamBody::Rect(rect)
            }
            SPI_SETHIGHCONTRAST => {
                let flags = src.read_u32_le("HighContrast::Flags")?;
                let color_scheme_length = src.read_u32_le("HighContrast::ColorSchemeLength")?;
                // ColorSchemeLength includes the UNICODE_STRING cbString(2) + body
                let color_scheme = if color_scheme_length >= 2 {
                    let cs = read_unicode_string(src, "HighContrast::ColorScheme", 520)?;
                    // Cross-validate: ColorSchemeLength must equal cbString(2) + body length
                    if color_scheme_length != 2 + cs.len() as u32 {
                        return Err(DecodeError::invalid_value(
                            "HighContrast",
                            "ColorSchemeLength",
                        ));
                    }
                    cs
                } else if color_scheme_length == 0 {
                    Vec::new()
                } else {
                    return Err(DecodeError::invalid_value(
                        "HighContrast",
                        "ColorSchemeLength",
                    ));
                };
                SysParamBody::HighContrast(HighContrast {
                    flags,
                    color_scheme,
                })
            }
            SPI_SETCARETWIDTH | SPI_SETSTICKYKEYS | SPI_SETTOGGLEKEYS => {
                let v = src.read_u32_le("Sysparam::DwordBody")?;
                SysParamBody::Dword(v)
            }
            SPI_SETFILTERKEYS => {
                let flags = src.read_u32_le("FilterKeys::Flags")?;
                let wait_ms = src.read_u32_le("FilterKeys::WaitMs")?;
                let delay_ms = src.read_u32_le("FilterKeys::DelayMs")?;
                let repeat_ms = src.read_u32_le("FilterKeys::RepeatMs")?;
                let bounce_ms = src.read_u32_le("FilterKeys::BounceMs")?;
                SysParamBody::FilterKeys {
                    flags,
                    wait_ms,
                    delay_ms,
                    repeat_ms,
                    bounce_ms,
                }
            }
            // Extended SPI 2/3 params: treat as bool (1 byte) or dword (4 bytes)
            0xF002..=0xF00E => {
                let v = src.read_u8("Sysparam::ExtendedBoolBody")?;
                SysParamBody::Bool(v != 0)
            }
            0xF010 | 0xF011 => {
                let v = src.read_u32_le("Sysparam::ExtendedDwordBody")?;
                SysParamBody::Dword(v)
            }
            _ => {
                return Err(DecodeError::invalid_value("SysParamPdu", "SystemParam"));
            }
        };

        Ok(Self { system_param, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysparam_bool_roundtrip() {
        let pdu = SysParamPdu::new_bool(SPI_SETDRAGFULLWINDOWS, true);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::SysParam);
        let decoded = SysParamPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn sysparam_rect_roundtrip() {
        let pdu = SysParamPdu::new_rect(
            SPI_SETWORKAREA,
            RailRect16 {
                left: 0,
                top: 0,
                right: 1920,
                bottom: 1040,
            },
        );
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = SysParamPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    /// Test vector from MS-RDPERP 4.1.6
    #[test]
    fn sysparam_high_contrast_spec_vector() {
        let bytes: &[u8] = &[
            0x03, 0x00, // orderType = TS_RAIL_ORDER_SYSPARAM
            0x12, 0x00, // orderLength = 18
            0x43, 0x00, 0x00, 0x00, // SystemParam = SPI_SETHIGHCONTRAST
            0x7e, 0x00, 0x00, 0x00, // Flags = 0x7E
            0x02, 0x00, 0x00, 0x00, // ColorSchemeLength = 2
            0x00, 0x00, // ColorScheme = UNICODE_STRING (cbString=0, no body)
        ];

        let mut cursor = ReadCursor::new(bytes);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::SysParam);
        assert_eq!(header.order_length, 18);
        let decoded = SysParamPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.system_param, SPI_SETHIGHCONTRAST);
        match &decoded.body {
            SysParamBody::HighContrast(hc) => {
                assert_eq!(hc.flags, 0x7E);
                assert!(hc.color_scheme.is_empty());
            }
            _ => panic!("expected HighContrast"),
        }
    }

    #[test]
    fn sysparam_filter_keys_roundtrip() {
        let pdu = SysParamPdu {
            system_param: SPI_SETFILTERKEYS,
            body: SysParamBody::FilterKeys {
                flags: 0x01,
                wait_ms: 500,
                delay_ms: 1000,
                repeat_ms: 300,
                bounce_ms: 0,
            },
        };
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = SysParamPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}

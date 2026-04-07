#![forbid(unsafe_code)]

//! MS-RDPESC Smart Card constants.
//!
//! All values are taken directly from [MS-RDPESC] with spec section references
//! in comments. This file contains constants only — no structs or encoding logic.

// =============================================================================
// IOCTL Codes (MS-RDPESC 3.2.5)
// =============================================================================

pub const SCARD_IOCTL_ESTABLISHCONTEXT: u32 = 0x0009_0014;
pub const SCARD_IOCTL_RELEASECONTEXT: u32 = 0x0009_0018;
pub const SCARD_IOCTL_ISVALIDCONTEXT: u32 = 0x0009_001C;
pub const SCARD_IOCTL_LISTREADERGROUPSA: u32 = 0x0009_0020;
pub const SCARD_IOCTL_LISTREADERGROUPSW: u32 = 0x0009_0024;
pub const SCARD_IOCTL_LISTREADERSA: u32 = 0x0009_0028;
pub const SCARD_IOCTL_LISTREADERSW: u32 = 0x0009_002C;
pub const SCARD_IOCTL_INTRODUCEREADERGROUPA: u32 = 0x0009_0050;
pub const SCARD_IOCTL_INTRODUCEREADERGROUPW: u32 = 0x0009_0054;
pub const SCARD_IOCTL_FORGETREADERGROUPA: u32 = 0x0009_0058;
pub const SCARD_IOCTL_FORGETREADERGROUPW: u32 = 0x0009_005C;
pub const SCARD_IOCTL_INTRODUCEREADERA: u32 = 0x0009_0060;
pub const SCARD_IOCTL_INTRODUCEREADERW: u32 = 0x0009_0064;
pub const SCARD_IOCTL_FORGETREADERA: u32 = 0x0009_0068;
pub const SCARD_IOCTL_FORGETREADERW: u32 = 0x0009_006C;
pub const SCARD_IOCTL_ADDREADERTOGROUPA: u32 = 0x0009_0070;
pub const SCARD_IOCTL_ADDREADERTOGROUPW: u32 = 0x0009_0074;
pub const SCARD_IOCTL_REMOVEREADERFROMGROUPA: u32 = 0x0009_0078;
pub const SCARD_IOCTL_REMOVEREADERFROMGROUPW: u32 = 0x0009_007C;
pub const SCARD_IOCTL_LOCATECARDSA: u32 = 0x0009_0098;
pub const SCARD_IOCTL_LOCATECARDSW: u32 = 0x0009_009C;
pub const SCARD_IOCTL_GETSTATUSCHANGEA: u32 = 0x0009_00A0;
pub const SCARD_IOCTL_GETSTATUSCHANGEW: u32 = 0x0009_00A4;
pub const SCARD_IOCTL_CANCEL: u32 = 0x0009_00A8;
pub const SCARD_IOCTL_CONNECTA: u32 = 0x0009_00AC;
pub const SCARD_IOCTL_CONNECTW: u32 = 0x0009_00B0;
pub const SCARD_IOCTL_RECONNECT: u32 = 0x0009_00B4;
pub const SCARD_IOCTL_DISCONNECT: u32 = 0x0009_00B8;
pub const SCARD_IOCTL_BEGINTRANSACTION: u32 = 0x0009_00BC;
pub const SCARD_IOCTL_ENDTRANSACTION: u32 = 0x0009_00C0;
pub const SCARD_IOCTL_STATE: u32 = 0x0009_00C4;
pub const SCARD_IOCTL_STATUSA: u32 = 0x0009_00C8;
pub const SCARD_IOCTL_STATUSW: u32 = 0x0009_00CC;
pub const SCARD_IOCTL_TRANSMIT: u32 = 0x0009_00D0;
pub const SCARD_IOCTL_CONTROL: u32 = 0x0009_00D4;
pub const SCARD_IOCTL_GETATTRIB: u32 = 0x0009_00D8;
pub const SCARD_IOCTL_SETATTRIB: u32 = 0x0009_00DC;
pub const SCARD_IOCTL_ACCESSSTARTEDEVENT: u32 = 0x0009_00E0;
pub const SCARD_IOCTL_RELEASESTARTEDEVENT: u32 = 0x0009_00E4;
pub const SCARD_IOCTL_LOCATECARDSBYATRA: u32 = 0x0009_00E8;
pub const SCARD_IOCTL_LOCATECARDSBYATRW: u32 = 0x0009_00EC;
pub const SCARD_IOCTL_READCACHEA: u32 = 0x0009_00F0;
pub const SCARD_IOCTL_READCACHEW: u32 = 0x0009_00F4;
pub const SCARD_IOCTL_WRITECACHEA: u32 = 0x0009_00F8;
pub const SCARD_IOCTL_WRITECACHEW: u32 = 0x0009_00FC;
pub const SCARD_IOCTL_GETTRANSMITCOUNT: u32 = 0x0009_0100;
pub const SCARD_IOCTL_GETREADERICON: u32 = 0x0009_0104;
pub const SCARD_IOCTL_GETDEVICETYPEID: u32 = 0x0009_0108;

// =============================================================================
// Scope Values (MS-RDPESC 2.2.2.1)
// =============================================================================

pub const SCARD_SCOPE_USER: u32 = 0x0000_0000;
pub const SCARD_SCOPE_TERMINAL: u32 = 0x0000_0001;
pub const SCARD_SCOPE_SYSTEM: u32 = 0x0000_0002;

// =============================================================================
// Disposition Values (MS-RDPESC 2.2.2.16)
// =============================================================================

pub const SCARD_LEAVE_CARD: u32 = 0x0000_0000;
pub const SCARD_RESET_CARD: u32 = 0x0000_0001;
pub const SCARD_UNPOWER_CARD: u32 = 0x0000_0002;
pub const SCARD_EJECT_CARD: u32 = 0x0000_0003;

// =============================================================================
// Share Mode (MS-RDPESC 2.2.2.13)
// =============================================================================

pub const SCARD_SHARE_EXCLUSIVE: u32 = 0x0000_0001;
pub const SCARD_SHARE_SHARED: u32 = 0x0000_0002;
pub const SCARD_SHARE_DIRECT: u32 = 0x0000_0003;

// =============================================================================
// Protocol IDs (MS-RDPESC 2.2.5)
// =============================================================================

pub const SCARD_PROTOCOL_UNDEFINED: u32 = 0x0000_0000;
pub const SCARD_PROTOCOL_T0: u32 = 0x0000_0001;
pub const SCARD_PROTOCOL_T1: u32 = 0x0000_0002;
pub const SCARD_PROTOCOL_TX: u32 = 0x0000_0003;
pub const SCARD_PROTOCOL_RAW: u32 = 0x0001_0000;
pub const SCARD_PROTOCOL_DEFAULT: u32 = 0x8000_0000;

// =============================================================================
// Special Values
// =============================================================================

pub const SCARD_AUTOALLOCATE: u32 = 0xFFFF_FFFF;
pub const SCARD_INFINITE: u32 = 0xFFFF_FFFF;

// =============================================================================
// Return Codes (MS-RDPESC 2.2.4)
// =============================================================================

pub const SCARD_S_SUCCESS: u32 = 0x0000_0000;
pub const SCARD_F_INTERNAL_ERROR: u32 = 0x8010_0001;
pub const SCARD_E_CANCELLED: u32 = 0x8010_0002;
pub const SCARD_E_INVALID_HANDLE: u32 = 0x8010_0003;
pub const SCARD_E_INVALID_PARAMETER: u32 = 0x8010_0004;
pub const SCARD_E_NO_MEMORY: u32 = 0x8010_0006;
pub const SCARD_E_INSUFFICIENT_BUFFER: u32 = 0x8010_0008;
pub const SCARD_E_UNKNOWN_READER: u32 = 0x8010_0009;
pub const SCARD_E_TIMEOUT: u32 = 0x8010_000A;
pub const SCARD_E_SHARING_VIOLATION: u32 = 0x8010_000B;
pub const SCARD_E_NO_SMARTCARD: u32 = 0x8010_000C;
pub const SCARD_E_PROTO_MISMATCH: u32 = 0x8010_000F;
pub const SCARD_E_NOT_READY: u32 = 0x8010_0010;
pub const SCARD_E_INVALID_VALUE: u32 = 0x8010_0011;
pub const SCARD_E_SYSTEM_CANCELLED: u32 = 0x8010_0012;
pub const SCARD_E_NOT_TRANSACTED: u32 = 0x8010_0016;
pub const SCARD_E_READER_UNAVAILABLE: u32 = 0x8010_0017;
pub const SCARD_E_NO_SERVICE: u32 = 0x8010_001D;
pub const SCARD_E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
pub const SCARD_W_UNSUPPORTED_CARD: u32 = 0x8010_0065;
pub const SCARD_W_UNRESPONSIVE_CARD: u32 = 0x8010_0066;
pub const SCARD_W_UNPOWERED_CARD: u32 = 0x8010_0067;
pub const SCARD_W_RESET_CARD: u32 = 0x8010_0068;
pub const SCARD_W_REMOVED_CARD: u32 = 0x8010_0069;

// =============================================================================
// Helper
// =============================================================================

/// Returns the human-readable name of an SCARD IOCTL code for debugging.
pub fn ioctl_name(code: u32) -> &'static str {
    match code {
        SCARD_IOCTL_ESTABLISHCONTEXT => "EstablishContext",
        SCARD_IOCTL_RELEASECONTEXT => "ReleaseContext",
        SCARD_IOCTL_ISVALIDCONTEXT => "IsValidContext",
        SCARD_IOCTL_LISTREADERGROUPSA => "ListReaderGroupsA",
        SCARD_IOCTL_LISTREADERGROUPSW => "ListReaderGroupsW",
        SCARD_IOCTL_LISTREADERSA => "ListReadersA",
        SCARD_IOCTL_LISTREADERSW => "ListReadersW",
        SCARD_IOCTL_INTRODUCEREADERGROUPA => "IntroduceReaderGroupA",
        SCARD_IOCTL_INTRODUCEREADERGROUPW => "IntroduceReaderGroupW",
        SCARD_IOCTL_FORGETREADERGROUPA => "ForgetReaderGroupA",
        SCARD_IOCTL_FORGETREADERGROUPW => "ForgetReaderGroupW",
        SCARD_IOCTL_INTRODUCEREADERA => "IntroduceReaderA",
        SCARD_IOCTL_INTRODUCEREADERW => "IntroduceReaderW",
        SCARD_IOCTL_FORGETREADERA => "ForgetReaderA",
        SCARD_IOCTL_FORGETREADERW => "ForgetReaderW",
        SCARD_IOCTL_ADDREADERTOGROUPA => "AddReaderToGroupA",
        SCARD_IOCTL_ADDREADERTOGROUPW => "AddReaderToGroupW",
        SCARD_IOCTL_REMOVEREADERFROMGROUPA => "RemoveReaderFromGroupA",
        SCARD_IOCTL_REMOVEREADERFROMGROUPW => "RemoveReaderFromGroupW",
        SCARD_IOCTL_LOCATECARDSA => "LocateCardsA",
        SCARD_IOCTL_LOCATECARDSW => "LocateCardsW",
        SCARD_IOCTL_GETSTATUSCHANGEA => "GetStatusChangeA",
        SCARD_IOCTL_GETSTATUSCHANGEW => "GetStatusChangeW",
        SCARD_IOCTL_CANCEL => "Cancel",
        SCARD_IOCTL_CONNECTA => "ConnectA",
        SCARD_IOCTL_CONNECTW => "ConnectW",
        SCARD_IOCTL_RECONNECT => "Reconnect",
        SCARD_IOCTL_DISCONNECT => "Disconnect",
        SCARD_IOCTL_BEGINTRANSACTION => "BeginTransaction",
        SCARD_IOCTL_ENDTRANSACTION => "EndTransaction",
        SCARD_IOCTL_STATE => "State",
        SCARD_IOCTL_STATUSA => "StatusA",
        SCARD_IOCTL_STATUSW => "StatusW",
        SCARD_IOCTL_TRANSMIT => "Transmit",
        SCARD_IOCTL_CONTROL => "Control",
        SCARD_IOCTL_GETATTRIB => "GetAttrib",
        SCARD_IOCTL_SETATTRIB => "SetAttrib",
        SCARD_IOCTL_ACCESSSTARTEDEVENT => "AccessStartedEvent",
        SCARD_IOCTL_RELEASESTARTEDEVENT => "ReleaseStartedEvent",
        SCARD_IOCTL_LOCATECARDSBYATRA => "LocateCardsByAtrA",
        SCARD_IOCTL_LOCATECARDSBYATRW => "LocateCardsByAtrW",
        SCARD_IOCTL_READCACHEA => "ReadCacheA",
        SCARD_IOCTL_READCACHEW => "ReadCacheW",
        SCARD_IOCTL_WRITECACHEA => "WriteCacheA",
        SCARD_IOCTL_WRITECACHEW => "WriteCacheW",
        SCARD_IOCTL_GETTRANSMITCOUNT => "GetTransmitCount",
        SCARD_IOCTL_GETREADERICON => "GetReaderIcon",
        SCARD_IOCTL_GETDEVICETYPEID => "GetDeviceTypeId",
        _ => "Unknown",
    }
}

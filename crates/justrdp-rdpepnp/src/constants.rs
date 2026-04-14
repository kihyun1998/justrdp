//! MS-RDPEPNP wire constants.
//!
//! All values are taken verbatim from the MS-RDPEPNP v22.0 specification.
//! Each constant is annotated with the spec section it appears in.

/// PNP Device Info Sub-protocol DVC channel name (MS-RDPEPNP §2.1).
///
/// A single instance of this channel carries the control traffic
/// (version negotiation, authentication signal, device add/remove).
pub const PNPDR_CHANNEL_NAME: &str = "PNPDR";

/// Size in bytes of [`crate::pdu::PnpInfoHeader`] (MS-RDPEPNP §2.2.1.1).
///
/// The header is `Size: u32 LE + PacketId: u32 LE` and is included in the
/// `Size` field value.
pub const PNP_INFO_HEADER_SIZE: usize = 8;

/// Capability bit indicating dynamic device addition support
/// (MS-RDPEPNP §2.2.1.2.1 / §2.2.1.2.2). Currently the only defined bit.
pub const PNP_CAP_DYNAMIC_DEVICE_ADDITION: u32 = 0x0000_0001;

/// `PacketId` values carried by [`crate::pdu::PnpInfoHeader`]
/// (MS-RDPEPNP §2.2.1.1).
pub mod packet_id {
    /// Server Version Message (S→C) / Client Version Message (C→S).
    /// Direction disambiguates which of the two is intended.
    pub const IRPDR_ID_VERSION: u32 = 0x0000_0065;

    /// Client Device Addition Message (C→S) — announces one or more
    /// `PNP_DEVICE_DESCRIPTION` entries.
    pub const IRPDR_ID_REDIRECT_DEVICES: u32 = 0x0000_0066;

    /// Authenticated Client Message (S→C) — tells the client that user
    /// logon has completed and it may now send device announcements.
    pub const IRPDR_ID_SERVER_LOGON: u32 = 0x0000_0067;

    /// Client Device Removal Message (C→S) — requests the server stop
    /// redirecting the named device.
    pub const IRPDR_ID_UNREDIRECT_DEVICE: u32 = 0x0000_0068;
}

/// `CustomFlag` values in `PNP_DEVICE_DESCRIPTION` (MS-RDPEPNP §2.2.1.3.1.1).
pub mod custom_flag {
    /// Redirectable — server MUST redirect.
    pub const REDIRECTABLE: u32 = 0x0000_0000;
    /// Optionally redirectable — server MAY skip.
    pub const OPTIONAL: u32 = 0x0000_0001;
    /// Redirectable — same semantics as [`REDIRECTABLE`].
    pub const REDIRECTABLE_ALT: u32 = 0x0000_0002;
}

/// Fixed value of `CustomFlagLength` in `PNP_DEVICE_DESCRIPTION`
/// (MS-RDPEPNP §2.2.1.3.1.1) — always 4 bytes (size of the `CustomFlag` u32).
pub const CUSTOM_FLAG_LENGTH: u32 = 0x0000_0004;

/// Fixed value of `cbContainerId` when the optional `ContainerId` field is
/// present (MS-RDPEPNP §2.2.1.3.1.1) — always 0x10 (16 bytes = GUID size).
pub const CB_CONTAINER_ID: u32 = 0x0000_0010;

/// Fixed value of `cbDeviceCaps` when the optional `DeviceCaps` field is
/// present (MS-RDPEPNP §2.2.1.3.1.1) — always 0x04 (4 bytes = u32 flags).
pub const CB_DEVICE_CAPS: u32 = 0x0000_0004;

/// `DeviceCaps` bit flags (MS-RDPEPNP §2.2.1.3.1.1, Appendix A §<8>).
pub mod device_caps {
    pub const PNP_DEVCAPS_LOCKSUPPORTED: u32 = 0x0000_0001;
    pub const PNP_DEVCAPS_EJECTSUPPORTED: u32 = 0x0000_0002;
    pub const PNP_DEVCAPS_REMOVABLE: u32 = 0x0000_0004;
    pub const PNP_DEVCAPS_SURPRISEREMOVALOK: u32 = 0x0000_0008;
}

// ── DoS caps (shared between inbound decode and outbound validation) ──

/// Maximum number of simultaneously tracked client devices. Enforced on
/// both the outbound `add_device` path and the inbound decoder so a
/// compromised server cannot amplify heap usage by sending a huge
/// `DeviceCount`.
pub const MAX_DEVICES: usize = 256;

/// Maximum accepted length of `InterfaceGUIDArray` (bytes). At 16 bytes
/// per GUID this caps at 16 interface GUIDs per device.
pub const MAX_INTERFACE_BYTES: usize = 256;

/// Maximum accepted length of `HardwareId` / `CompatibilityID` byte
/// arrays. A Windows hardware-ID multisz rarely exceeds a few hundred
/// bytes in practice.
pub const MAX_HARDWARE_ID_BYTES: usize = 1024;

/// Maximum accepted length of `DeviceDescription` (UTF-16LE, 2 bytes/char).
pub const MAX_DEVICE_DESCRIPTION_BYTES: usize = 512;

/// Windows implementation version constants (MS-RDPEPNP Appendix A §<2>–§<5>).
///
/// Exposed as defaults for test vectors and the client builder.
pub mod version {
    /// Server MajorVersion used by the Windows implementation.
    pub const SERVER_MAJOR: u32 = 0x0000_0001;
    /// Server MinorVersion used by the Windows implementation.
    pub const SERVER_MINOR: u32 = 0x0000_0005;
    /// Client MajorVersion used by the Windows implementation.
    pub const CLIENT_MAJOR: u32 = 0x0000_0001;
    /// Client MinorVersion used by the Windows implementation.
    pub const CLIENT_MINOR: u32 = 0x0000_0005;
}

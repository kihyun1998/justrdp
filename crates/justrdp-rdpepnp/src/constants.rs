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

/// Maximum accepted length of `HardwareId` (bytes). A Windows hardware-ID
/// multisz rarely exceeds a few hundred bytes in practice.
pub const MAX_HARDWARE_ID_BYTES: usize = 1024;

/// Maximum accepted length of `CompatibilityID` (bytes). Kept equal to
/// [`MAX_HARDWARE_ID_BYTES`] because the two fields share a multisz
/// encoding and similar expected sizes, but exposed as its own constant
/// so that future tightening of one bound does not silently affect the
/// other.
pub const MAX_COMPAT_ID_BYTES: usize = MAX_HARDWARE_ID_BYTES;

/// Maximum accepted length of `DeviceDescription` (UTF-16LE, 2 bytes/char).
pub const MAX_DEVICE_DESCRIPTION_BYTES: usize = 512;

// ── Optional tail block sizes (MS-RDPEPNP §2.2.1.3.1.1) ──

/// Size in bytes of the optional `cbContainerId + ContainerId` block
/// inside `PNP_DEVICE_DESCRIPTION`. Present iff the encoded `DataSize`
/// leaves at least this many bytes after the mandatory fields.
pub const CONTAINER_ID_BLOCK_SIZE: usize = 4 + 16;

/// Size in bytes of the optional `cbDeviceCaps + DeviceCaps` block
/// inside `PNP_DEVICE_DESCRIPTION`.
pub const DEVICE_CAPS_BLOCK_SIZE: usize = 4 + 4;

// ── FileRedirectorChannel (MS-RDPEPNP §2.2.2) ──

/// Device I/O Sub-protocol DVC channel name (MS-RDPEPNP §1.9 / §2.1).
///
/// A *new* instance of this DVC is opened by the server for every
/// CreateFile call the driver makes against a redirected PnP device;
/// therefore a DVC host may see many concurrent channels all sharing
/// this name, each with its own channel_id and its own per-channel
/// state machine.
pub const FILE_REDIRECTOR_CHANNEL_NAME: &str = "FileRedirectorChannel";

/// Size in bytes of `SERVER_IO_HEADER` (MS-RDPEPNP §2.2.2.1.1):
/// `RequestId` (3 bytes, LE) + `UnusedBits` (1 byte) + `FunctionId` (4 bytes).
pub const SERVER_IO_HEADER_SIZE: usize = 8;

/// Size in bytes of `CLIENT_IO_HEADER` (MS-RDPEPNP §2.2.2.1.2):
/// `RequestId` (3 bytes, LE) + `PacketType` (1 byte).
pub const CLIENT_IO_HEADER_SIZE: usize = 4;

/// Inclusive upper bound of a 24-bit `RequestId` (MS-RDPEPNP §2.2.2.1.1).
pub const MAX_REQUEST_ID: u32 = 0x00FF_FFFF;

/// `FunctionId` values carried by `SERVER_IO_HEADER` (MS-RDPEPNP §2.2.2.1.1).
pub mod function_id {
    /// Read Request (§2.2.2.3.3).
    pub const READ_REQUEST: u32 = 0x0000_0000;
    /// Write Request (§2.2.2.3.5).
    pub const WRITE_REQUEST: u32 = 0x0000_0001;
    /// IOControl Request (§2.2.2.3.7).
    pub const IOCONTROL_REQUEST: u32 = 0x0000_0002;
    // 0x0000_0003 is explicitly not defined by the specification.
    /// CreateFile Request (§2.2.2.3.1).
    pub const CREATE_FILE_REQUEST: u32 = 0x0000_0004;
    /// Server Capabilities Request (§2.2.2.2.1).
    pub const CAPABILITIES_REQUEST: u32 = 0x0000_0005;
    /// Specific IoCancel Request (§2.2.2.3.9).
    pub const SPECIFIC_IOCANCEL_REQUEST: u32 = 0x0000_0006;
}

/// `PacketType` values carried by `CLIENT_IO_HEADER` (MS-RDPEPNP §2.2.2.1.2).
pub mod packet_type {
    /// Response to a pending server I/O request (`RESPONSE_PACKET`).
    pub const RESPONSE: u8 = 0x00;
    /// Asynchronous client-initiated custom event (`CUSTOM_EVENT_PACKET`,
    /// only valid once both peers negotiated version ≥ 0x0006).
    pub const CUSTOM_EVENT: u8 = 0x01;
}

/// FileRedirectorChannel protocol version values (MS-RDPEPNP §2.2.2.2.1).
///
/// The negotiated version is `min(server, client)`.
pub mod io_version {
    /// Baseline version — `ClientDeviceCustomEvent` is **not** supported.
    pub const NO_CUSTOM_EVENT: u16 = 0x0004;
    /// Custom-event-capable version.
    pub const CUSTOM_EVENT: u16 = 0x0006;
}

// ── FileRedirectorChannel DoS caps ──
//
// The DRDYNVC framing already reassembles an entire message for us
// before handing it to the DvcProcessor, so a compromised server could
// attempt to inflate any length field up to the DVC payload ceiling.
// Each variable-length body therefore carries an explicit cap chosen
// to leave plenty of headroom for real hardware (printers, sensors,
// portable media players) while refusing pathological sizes. These
// values mirror the conservative caps used by PNPDR (§9.14a).

/// Maximum accepted `cbBytesToRead` / `cbBytesRead` (bytes).
pub const MAX_READ_BYTES: usize = 64 * 1024;
/// Maximum accepted `cbWrite` / `cbBytesWritten` (bytes).
pub const MAX_WRITE_BYTES: usize = 64 * 1024;
/// Maximum accepted `cbIn` or `cbOut` in one IoControl message (bytes).
pub const MAX_IOCONTROL_BYTES: usize = 64 * 1024;
/// Maximum accepted `cbData` in a `ClientDeviceCustomEvent` (bytes).
pub const MAX_CUSTOM_EVENT_BYTES: usize = 64 * 1024;
/// Maximum number of simultaneously outstanding server requests on one
/// FileRedirectorChannel instance.
pub const MAX_OUTSTANDING_REQUESTS: usize = 256;
/// Maximum number of concurrent FileRedirectorChannel DVC instances a
/// single client will track. A malicious server can call DRDYNVC
/// Create Request repeatedly with the same channel name, so this cap
/// bounds heap growth at the outer `BTreeMap<channel_id, _>` level
/// (the per-instance [`MAX_OUTSTANDING_REQUESTS`] only protects the
/// inner table).
pub const MAX_CHANNELS: usize = 256;

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

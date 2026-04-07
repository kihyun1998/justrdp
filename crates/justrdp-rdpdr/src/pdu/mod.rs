#![forbid(unsafe_code)]

//! RDPDR PDU types -- MS-RDPEFS 2.2

pub mod header;
pub mod capability;
pub mod device;
pub mod init;
pub mod irp;
pub mod printer;
pub(crate) mod util;

pub use header::{Component, PacketId, SharedHeader, SHARED_HEADER_SIZE};
pub use device::{
    DeviceType, DeviceAnnounce, DeviceListAnnouncePdu, DeviceAnnounceResponsePdu,
    DeviceListRemovePdu,
};
pub use init::{
    ClientAnnounceReply, ClientNameRequest, ServerAnnounceRequest, ServerClientIdConfirm,
    UserLoggedOnPdu, VersionPdu,
};
pub use capability::{
    CapabilitySet, CapabilityRequestPdu, GeneralCapabilitySet,
    IoCode1, ExtendedPdu, ExtraFlags1,
    GENERAL_CAPABILITY_VERSION_01, GENERAL_CAPABILITY_VERSION_02, RDPDR_MAJOR_RDP_VERSION,
};
pub use printer::{
    PrinterFlags, PrinterDeviceData, PrinterUsingXpsPdu,
    PrinterCacheDataPdu, PrinterCacheEventId,
};
pub use irp::{
    MajorFunction, MinorFunction, DeviceIoRequest, DeviceIoResponse,
    DeviceCreateRequest, DeviceReadRequest, DeviceWriteRequest,
    DeviceControlRequest, DeviceQueryInformationRequest, DeviceSetInformationRequest,
    DeviceQueryVolumeInformationRequest, DeviceQueryDirectoryRequest,
    DeviceNotifyChangeDirectoryRequest, DeviceLockControlRequest, LockInfo,
    IrpRequest,
};

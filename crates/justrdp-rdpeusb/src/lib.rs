#![no_std]
#![forbid(unsafe_code)]

//! USB Devices Virtual Channel Extension -- MS-RDPEUSB
//!
//! Implements the URBDRC dynamic virtual channel (`"URBDRC"`) used to redirect
//! physical USB devices from the client host to the remote session. The crate
//! is split into:
//!
//! - [`pdu`] -- wire-format structs with `Encode` / `Decode`
//! - [`ts_urb`] -- `TS_URB_*` variants (MS-RDPEUSB section 2.2.9)
//! - [`client`] -- `UrbdrcClient` implementing `DvcProcessor` and the
//!   [`UrbHandler`](client::UrbHandler) trait abstraction for the host USB
//!   stack

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod ts_urb;

#[cfg(feature = "alloc")]
pub mod client;

#[cfg(feature = "alloc")]
pub use client::{
    IoControlResult, MockUrbHandler, QueryDeviceTextResult, TransferInResult, TransferOutResult,
    UrbHandler, UrbdrcClient, UrbdrcClientConfig, UsbDeviceDescriptor,
};

#[cfg(feature = "alloc")]
pub use pdu::{
    AddDevice, AddVirtualChannel, CancelRequest, ChannelCreated, IoControl, IoControlCompletion,
    InternalIoControl, Mask, QueryDeviceText, QueryDeviceTextRsp, RegisterRequestCallback,
    RetractDevice, RimExchangeCapabilityRequest, RimExchangeCapabilityResponse, SharedMsgHeader,
    TransferInRequest, TransferOutRequest, UrbCompletion, UrbCompletionNoData, UsbDeviceCapabilities,
    CHANNEL_NAME, FN_ADD_DEVICE, FN_ADD_VIRTUAL_CHANNEL, FN_CANCEL_REQUEST, FN_CHANNEL_CREATED,
    FN_INTERNAL_IO_CONTROL, FN_IOCONTROL_COMPLETION, FN_IO_CONTROL, FN_QUERY_DEVICE_TEXT,
    FN_REGISTER_REQUEST_CALLBACK, FN_RETRACT_DEVICE, FN_RIM_EXCHANGE_CAPABILITY_REQUEST,
    FN_TRANSFER_IN_REQUEST, FN_TRANSFER_OUT_REQUEST, FN_URB_COMPLETION, FN_URB_COMPLETION_NO_DATA,
    HRESULT_E_FAIL, HRESULT_FROM_WIN32_ERROR_INSUFFICIENT_BUFFER, HRESULT_STATUS_TIMEOUT,
    HRESULT_S_OK, IID_CAPABILITY_NEGOTIATOR, IID_CHANNEL_NOTIFICATION_C2S,
    IID_CHANNEL_NOTIFICATION_S2C, IID_DEVICE_SINK, MAX_CB_TS_URB, MAX_COMPATIBILITY_IDS_CHARS,
    MAX_CONTAINER_ID_CHARS, MAX_DEVICE_DESCRIPTION_CHARS, MAX_DEVICE_INSTANCE_ID_CHARS,
    MAX_DEVICE_PIPES, MAX_HARDWARE_IDS_CHARS, MAX_IN_FLIGHT_REQUESTS_PER_DEVICE,
    MAX_IOCTL_BUFFER_SIZE, MAX_ISOCH_PACKETS, MAX_PDU_SIZE, MAX_SELECT_CONFIG_INTERFACES,
    MAX_TRANSFER_OUTPUT_BUFFER_SIZE, RIM_CAPABILITY_VERSION_01, STREAM_ID_NONE, STREAM_ID_PROXY,
    STREAM_ID_STUB, USB_RETRACT_REASON_BLOCKED_BY_POLICY,
};

#[cfg(feature = "alloc")]
pub use ts_urb::{
    TsUrb, TsUrbBulkOrInterruptTransfer, TsUrbControlDescriptorRequest,
    TsUrbControlFeatureRequest, TsUrbControlGetConfigurationRequest,
    TsUrbControlGetInterfaceRequest, TsUrbControlGetStatusRequest, TsUrbControlTransfer,
    TsUrbControlTransferEx, TsUrbControlVendorOrClassRequest, TsUrbGetCurrentFrameNumber,
    TsUrbHeader, TsUrbIsochTransfer, TsUrbOsFeatureDescriptorRequest, TsUrbPipeRequest,
    TsUrbResultHeader, TsUrbSelectConfiguration, TsUrbSelectInterface, UsbdIsoPacketDescriptor,
    URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER, URB_FUNCTION_CONTROL_TRANSFER,
    URB_FUNCTION_CONTROL_TRANSFER_EX, URB_FUNCTION_GET_CONFIGURATION,
    URB_FUNCTION_GET_CURRENT_FRAME_NUMBER, URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE,
    URB_FUNCTION_GET_INTERFACE, URB_FUNCTION_GET_STATUS_FROM_DEVICE, URB_FUNCTION_ISOCH_TRANSFER,
    URB_FUNCTION_OS_FEATURE_DESCRIPTOR_REQUEST, URB_FUNCTION_SELECT_CONFIGURATION,
    URB_FUNCTION_SELECT_INTERFACE, URB_FUNCTION_SET_FEATURE_TO_DEVICE, URB_FUNCTION_SYNC_RESET_PIPE,
    URB_FUNCTION_VENDOR_DEVICE,
};

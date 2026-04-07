#![forbid(unsafe_code)]

//! RDPDR channel processor -- SVC integration.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, RDPDR, SvcClientProcessor, SvcMessage, SvcProcessor,
    SvcResult,
};

use crate::backend::{DeviceIoError, FileHandle, RdpdrBackend};
use crate::pdu::capability::{
    CapabilityRequestPdu, CapabilitySet, ExtendedPdu, ExtraFlags1, GENERAL_CAPABILITY_VERSION_02,
    GeneralCapabilitySet, IoCode1, RDPDR_MAJOR_RDP_VERSION,
};
use crate::pdu::device::{DeviceAnnounceResponsePdu, DeviceListAnnouncePdu};
use crate::pdu::header::{Component, PacketId, SharedHeader};
use crate::pdu::init::{ClientAnnounceReply, ClientNameRequest, VersionPdu};
use crate::pdu::irp::{DeviceIoRequest, DeviceIoResponse, IrpRequest};

/// RDPDR version minor values -- MS-RDPEFS 2.2.2.2
const VERSION_MINOR_12: u16 = 0x000C;

/// Client-side RDPDR channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdpdrState {
    /// Waiting for server announce.
    WaitingForServerAnnounce,
    /// Sent client announce + name, waiting for server capability.
    WaitingForServerCapability,
    /// Sent client capability, waiting for server client ID confirm.
    WaitingForServerClientIdConfirm,
    /// Initialization complete, processing I/O requests.
    Ready,
}

/// Client-side RDPDR channel processor.
///
/// Implements [`SvcProcessor`] to handle the RDPDR virtual channel.
pub struct RdpdrClient {
    state: RdpdrState,
    backend: Box<dyn RdpdrBackend>,
    /// Server-assigned client ID.
    client_id: u32,
    /// Negotiated protocol minor version.
    version_minor: u16,
    /// Computer name to announce.
    computer_name: String,
}

impl AsAny for RdpdrClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for RdpdrClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpdrClient")
            .field("state", &self.state)
            .field("client_id", &self.client_id)
            .field("version_minor", &self.version_minor)
            .field("computer_name", &self.computer_name)
            .finish()
    }
}

impl RdpdrClient {
    /// Create a new RDPDR client processor.
    pub fn new(backend: Box<dyn RdpdrBackend>) -> Self {
        Self {
            state: RdpdrState::WaitingForServerAnnounce,
            backend,
            client_id: 0,
            version_minor: VERSION_MINOR_12,
            computer_name: String::from("YOURPC"),
        }
    }

    /// Set the computer name announced to the server.
    pub fn with_computer_name(mut self, name: String) -> Self {
        self.computer_name = name;
        self
    }

    /// Encode a SharedHeader + body PDU into an SvcMessage.
    fn encode_message<T: Encode>(
        component: Component,
        packet_id: PacketId,
        body: &T,
    ) -> SvcResult<SvcMessage> {
        let header = SharedHeader::new(component, packet_id);
        let total = header.size() + body.size();
        let mut buf = vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        body.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the device I/O completion response.
    fn encode_io_completion(
        device_id: u32,
        completion_id: u32,
        io_status: u32,
        response_data: &[u8],
    ) -> SvcResult<SvcMessage> {
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoCompletion);
        let resp = DeviceIoResponse {
            device_id,
            completion_id,
            io_status,
        };
        let total = header.size() + resp.size() + response_data.len();
        let mut buf = vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        resp.encode(&mut cursor)?;
        if !response_data.is_empty() {
            cursor.write_slice(response_data, "IoCompletion::responseData")?;
        }
        Ok(SvcMessage::new(buf))
    }

    /// Build client announce reply + client name messages.
    fn build_announce_reply(&self) -> SvcResult<Vec<SvcMessage>> {
        let mut messages = Vec::new();

        // Client Announce Reply -- MS-RDPEFS 2.2.2.3
        // DR_CORE_CLIENT_ANNOUNCE_RSP shares PacketId::ClientIdConfirm (0x4343)
        let reply = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: self.version_minor,
            client_id: self.client_id,
        };
        messages.push(Self::encode_message(
            Component::Core,
            PacketId::ClientIdConfirm,
            &reply,
        )?);

        // Client Name Request -- MS-RDPEFS 2.2.2.4
        let name_req = ClientNameRequest {
            unicode: true,
            computer_name: self.computer_name.clone(),
        };
        messages.push(Self::encode_message(
            Component::Core,
            PacketId::ClientName,
            &name_req,
        )?);

        Ok(messages)
    }

    /// Build client capability response.
    fn build_capability_response(&self) -> SvcResult<SvcMessage> {
        let general = GeneralCapabilitySet {
            os_type: 0,
            os_version: 0,
            protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
            protocol_minor_version: self.version_minor,
            io_code1: IoCode1::RDPDR_IRP_MJ_CREATE
                .union(IoCode1::RDPDR_IRP_MJ_CLEANUP)
                .union(IoCode1::RDPDR_IRP_MJ_CLOSE)
                .union(IoCode1::RDPDR_IRP_MJ_READ)
                .union(IoCode1::RDPDR_IRP_MJ_WRITE)
                .union(IoCode1::RDPDR_IRP_MJ_FLUSH_BUFFERS)
                .union(IoCode1::RDPDR_IRP_MJ_SHUTDOWN)
                .union(IoCode1::RDPDR_IRP_MJ_DEVICE_CONTROL)
                .union(IoCode1::RDPDR_IRP_MJ_QUERY_VOLUME_INFORMATION)
                .union(IoCode1::RDPDR_IRP_MJ_SET_VOLUME_INFORMATION)
                .union(IoCode1::RDPDR_IRP_MJ_QUERY_INFORMATION)
                .union(IoCode1::RDPDR_IRP_MJ_SET_INFORMATION)
                .union(IoCode1::RDPDR_IRP_MJ_DIRECTORY_CONTROL)
                .union(IoCode1::RDPDR_IRP_MJ_LOCK_CONTROL),
            extended_pdu: ExtendedPdu::RDPDR_DEVICE_REMOVE_PDUS
                .union(ExtendedPdu::RDPDR_CLIENT_DISPLAY_NAME_PDU)
                .union(ExtendedPdu::RDPDR_USER_LOGGEDON_PDU),
            extra_flags1: ExtraFlags1::NONE,
            // MS-RDPEFS 2.2.2.7.1: SpecialTypeDeviceCap = number of smartcard devices
            special_type_device_cap: Some(
                self.backend
                    .device_list()
                    .iter()
                    .filter(|d| d.device_type == crate::pdu::device::DeviceType::Smartcard)
                    .count() as u32,
            ),
        };

        let caps = CapabilityRequestPdu::new(vec![
            CapabilitySet::General(general),
            CapabilitySet::Drive {
                version: GENERAL_CAPABILITY_VERSION_02,
            },
        ]);

        Self::encode_message(Component::Core, PacketId::ClientCapability, &caps)
    }

    /// Build device list announce message.
    fn build_device_list(&self) -> SvcResult<SvcMessage> {
        let devices = self.backend.device_list();
        let pdu = DeviceListAnnouncePdu { devices };
        Self::encode_message(Component::Core, PacketId::DeviceListAnnounce, &pdu)
    }

    /// Handle a received RDPDR PDU.
    fn handle_pdu(
        &mut self,
        header: &SharedHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        match (header.component, header.packet_id) {
            // Server Announce Request -- MS-RDPEFS 2.2.2.2
            (Component::Core, PacketId::ServerAnnounce) => {
                if self.state != RdpdrState::WaitingForServerAnnounce {
                    return Ok(Vec::new());
                }
                let announce = VersionPdu::decode(body)?;
                self.client_id = announce.client_id;
                // MS-RDPEFS 2.2.2.3: negotiate version = min(server, client)
                self.version_minor = announce.version_minor.min(VERSION_MINOR_12);
                self.state = RdpdrState::WaitingForServerCapability;
                self.build_announce_reply()
            }

            // Server Core Capability Request -- MS-RDPEFS 2.2.2.7
            (Component::Core, PacketId::ServerCapability) => {
                if self.state != RdpdrState::WaitingForServerCapability {
                    return Ok(Vec::new());
                }
                let _caps = CapabilityRequestPdu::decode(body)?;
                self.state = RdpdrState::WaitingForServerClientIdConfirm;
                let msg = self.build_capability_response()?;
                Ok(vec![msg])
            }

            // Server Client ID Confirm -- MS-RDPEFS 2.2.2.6
            (Component::Core, PacketId::ClientIdConfirm) => {
                if self.state != RdpdrState::WaitingForServerClientIdConfirm {
                    return Ok(Vec::new());
                }
                let confirm = VersionPdu::decode(body)?;
                self.client_id = confirm.client_id;
                self.state = RdpdrState::Ready;

                // Send device list immediately -- MS-RDPEFS 1.3.1
                let msg = self.build_device_list()?;
                Ok(vec![msg])
            }

            // Server User Logged On -- MS-RDPEFS 2.2.2.5
            // Per MS-RDPEFS 1.3.2, client MUST re-announce devices on user logon.
            (Component::Core, PacketId::UserLoggedOn) => {
                if self.state != RdpdrState::Ready {
                    return Ok(Vec::new());
                }
                let msg = self.build_device_list()?;
                Ok(vec![msg])
            }

            // Server Device Announce Response -- MS-RDPEFS 2.2.2.1
            (Component::Core, PacketId::DeviceReply) => {
                if self.state != RdpdrState::Ready {
                    return Ok(Vec::new());
                }
                let resp = DeviceAnnounceResponsePdu::decode(body)?;
                self.backend
                    .on_device_reply(resp.device_id, resp.result_code);
                Ok(Vec::new())
            }

            // Server Device I/O Request -- MS-RDPEFS 2.2.1.4
            (Component::Core, PacketId::DeviceIoRequest) => {
                if self.state != RdpdrState::Ready {
                    return Ok(Vec::new());
                }
                self.handle_io_request(body)
            }

            // Server Printer Set XPS Mode -- MS-RDPEPC 2.2.2.2
            (Component::Printer, PacketId::PrnUsingXps) => {
                if self.state != RdpdrState::Ready {
                    return Ok(Vec::new());
                }
                let pdu =
                    crate::pdu::printer::PrinterUsingXpsPdu::decode(body)?;
                self.backend.on_printer_using_xps(pdu.printer_id, pdu.flags);
                Ok(Vec::new())
            }

            // Server Printer Cache Data -- MS-RDPEPC 2.2.2.3
            (Component::Printer, PacketId::PrnCacheData) => {
                if self.state != RdpdrState::Ready {
                    return Ok(Vec::new());
                }
                let pdu =
                    crate::pdu::printer::PrinterCacheDataPdu::decode(body)?;
                self.backend
                    .on_printer_cache_data(pdu.event_id as u32, &pdu.event_data);
                Ok(Vec::new())
            }

            _ => {
                // Ignore unknown PDUs.
                Ok(Vec::new())
            }
        }
    }

    /// Handle a device I/O request.
    fn handle_io_request(&mut self, src: &mut ReadCursor<'_>) -> SvcResult<Vec<SvcMessage>> {
        let io_req = DeviceIoRequest::decode(src)?;
        let irp = IrpRequest::decode_body(io_req.major_function, io_req.minor_function, src)?;

        let device_id = io_req.device_id;
        let completion_id = io_req.completion_id;
        let file_id = FileHandle(io_req.file_id);

        match irp {
            IrpRequest::Create(req) => {
                let result = self.backend.create(
                    device_id,
                    &req.path,
                    req.desired_access,
                    req.create_disposition,
                    req.create_options,
                    req.file_attributes,
                );
                match result {
                    Ok(resp) => {
                        // DR_CREATE_RSP: FileId(4) + Information(1)
                        let mut data = [0u8; 5];
                        let mut c = WriteCursor::new(&mut data);
                        c.write_u32_le(resp.file_id.0, "FileId")?;
                        c.write_u8(resp.information, "Information")?;
                        let msg = Self::encode_io_completion(
                            device_id,
                            completion_id,
                            0, // STATUS_SUCCESS
                            &data,
                        )?;
                        Ok(vec![msg])
                    }
                    Err(e) => {
                        // Error: FileId=0, Information=0
                        let data = [0u8; 5];
                        let msg = Self::encode_io_completion(
                            device_id,
                            completion_id,
                            e.ntstatus,
                            &data,
                        )?;
                        Ok(vec![msg])
                    }
                }
            }

            IrpRequest::Close => {
                let result = self.backend.close(device_id, file_id);
                let io_status = match result {
                    Ok(()) => 0,
                    Err(e) => e.ntstatus,
                };
                // DR_CLOSE_RSP: 4 bytes padding
                let msg =
                    Self::encode_io_completion(device_id, completion_id, io_status, &[0u8; 4])?;
                Ok(vec![msg])
            }

            IrpRequest::Read(req) => {
                let result = self
                    .backend
                    .read(device_id, file_id, req.length, req.offset);
                match result {
                    Ok(data) => {
                        // DR_READ_RSP: Length(4) + ReadData
                        let mut buf = vec![0u8; 4 + data.len()];
                        let mut c = WriteCursor::new(&mut buf);
                        c.write_u32_le(data.len() as u32, "Length")?;
                        c.write_slice(&data, "ReadData")?;
                        let msg = Self::encode_io_completion(device_id, completion_id, 0, &buf)?;
                        Ok(vec![msg])
                    }
                    Err(e) => {
                        let buf = [0u8; 4]; // Length=0
                        let msg =
                            Self::encode_io_completion(device_id, completion_id, e.ntstatus, &buf)?;
                        Ok(vec![msg])
                    }
                }
            }

            IrpRequest::Write(req) => {
                let result = self
                    .backend
                    .write(device_id, file_id, req.offset, &req.write_data);
                match result {
                    Ok(written) => {
                        // DR_WRITE_RSP: Length(4) + Padding(1)
                        let mut buf = [0u8; 5];
                        let mut c = WriteCursor::new(&mut buf);
                        c.write_u32_le(written, "Length")?;
                        c.write_u8(0, "Padding")?;
                        let msg = Self::encode_io_completion(device_id, completion_id, 0, &buf)?;
                        Ok(vec![msg])
                    }
                    Err(e) => {
                        let buf = [0u8; 5];
                        let msg =
                            Self::encode_io_completion(device_id, completion_id, e.ntstatus, &buf)?;
                        Ok(vec![msg])
                    }
                }
            }

            IrpRequest::DeviceControl(req) => {
                let result = self.backend.device_control(
                    device_id,
                    file_id,
                    req.io_control_code,
                    &req.input_buffer,
                    req.output_buffer_length,
                );
                match result {
                    Ok(output) => {
                        // DR_CONTROL_RSP: OutputBufferLength(4) + OutputBuffer
                        let mut buf = vec![0u8; 4 + output.len()];
                        let mut c = WriteCursor::new(&mut buf);
                        c.write_u32_le(output.len() as u32, "OutputBufferLength")?;
                        c.write_slice(&output, "OutputBuffer")?;
                        let msg = Self::encode_io_completion(device_id, completion_id, 0, &buf)?;
                        Ok(vec![msg])
                    }
                    Err(e) => {
                        let buf = [0u8; 4]; // OutputBufferLength=0
                        let msg =
                            Self::encode_io_completion(device_id, completion_id, e.ntstatus, &buf)?;
                        Ok(vec![msg])
                    }
                }
            }

            IrpRequest::QueryInformation(req) => {
                let result =
                    self.backend
                        .query_information(device_id, file_id, req.fs_information_class);
                self.encode_buffer_response(device_id, completion_id, result)
            }

            IrpRequest::SetInformation(req) => {
                let result = self.backend.set_information(
                    device_id,
                    file_id,
                    req.fs_information_class,
                    &req.set_buffer,
                );
                let io_status = match result {
                    Ok(()) => 0,
                    Err(e) => e.ntstatus,
                };
                // DR_SET_INFORMATION_RSP: 4 bytes Padding -- MS-RDPEFS 2.2.3.4.9
                let msg =
                    Self::encode_io_completion(device_id, completion_id, io_status, &[0u8; 4])?;
                Ok(vec![msg])
            }

            IrpRequest::QueryVolumeInformation(req) => {
                let result = self
                    .backend
                    .query_volume_information(device_id, req.fs_information_class);
                self.encode_buffer_response(device_id, completion_id, result)
            }

            IrpRequest::QueryDirectory(req) => {
                let initial = req.initial_query != 0;
                let path = if initial {
                    Some(req.path.as_str())
                } else {
                    None
                };
                let result = self.backend.query_directory(
                    device_id,
                    file_id,
                    req.fs_information_class,
                    initial,
                    path,
                );
                self.encode_buffer_response(device_id, completion_id, result)
            }

            IrpRequest::NotifyChangeDirectory(req) => {
                let result = self.backend.notify_change_directory(
                    device_id,
                    file_id,
                    req.watch_tree != 0,
                    req.completion_filter,
                );
                self.encode_buffer_response(device_id, completion_id, result)
            }

            IrpRequest::LockControl(req) => {
                let locks: Vec<(u64, u64)> =
                    req.locks.iter().map(|l| (l.offset, l.length)).collect();
                let result = self
                    .backend
                    .lock_control(device_id, file_id, req.operation, &locks);
                let io_status = match result {
                    Ok(()) => 0,
                    Err(e) => e.ntstatus,
                };
                let msg = Self::encode_io_completion(device_id, completion_id, io_status, &[])?;
                Ok(vec![msg])
            }
        }
    }

    /// Encode a standard buffer response: Length(4) + Buffer.
    fn encode_buffer_response(
        &self,
        device_id: u32,
        completion_id: u32,
        result: Result<Vec<u8>, DeviceIoError>,
    ) -> SvcResult<Vec<SvcMessage>> {
        match result {
            Ok(data) => {
                let mut buf = vec![0u8; 4 + data.len()];
                let mut c = WriteCursor::new(&mut buf);
                c.write_u32_le(data.len() as u32, "Length")?;
                c.write_slice(&data, "Buffer")?;
                let msg = Self::encode_io_completion(device_id, completion_id, 0, &buf)?;
                Ok(vec![msg])
            }
            Err(e) => {
                let buf = [0u8; 4]; // Length=0
                let msg = Self::encode_io_completion(device_id, completion_id, e.ntstatus, &buf)?;
                Ok(vec![msg])
            }
        }
    }
}

impl SvcProcessor for RdpdrClient {
    fn channel_name(&self) -> ChannelName {
        RDPDR
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for server to send announce first.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);
        let header = SharedHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for RdpdrClient {}

// ── Public API ─────────────────────────────────────────────────────────────

impl RdpdrClient {
    /// Build a device list remove message.
    ///
    /// Call this when devices are dynamically removed.
    pub fn build_device_list_remove(&self, device_ids: Vec<u32>) -> SvcResult<SvcMessage> {
        use crate::pdu::device::DeviceListRemovePdu;
        let pdu = DeviceListRemovePdu { device_ids };
        Self::encode_message(Component::Core, PacketId::DeviceListRemove, &pdu)
    }

    /// Build a device list announce message for dynamically added devices.
    pub fn build_device_list_announce(
        &self,
        devices: Vec<crate::pdu::device::DeviceAnnounce>,
    ) -> SvcResult<SvcMessage> {
        let pdu = DeviceListAnnouncePdu { devices };
        Self::encode_message(Component::Core, PacketId::DeviceListAnnounce, &pdu)
    }
}

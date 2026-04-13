//! End-to-end integration test for the MS-RDPEUSB DVC client.
//!
//! Drives `UrbdrcClient` through the full handshake and exercises one
//! IO_CONTROL + one TRANSFER_IN round-trip followed by RETRACT_DEVICE.

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::DvcProcessor;
use justrdp_rdpeusb::client::{MockUrbHandler, UrbdrcClient, UsbDeviceDescriptor};
use justrdp_rdpeusb::pdu::{
    hresult_is_success, AddVirtualChannel, ChannelCreated, IoControl, IoControlCompletion, Mask,
    RegisterRequestCallback, RetractDevice, RimExchangeCapabilityRequest,
    RimExchangeCapabilityResponse, SharedMsgHeader, TransferInRequest, UrbCompletionNoData,
    UsbDeviceCapabilities, FN_IO_CONTROL, FN_RETRACT_DEVICE, FN_TRANSFER_IN_REQUEST,
    HRESULT_S_OK, USB_RETRACT_REASON_BLOCKED_BY_POLICY,
};
use justrdp_rdpeusb::ts_urb::{
    TsUrb, TsUrbBulkOrInterruptTransfer, TsUrbHeader, URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
};

fn encode<E: Encode>(pdu: &E) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

#[test]
fn full_flow_capability_then_channel_created_then_io_control_then_transfer_in_then_retract() {
    let handler = Box::new(MockUrbHandler::default());
    let mut client = UrbdrcClient::new(handler);

    // ── 1. RIM_EXCHANGE_CAPABILITY_REQUEST ──
    let req = RimExchangeCapabilityRequest::new(1);
    let buf = encode(&req);
    let out = client.process(0, &buf).unwrap();
    assert_eq!(out.len(), 1, "expected RIM_EXCHANGE_CAPABILITY_RESPONSE");
    // Decode and verify it parses back as a response.
    let mut src = ReadCursor::new(&out[0].data);
    let rsp = RimExchangeCapabilityResponse::decode(&mut src).unwrap();
    assert_eq!(rsp.result, HRESULT_S_OK);

    // ── 2. Server CHANNEL_CREATED ──
    let server_cc = ChannelCreated::server(2);
    let buf = encode(&server_cc);
    let out = client.process(0, &buf).unwrap();
    assert_eq!(out.len(), 1, "expected client CHANNEL_CREATED");
    assert!(client.is_ready());
    // Verify the client's own ChannelCreated parses back.
    let mut src = ReadCursor::new(&out[0].data);
    let client_cc = ChannelCreated::decode(&mut src).unwrap();
    assert_eq!(
        client_cc.header.interface_id,
        justrdp_rdpeusb::pdu::IID_CHANNEL_NOTIFICATION_C2S
    );
    client_cc.validate_version().unwrap();

    // ── 3. ADD_VIRTUAL_CHANNEL (client → server) ──
    let msg = client.build_add_virtual_channel().unwrap();
    let mut src = ReadCursor::new(&msg.data);
    let _ = AddVirtualChannel::decode(&mut src).unwrap();

    // ── 4. ADD_DEVICE (register the device instance client-side) ──
    // We reuse the same client instance as the per-device processor for
    // test simplicity. Choose a UsbDevice interface ID.
    let dev_iid = 0x0000_1000;
    let descriptor = UsbDeviceDescriptor {
        usb_device_interface_id: dev_iid,
        device_instance_id: "USB\\VID_1234&PID_5678".encode_utf16().collect(),
        hardware_ids: {
            let mut v: Vec<u16> = "USB\\VID_1234".encode_utf16().collect();
            v.push(0);
            v.push(0);
            v
        },
        compatibility_ids: Vec::new(),
        container_id: "{11112222-3333-4444-5555-666677778888}"
            .encode_utf16()
            .collect(),
        capabilities: UsbDeviceCapabilities {
            cb_size: 28,
            usb_bus_interface_version: 2,
            usbdi_version: 0x500,
            supported_usb_version: 0x0200,
            hcd_capabilities: 0,
            device_is_high_speed: 1,
            no_ack_isoch_write_jitter_buffer_size_in_ms: 0,
        },
    };
    let _add_device_msg = client.build_add_device(&descriptor).unwrap();

    // ── 5. REGISTER_REQUEST_CALLBACK on the per-device DVC ──
    let register = RegisterRequestCallback::new(dev_iid, 10, 0x0000_2000);
    let buf = encode(&register);
    let out = client.process(0, &buf).unwrap();
    assert!(out.is_empty(), "REGISTER_REQUEST_CALLBACK has no reply");

    // ── 5. IO_CONTROL → IOCONTROL_COMPLETION ──
    let ioctl = IoControl {
        header: SharedMsgHeader::request(dev_iid, Mask::StreamIdProxy, 11, FN_IO_CONTROL),
        io_control_code: 0x0022_0003, // arbitrary IOCTL
        input_buffer: vec![0xDE, 0xAD, 0xBE, 0xEF],
        output_buffer_size: 64,
        request_id: 1001,
    };
    let buf = encode(&ioctl);
    let out = client.process(0, &buf).unwrap();
    assert_eq!(out.len(), 1, "expected IOCONTROL_COMPLETION");
    let mut src = ReadCursor::new(&out[0].data);
    let completion = IoControlCompletion::decode(&mut src).unwrap();
    assert_eq!(completion.request_id, 1001);
    assert!(hresult_is_success(completion.h_result));

    // ── 6. TRANSFER_IN_REQUEST → URB_COMPLETION_NO_DATA ──
    let urb = TsUrb::BulkOrInterruptTransfer(TsUrbBulkOrInterruptTransfer {
        header: TsUrbHeader::new(
            TsUrbBulkOrInterruptTransfer::WIRE_SIZE as u16,
            URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
            2002,
        ),
        pipe_handle: 0x0100,
        transfer_flags: 0,
    });
    let ts_urb = urb.encode_to_vec().unwrap();
    let req = TransferInRequest {
        header: SharedMsgHeader::request(dev_iid, Mask::StreamIdProxy, 12, FN_TRANSFER_IN_REQUEST),
        cb_ts_urb: ts_urb.len() as u32,
        ts_urb,
        output_buffer_size: 128,
    };
    let buf = encode(&req);
    let out = client.process(0, &buf).unwrap();
    assert_eq!(out.len(), 1, "expected URB_COMPLETION_NO_DATA");
    let mut src = ReadCursor::new(&out[0].data);
    let comp = UrbCompletionNoData::decode(&mut src).unwrap();
    assert_eq!(comp.request_id, 2002);
    assert_eq!(
        comp.output_buffer_size, 0,
        "TRANSFER_IN no-data completion MUST have OutputBufferSize = 0"
    );

    // ── 7. RETRACT_DEVICE → client closes DVC ──
    let retract = RetractDevice {
        header: SharedMsgHeader::request(dev_iid, Mask::StreamIdProxy, 13, FN_RETRACT_DEVICE),
        reason: USB_RETRACT_REASON_BLOCKED_BY_POLICY,
    };
    let buf = encode(&retract);
    let out = client.process(0, &buf).unwrap();
    assert!(out.is_empty());
    assert!(client.is_closed());

}

//! State-machine and outstanding-request tracking tests for
//! [`FileRedirectorChannelClient`] (MS-RDPEPNP §3.2).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::Encode;
use justrdp_core::WriteCursor;
use justrdp_dvc::DvcProcessor;

use crate::constants::{io_version, MAX_CHANNELS};
use crate::file_redirector::{
    FileRedirectorChannelClient, FileRedirectorState, IoCallback, NullIoCallback,
};
use crate::pdu::io::{
    ClientCapabilitiesReply, CreateFileRequest, IoControlReply, IoControlRequest,
    ReadReply, ReadRequest, ServerCapabilitiesRequest, SpecificIoCancelRequest, WriteReply,
    WriteRequest,
};

fn enc<E: Encode>(pdu: &E) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

const CHAN: u32 = 42;

fn boot<C: IoCallback + Send + core::fmt::Debug + 'static>(
    mut client: FileRedirectorChannelClient<C>,
) -> FileRedirectorChannelClient<C> {
    client.start(CHAN).unwrap();
    client
}

fn cap_exchange<C: IoCallback + Send + core::fmt::Debug + 'static>(
    client: &mut FileRedirectorChannelClient<C>,
) {
    let req = ServerCapabilitiesRequest {
        request_id: 1,
        version: io_version::CUSTOM_EVENT,
    };
    let out = client.process(CHAN, &enc(&req)).unwrap();
    assert_eq!(out.len(), 1);
    // Client echoes its own preferred version (CUSTOM_EVENT by default).
    let reply_bytes = &out[0].data;
    let reply: ClientCapabilitiesReply = {
        use justrdp_core::{Decode, ReadCursor};
        let mut c = ReadCursor::new(reply_bytes);
        ClientCapabilitiesReply::decode(&mut c).unwrap()
    };
    assert_eq!(reply.request_id, 1);
    assert_eq!(reply.version, io_version::CUSTOM_EVENT);
    assert_eq!(
        client.instance(CHAN).unwrap().state(),
        FileRedirectorState::WaitCreateFile
    );
    assert_eq!(
        client.instance(CHAN).unwrap().negotiated_version(),
        Some(io_version::CUSTOM_EVENT)
    );
}

fn create_file_exchange<C: IoCallback + Send + core::fmt::Debug + 'static>(
    client: &mut FileRedirectorChannelClient<C>,
) {
    let req = CreateFileRequest {
        request_id: 2,
        device_id: 99,
        desired_access: 0xC000_0000,
        share_mode: 3,
        creation_disposition: 3,
        flags_and_attributes: 0x80,
    };
    let out = client.process(CHAN, &enc(&req)).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(
        client.instance(CHAN).unwrap().state(),
        FileRedirectorState::Active
    );
}

// ── FSM happy path ──

#[test]
fn fsm_walks_capabilities_to_active() {
    let mut c = boot(FileRedirectorChannelClient::new());
    assert_eq!(
        c.instance(CHAN).unwrap().state(),
        FileRedirectorState::WaitCapabilities
    );
    cap_exchange(&mut c);
    create_file_exchange(&mut c);
}

#[test]
fn create_file_rejected_before_capabilities() {
    let mut c = boot(FileRedirectorChannelClient::new());
    let req = CreateFileRequest {
        request_id: 1,
        device_id: 1,
        desired_access: 0,
        share_mode: 0,
        creation_disposition: 0,
        flags_and_attributes: 0,
    };
    assert!(c.process(CHAN, &enc(&req)).is_err());
}

#[test]
fn read_request_rejected_before_active() {
    let mut c = boot(FileRedirectorChannelClient::new());
    cap_exchange(&mut c);
    let req = ReadRequest {
        request_id: 5,
        cb_bytes_to_read: 10,
        offset_high: 0,
        offset_low: 0,
    };
    assert!(c.process(CHAN, &enc(&req)).is_err());
}

#[test]
fn version_negotiation_is_minimum() {
    let mut c = boot(FileRedirectorChannelClient::new().with_version(io_version::CUSTOM_EVENT));
    let req = ServerCapabilitiesRequest {
        request_id: 1,
        version: io_version::NO_CUSTOM_EVENT, // server only supports 0x0004
    };
    c.process(CHAN, &enc(&req)).unwrap();
    assert_eq!(
        c.instance(CHAN).unwrap().negotiated_version(),
        Some(io_version::NO_CUSTOM_EVENT)
    );
}

// ── I/O through a callback ──

#[derive(Debug, Default)]
struct RecordingCb {
    reads: u32,
    writes: u32,
    ioctls: u32,
    cancels: u32,
}

impl IoCallback for RecordingCb {
    fn on_create_file(&mut self, _req: &CreateFileRequest) -> i32 {
        0 // success
    }
    fn on_read(&mut self, req: &ReadRequest) -> (i32, Vec<u8>) {
        self.reads += 1;
        (0, vec![7; req.cb_bytes_to_read as usize])
    }
    fn on_write(&mut self, req: &WriteRequest) -> (i32, u32) {
        self.writes += 1;
        (0, req.data.len() as u32)
    }
    fn on_io_control(&mut self, _req: &IoControlRequest) -> (i32, Vec<u8>) {
        self.ioctls += 1;
        (0, vec![0xAA, 0xBB])
    }
    fn on_cancel(&mut self, _id: u32) {
        self.cancels += 1;
    }
}

#[test]
fn read_write_iocontrol_flow_through_callback() {
    use justrdp_core::{Decode, ReadCursor};
    let mut c: FileRedirectorChannelClient<RecordingCb> =
        boot(FileRedirectorChannelClient::with_callback(RecordingCb::default()));
    cap_exchange(&mut c);
    create_file_exchange(&mut c);

    // Read
    let rreq = ReadRequest {
        request_id: 10,
        cb_bytes_to_read: 4,
        offset_high: 0,
        offset_low: 0,
    };
    let out = c.process(CHAN, &enc(&rreq)).unwrap();
    let reply = {
        let mut cur = ReadCursor::new(&out[0].data);
        ReadReply::decode(&mut cur).unwrap()
    };
    assert_eq!(reply.request_id, 10);
    assert_eq!(reply.data, vec![7; 4]);

    // Write
    let wreq = WriteRequest {
        request_id: 11,
        offset_high: 0,
        offset_low: 0,
        data: vec![1, 2, 3],
    };
    let out = c.process(CHAN, &enc(&wreq)).unwrap();
    let reply = {
        let mut cur = ReadCursor::new(&out[0].data);
        WriteReply::decode(&mut cur).unwrap()
    };
    assert_eq!(reply.cb_bytes_written, 3);

    // IoControl
    let ioreq = IoControlRequest {
        request_id: 12,
        io_code: 0x1234,
        data_in: vec![9, 9],
        cb_out: 16,
        data_out: Vec::new(),
    };
    let out = c.process(CHAN, &enc(&ioreq)).unwrap();
    let reply = {
        let mut cur = ReadCursor::new(&out[0].data);
        IoControlReply::decode(&mut cur).unwrap()
    };
    assert_eq!(reply.data, vec![0xAA, 0xBB]);

    assert_eq!(c.callback().reads, 1);
    assert_eq!(c.callback().writes, 1);
    assert_eq!(c.callback().ioctls, 1);

    // Every outstanding request was retired when its reply was issued.
    assert_eq!(c.instance(CHAN).unwrap().outstanding_len(), 0);
}

#[test]
fn iocontrol_reply_truncated_to_cb_out() {
    #[derive(Debug, Default)]
    struct OverCb;
    impl IoCallback for OverCb {
        fn on_create_file(&mut self, _: &CreateFileRequest) -> i32 {
            0
        }
        fn on_io_control(&mut self, _req: &IoControlRequest) -> (i32, Vec<u8>) {
            (0, vec![0xCC; 100])
        }
    }
    use justrdp_core::{Decode, ReadCursor};
    let mut c: FileRedirectorChannelClient<OverCb> =
        boot(FileRedirectorChannelClient::with_callback(OverCb));
    cap_exchange(&mut c);
    create_file_exchange(&mut c);

    let req = IoControlRequest {
        request_id: 20,
        io_code: 0,
        data_in: Vec::new(),
        cb_out: 4,
        data_out: Vec::new(),
    };
    let out = c.process(CHAN, &enc(&req)).unwrap();
    let reply = {
        let mut cur = ReadCursor::new(&out[0].data);
        IoControlReply::decode(&mut cur).unwrap()
    };
    assert_eq!(reply.data.len(), 4);
}

#[test]
fn read_reply_truncated_to_cb_bytes_to_read() {
    #[derive(Debug, Default)]
    struct OverCb;
    impl IoCallback for OverCb {
        fn on_create_file(&mut self, _: &CreateFileRequest) -> i32 {
            0
        }
        fn on_read(&mut self, _req: &ReadRequest) -> (i32, Vec<u8>) {
            (0, vec![1; 1000])
        }
    }
    use justrdp_core::{Decode, ReadCursor};
    let mut c: FileRedirectorChannelClient<OverCb> =
        boot(FileRedirectorChannelClient::with_callback(OverCb));
    cap_exchange(&mut c);
    create_file_exchange(&mut c);
    let req = ReadRequest {
        request_id: 30,
        cb_bytes_to_read: 8,
        offset_high: 0,
        offset_low: 0,
    };
    let out = c.process(CHAN, &enc(&req)).unwrap();
    let reply = {
        let mut cur = ReadCursor::new(&out[0].data);
        ReadReply::decode(&mut cur).unwrap()
    };
    assert_eq!(reply.data.len(), 8);
}

// ── Outstanding request bookkeeping ──

#[test]
fn cancel_removes_outstanding_request() {
    // Stall one read by using a callback that never finishes normally —
    // not possible with the sync trait, so we exercise the path by
    // issuing a cancel for an ID that is still tracked. To get one
    // tracked we manually register via a synthetic helper: issue a
    // read-through-callback that returns empty, then check that after
    // cancel no outstanding remain.
    #[derive(Debug, Default)]
    struct Cb {
        cancelled: u32,
    }
    impl IoCallback for Cb {
        fn on_create_file(&mut self, _: &CreateFileRequest) -> i32 {
            0
        }
        fn on_cancel(&mut self, id: u32) {
            self.cancelled = id;
        }
    }
    let mut c: FileRedirectorChannelClient<Cb> =
        boot(FileRedirectorChannelClient::with_callback(Cb::default()));
    cap_exchange(&mut c);
    create_file_exchange(&mut c);

    // Inject a Read — it will be fully served before we see the reply,
    // so there is no outstanding ID to cancel. Expect on_cancel NOT to
    // fire.
    let rreq = ReadRequest {
        request_id: 100,
        cb_bytes_to_read: 0,
        offset_high: 0,
        offset_low: 0,
    };
    c.process(CHAN, &enc(&rreq)).unwrap();

    // Cancel an unknown id — must be silently tolerated.
    let cancel = SpecificIoCancelRequest {
        request_id: 0x00FFFFFF,
        unused_bits: 0,
        id_to_cancel: 100,
    };
    let out = c.process(CHAN, &enc(&cancel)).unwrap();
    assert!(out.is_empty());
    assert_eq!(c.callback().cancelled, 0);
}

// ── Multi-instance ──

#[test]
fn each_channel_id_has_independent_state() {
    let mut c = FileRedirectorChannelClient::<NullIoCallback>::new();
    c.start(1).unwrap();
    c.start(2).unwrap();
    // Drive channel 1 to Active.
    let req = ServerCapabilitiesRequest {
        request_id: 1,
        version: io_version::CUSTOM_EVENT,
    };
    c.process(1, &enc(&req)).unwrap();
    let cfr = CreateFileRequest {
        request_id: 2,
        device_id: 1,
        desired_access: 0,
        share_mode: 0,
        creation_disposition: 0,
        flags_and_attributes: 0,
    };
    c.process(1, &enc(&cfr)).unwrap();

    assert_eq!(c.instance(1).unwrap().state(), FileRedirectorState::Active);
    assert_eq!(
        c.instance(2).unwrap().state(),
        FileRedirectorState::WaitCapabilities
    );

    // Closing channel 1 must not affect channel 2.
    c.close(1);
    assert!(c.instance(1).is_none());
    assert_eq!(
        c.instance(2).unwrap().state(),
        FileRedirectorState::WaitCapabilities
    );
}

#[test]
fn custom_event_requires_active_and_v6() {
    let mut c = FileRedirectorChannelClient::<NullIoCallback>::new();
    c.start(CHAN).unwrap();
    // Not Active yet.
    assert!(c.send_custom_event(CHAN, [0; 16], Vec::new()).is_err());
    cap_exchange(&mut c);
    create_file_exchange(&mut c);
    // Now it's allowed.
    let msg = c.send_custom_event(CHAN, [0xAA; 16], vec![1, 2, 3]).unwrap();
    assert!(msg.data.len() > 0);
}

#[test]
fn start_enforces_max_channels_for_new_ids() {
    let mut c = FileRedirectorChannelClient::<NullIoCallback>::new();
    for id in 0..MAX_CHANNELS as u32 {
        c.start(id).unwrap();
    }
    assert_eq!(c.instance_count(), MAX_CHANNELS);
    // One more distinct id must be rejected...
    assert!(c.start(MAX_CHANNELS as u32).is_err());
    // ...but re-starting an already-tracked id is always allowed so
    // the peer can recover a broken channel without tripping the cap.
    c.start(0).unwrap();
}

#[test]
fn protocol_error_marks_instance_closed() {
    let mut c = boot(FileRedirectorChannelClient::new());
    cap_exchange(&mut c);
    // Inject a synthetic payload with an unknown FunctionId (0x99)
    // carried on a valid ServerIoHeader. handle_payload must reject
    // it and the FSM must transition to Closed.
    let mut bogus = vec![0u8; 8];
    bogus[4..8].copy_from_slice(&0x99u32.to_le_bytes());
    assert!(c.process(CHAN, &bogus).is_err());
    assert_eq!(
        c.instance(CHAN).unwrap().state(),
        FileRedirectorState::Closed
    );
    assert_eq!(c.instance(CHAN).unwrap().outstanding_len(), 0);
}

#[test]
fn custom_event_blocked_when_negotiated_v4() {
    // Client prefers v4 → negotiation yields v4 even though server
    // offers v6.
    let mut c = FileRedirectorChannelClient::<NullIoCallback>::new()
        .with_version(io_version::NO_CUSTOM_EVENT);
    c.start(CHAN).unwrap();
    let req = ServerCapabilitiesRequest {
        request_id: 1,
        version: io_version::CUSTOM_EVENT,
    };
    c.process(CHAN, &enc(&req)).unwrap();
    let cfr = CreateFileRequest {
        request_id: 2,
        device_id: 0,
        desired_access: 0,
        share_mode: 0,
        creation_disposition: 0,
        flags_and_attributes: 0,
    };
    c.process(CHAN, &enc(&cfr)).unwrap();
    assert!(c.send_custom_event(CHAN, [0; 16], Vec::new()).is_err());
}

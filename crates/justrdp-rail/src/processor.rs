#![forbid(unsafe_code)]

//! RAIL channel processor -- SVC integration.

use alloc::boxed::Box;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor, SvcResult,
};

use crate::backend::RailBackend;
use crate::pdu::{
    ActivatePdu, ClientStatusPdu, CloakPdu, ExecPdu, ExecResultPdu, GetAppIdReqPdu,
    GetAppIdRespPdu, HandshakeExPdu, HandshakePdu, LangBarInfoPdu, LocalMoveSizePdu,
    MinMaxInfoPdu, NotifyEventPdu, RailHeader, RailOrderType, SnapArrangePdu, SysCommandPdu,
    SysMenuPdu, SysParamPdu, WindowMovePdu, ZOrderSyncPdu,
};

/// RAIL SVC channel name.
const RAIL: ChannelName = ChannelName::new(b"rail");

/// Client-side RAIL channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RailState {
    /// Waiting for server handshake (Handshake or HandshakeEx).
    WaitingForHandshake,
    /// Handshake complete, ready for data exchange.
    Active,
}

/// Client-side RAIL channel processor.
///
/// Implements [`SvcProcessor`] to handle the RAIL virtual channel.
pub struct RailClient {
    state: RailState,
    backend: Box<dyn RailBackend>,
    /// Our build number to send in handshake response.
    build_number: u32,
    /// Client status flags to send after handshake.
    client_status_flags: u32,
    /// Server handshake flags (from HandshakeEx, if received).
    server_handshake_flags: u32,
}

impl AsAny for RailClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for RailClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RailClient")
            .field("state", &self.state)
            .field("build_number", &self.build_number)
            .field("client_status_flags", &self.client_status_flags)
            .field("server_handshake_flags", &self.server_handshake_flags)
            .finish()
    }
}

impl RailClient {
    /// Create a new RAIL client processor.
    pub fn new(backend: Box<dyn RailBackend>) -> Self {
        Self {
            state: RailState::WaitingForHandshake,
            backend,
            build_number: 0x00001DB1, // Default build number
            client_status_flags: 0,
            server_handshake_flags: 0,
        }
    }

    /// Set the build number to send in the client handshake response.
    pub fn with_build_number(mut self, build_number: u32) -> Self {
        self.build_number = build_number;
        self
    }

    /// Set the client status flags to send after handshake.
    pub fn with_client_status_flags(mut self, flags: u32) -> Self {
        self.client_status_flags = flags;
        self
    }

    /// Get the server handshake flags (from HandshakeEx).
    pub fn server_handshake_flags(&self) -> u32 {
        self.server_handshake_flags
    }

    /// Encode a PDU into an SvcMessage.
    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build a client execute message.
    pub fn build_exec(
        &self,
        flags: u16,
        exe_or_file: Vec<u8>,
        working_dir: Vec<u8>,
        arguments: Vec<u8>,
    ) -> SvcResult<SvcMessage> {
        let pdu = ExecPdu::new(flags, exe_or_file, working_dir, arguments);
        Self::encode_pdu(&pdu)
    }

    /// Build a window activate message.
    pub fn build_activate(&self, window_id: u32, enabled: bool) -> SvcResult<SvcMessage> {
        let pdu = ActivatePdu::new(window_id, enabled);
        Self::encode_pdu(&pdu)
    }

    /// Build a system command message.
    pub fn build_sys_command(&self, window_id: u32, command: u16) -> SvcResult<SvcMessage> {
        let pdu = SysCommandPdu::new(window_id, command);
        Self::encode_pdu(&pdu)
    }

    /// Build a system menu message.
    pub fn build_sys_menu(&self, window_id: u32, left: i16, top: i16) -> SvcResult<SvcMessage> {
        let pdu = SysMenuPdu::new(window_id, left, top);
        Self::encode_pdu(&pdu)
    }

    /// Build a notify event message.
    pub fn build_notify_event(
        &self,
        window_id: u32,
        notify_icon_id: u32,
        message: u32,
    ) -> SvcResult<SvcMessage> {
        let pdu = NotifyEventPdu::new(window_id, notify_icon_id, message);
        Self::encode_pdu(&pdu)
    }

    /// Build a window move message.
    pub fn build_window_move(
        &self,
        window_id: u32,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    ) -> SvcResult<SvcMessage> {
        let pdu = WindowMovePdu::new(window_id, left, top, right, bottom);
        Self::encode_pdu(&pdu)
    }

    /// Build a window cloak message.
    pub fn build_cloak(&self, window_id: u32, cloaked: bool) -> SvcResult<SvcMessage> {
        let pdu = CloakPdu::new(window_id, cloaked);
        Self::encode_pdu(&pdu)
    }

    /// Build a snap arrange message.
    pub fn build_snap_arrange(
        &self,
        window_id: u32,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    ) -> SvcResult<SvcMessage> {
        let pdu = SnapArrangePdu::new(window_id, left, top, right, bottom);
        Self::encode_pdu(&pdu)
    }

    /// Build a get app ID request message.
    pub fn build_get_app_id_req(&self, window_id: u32) -> SvcResult<SvcMessage> {
        let pdu = GetAppIdReqPdu::new(window_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a language bar info message.
    pub fn build_langbar_info(&self, status: u32) -> SvcResult<SvcMessage> {
        let pdu = LangBarInfoPdu::new(status);
        Self::encode_pdu(&pdu)
    }

    /// Build a system parameters update message.
    pub fn build_sysparam(&self, pdu: &SysParamPdu) -> SvcResult<SvcMessage> {
        Self::encode_pdu(pdu)
    }

    /// Handle the handshake sequence.
    fn handle_handshake(&mut self) -> SvcResult<Vec<SvcMessage>> {
        let mut messages = Vec::new();

        // Client responds with Handshake PDU (always Handshake, never HandshakeEx).
        let handshake = HandshakePdu::new(self.build_number);
        messages.push(Self::encode_pdu(&handshake)?);

        // Send client status PDU.
        let status = ClientStatusPdu::new(self.client_status_flags);
        messages.push(Self::encode_pdu(&status)?);

        self.state = RailState::Active;
        Ok(messages)
    }

    /// Handle a received RAIL PDU.
    fn handle_pdu(
        &mut self,
        header: &RailHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        // During handshake, only accept handshake PDUs.
        if self.state == RailState::WaitingForHandshake {
            match header.order_type {
                RailOrderType::Handshake => {
                    let _pdu = HandshakePdu::decode(body)?;
                    return self.handle_handshake();
                }
                RailOrderType::HandshakeEx => {
                    let pdu = HandshakeExPdu::decode(body)?;
                    self.server_handshake_flags = pdu.rail_handshake_flags;
                    return self.handle_handshake();
                }
                _ => return Ok(Vec::new()),
            }
        }

        // Active state: dispatch by order type.
        match header.order_type {
            RailOrderType::Handshake | RailOrderType::HandshakeEx => {
                // Ignore duplicate handshakes.
                Ok(Vec::new())
            }

            RailOrderType::ExecResult => {
                let pdu = ExecResultPdu::decode(body)?;
                self.backend.on_exec_result(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::SysParam => {
                let pdu = SysParamPdu::decode(body)?;
                self.backend.on_server_sysparam(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::LocalMoveSize => {
                let pdu = LocalMoveSizePdu::decode(body)?;
                self.backend.on_local_move_size(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::MinMaxInfo => {
                let pdu = MinMaxInfoPdu::decode(body)?;
                self.backend.on_min_max_info(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::ZOrderSync => {
                let pdu = ZOrderSyncPdu::decode(body)?;
                self.backend.on_z_order_sync(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::LangBarInfo => {
                let pdu = LangBarInfoPdu::decode(body)?;
                self.backend.on_langbar_info(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::GetAppIdResp => {
                let pdu = GetAppIdRespPdu::decode(body)?;
                self.backend.on_get_app_id_resp(&pdu);
                Ok(Vec::new())
            }

            RailOrderType::Cloak => {
                let pdu = CloakPdu::decode(body)?;
                self.backend.on_server_cloak(&pdu);
                Ok(Vec::new())
            }

            // Client-to-server PDUs that the server should not send to us.
            // Ignore gracefully.
            RailOrderType::Exec
            | RailOrderType::Activate
            | RailOrderType::SysCommand
            | RailOrderType::SysMenu
            | RailOrderType::NotifyEvent
            | RailOrderType::WindowMove
            | RailOrderType::ClientStatus
            | RailOrderType::GetAppIdReq
            | RailOrderType::SnapArrange => Ok(Vec::new()),

            // Other server PDUs we don't need to act on currently.
            _ => Ok(Vec::new()),
        }
    }
}

impl SvcProcessor for RailClient {
    fn channel_name(&self) -> ChannelName {
        RAIL
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for server to send handshake first.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);
        let header = RailHeader::decode(&mut cursor)?;

        // Verify declared orderLength matches actual payload size.
        if header.order_length as usize != payload.len() {
            return Err(justrdp_svc::SvcError::Protocol(
                alloc::format!(
                    "RAIL orderLength mismatch: declared={}, actual={}",
                    header.order_length,
                    payload.len()
                ),
            ));
        }

        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for RailClient {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::AsAny;

    struct TestBackend {
        exec_results: Vec<ExecResultPdu>,
        sysparams: Vec<SysParamPdu>,
        move_sizes: Vec<LocalMoveSizePdu>,
        min_max_infos: Vec<MinMaxInfoPdu>,
        z_order_syncs: Vec<ZOrderSyncPdu>,
        langbar_infos: Vec<LangBarInfoPdu>,
        app_id_resps: Vec<GetAppIdRespPdu>,
        cloaks: Vec<CloakPdu>,
    }

    impl AsAny for TestBackend {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                exec_results: Vec::new(),
                sysparams: Vec::new(),
                move_sizes: Vec::new(),
                min_max_infos: Vec::new(),
                z_order_syncs: Vec::new(),
                langbar_infos: Vec::new(),
                app_id_resps: Vec::new(),
                cloaks: Vec::new(),
            }
        }
    }

    impl RailBackend for TestBackend {
        fn on_exec_result(&mut self, result: &ExecResultPdu) {
            self.exec_results.push(result.clone());
        }
        fn on_server_sysparam(&mut self, pdu: &SysParamPdu) {
            self.sysparams.push(pdu.clone());
        }
        fn on_local_move_size(&mut self, pdu: &LocalMoveSizePdu) {
            self.move_sizes.push(pdu.clone());
        }
        fn on_min_max_info(&mut self, pdu: &MinMaxInfoPdu) {
            self.min_max_infos.push(pdu.clone());
        }
        fn on_z_order_sync(&mut self, pdu: &ZOrderSyncPdu) {
            self.z_order_syncs.push(pdu.clone());
        }
        fn on_langbar_info(&mut self, pdu: &LangBarInfoPdu) {
            self.langbar_infos.push(pdu.clone());
        }
        fn on_get_app_id_resp(&mut self, pdu: &GetAppIdRespPdu) {
            self.app_id_resps.push(pdu.clone());
        }
        fn on_server_cloak(&mut self, pdu: &CloakPdu) {
            self.cloaks.push(pdu.clone());
        }
    }

    fn make_client() -> RailClient {
        RailClient::new(Box::new(TestBackend::new()))
    }

    fn encode_handshake() -> Vec<u8> {
        let pdu = HandshakePdu::new(0x1DB1);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    fn encode_handshake_ex(flags: u32) -> Vec<u8> {
        let pdu = HandshakeExPdu::new(0x1DB1, flags);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    #[test]
    fn handshake_flow() {
        let mut client = make_client();
        assert_eq!(client.state, RailState::WaitingForHandshake);

        let responses = client.process(&encode_handshake()).unwrap();
        assert_eq!(client.state, RailState::Active);
        // Should send: Handshake + ClientStatus
        assert_eq!(responses.len(), 2);
    }

    #[test]
    fn handshake_ex_flow() {
        let mut client = make_client();
        let responses = client
            .process(&encode_handshake_ex(
                crate::pdu::TS_RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF,
            ))
            .unwrap();
        assert_eq!(client.state, RailState::Active);
        assert_eq!(
            client.server_handshake_flags(),
            crate::pdu::TS_RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF,
        );
        assert_eq!(responses.len(), 2);
    }

    #[test]
    fn rejects_data_before_handshake() {
        let mut client = make_client();

        // Send an exec result before handshake — should be ignored.
        let exec_result = ExecResultPdu::new(
            0,
            crate::pdu::RAIL_EXEC_S_OK,
            0,
            b"n\x00".to_vec(),
        );
        let mut buf = vec![0u8; exec_result.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        exec_result.encode(&mut cursor).unwrap();

        let responses = client.process(&buf).unwrap();
        assert_eq!(responses.len(), 0);
        assert_eq!(client.state, RailState::WaitingForHandshake);
    }

    #[test]
    fn exec_result_dispatch() {
        let mut client = make_client();
        client.process(&encode_handshake()).unwrap();

        let exec_result = ExecResultPdu::new(
            0,
            crate::pdu::RAIL_EXEC_S_OK,
            0,
            b"n\x00o\x00t\x00e\x00".to_vec(),
        );
        let mut buf = vec![0u8; exec_result.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        exec_result.encode(&mut cursor).unwrap();

        client.process(&buf).unwrap();

        let backend = client.backend.as_any().downcast_ref::<TestBackend>().unwrap();
        assert_eq!(backend.exec_results.len(), 1);
        assert_eq!(
            backend.exec_results[0].exec_result,
            crate::pdu::RAIL_EXEC_S_OK,
        );
    }

    #[test]
    fn z_order_sync_dispatch() {
        let mut client = make_client();
        client.process(&encode_handshake()).unwrap();

        let pdu = ZOrderSyncPdu::new(0xDEAD);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        client.process(&buf).unwrap();

        let backend = client.backend.as_any().downcast_ref::<TestBackend>().unwrap();
        assert_eq!(backend.z_order_syncs.len(), 1);
        assert_eq!(backend.z_order_syncs[0].window_id_marker, 0xDEAD);
    }

    #[test]
    fn cloak_dispatch() {
        let mut client = make_client();
        client.process(&encode_handshake()).unwrap();

        let pdu = CloakPdu::new(0x42, true);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        client.process(&buf).unwrap();

        let backend = client.backend.as_any().downcast_ref::<TestBackend>().unwrap();
        assert_eq!(backend.cloaks.len(), 1);
        assert!(backend.cloaks[0].cloaked);
    }

    #[test]
    fn build_exec_message() {
        let client = make_client();
        let msg = client
            .build_exec(0, b"n\x00".to_vec(), Vec::new(), Vec::new())
            .unwrap();
        assert!(!msg.data.is_empty());
    }

    #[test]
    fn build_sys_command_message() {
        let client = make_client();
        let msg = client
            .build_sys_command(0x42, crate::pdu::SC_MAXIMIZE)
            .unwrap();
        assert_eq!(msg.data.len(), crate::pdu::SysCommandPdu::FIXED_SIZE);
    }

    #[test]
    fn duplicate_handshake_ignored() {
        let mut client = make_client();
        let responses = client.process(&encode_handshake()).unwrap();
        assert_eq!(responses.len(), 2);

        // Second handshake should be ignored.
        let responses = client.process(&encode_handshake()).unwrap();
        assert_eq!(responses.len(), 0);
    }

    #[test]
    fn channel_name() {
        let client = make_client();
        assert_eq!(client.channel_name().as_str(), "rail");
    }
}

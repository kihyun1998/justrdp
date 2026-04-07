#![forbid(unsafe_code)]

//! RAIL backend trait -- application-level RemoteApp integration.

use justrdp_core::AsAny;

use crate::pdu::{
    CloakPdu, ExecResultPdu, GetAppIdRespPdu, LangBarInfoPdu, LocalMoveSizePdu, MinMaxInfoPdu,
    SysParamPdu, ZOrderSyncPdu,
};

/// Application-level RAIL backend.
///
/// Implement this trait to handle RAIL events from the server.
/// All methods have default no-op implementations except `on_exec_result`,
/// which is typically required to know whether the remote app launched.
pub trait RailBackend: AsAny + Send {
    /// Called when the server sends an execute result.
    fn on_exec_result(&mut self, result: &ExecResultPdu);

    /// Called when the server sends a system parameters update.
    fn on_server_sysparam(&mut self, _pdu: &SysParamPdu) {}

    /// Called when the server starts or ends a local move/size operation.
    fn on_local_move_size(&mut self, _pdu: &LocalMoveSizePdu) {}

    /// Called when the server sends min/max info for a window.
    fn on_min_max_info(&mut self, _pdu: &MinMaxInfoPdu) {}

    /// Called when the server sends a Z-order sync.
    fn on_z_order_sync(&mut self, _pdu: &ZOrderSyncPdu) {}

    /// Called when the server sends a language bar info update.
    fn on_langbar_info(&mut self, _pdu: &LangBarInfoPdu) {}

    /// Called when the server sends a get app ID response.
    fn on_get_app_id_resp(&mut self, _pdu: &GetAppIdRespPdu) {}

    /// Called when the server sends a cloak state change.
    fn on_server_cloak(&mut self, _pdu: &CloakPdu) {}
}

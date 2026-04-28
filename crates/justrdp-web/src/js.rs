#![forbid(unsafe_code)]

//! `wasm-bindgen` JavaScript facade (wasm32 only).
//!
//! Thin shim that ties [`WebSocketTransport`] and [`WebClient`] together
//! into a one-shot `connect()` Promise visible from JS. Native callers
//! should prefer `WebClient::connect()` directly — this module exists
//! only to give browser embedders an out-of-the-box entry point.
//!
//! S2 surface is intentionally minimal — Standard RDP Security only,
//! no post-handshake plumbing. S3+ will add the active-session pump and
//! a stateful `JsClient` handle.

use alloc::format;
use alloc::string::String;

use js_sys::{Object, Reflect};
use justrdp_connector::Config;
use justrdp_pdu::x224::SecurityProtocol;
use wasm_bindgen::prelude::*;

use crate::driver::WebClient;
use crate::websocket::{WebSocketConfig, WebSocketTransport};

/// One-shot Standard-Security connect.
///
/// Resolves with a small JS object describing the negotiated session:
/// ```text
/// { shareId, ioChannelId, userChannelId, channels: ["rdpdr", ...] }
/// ```
/// Rejects with an `Error` whose message is a human-readable diagnostic.
#[wasm_bindgen(js_name = justrdpConnect)]
pub async fn justrdp_connect(
    url: String,
    username: String,
    password: String,
    domain: Option<String>,
) -> Result<JsValue, JsValue> {
    // 1. Open the WebSocket bridge.
    let transport = WebSocketTransport::connect(WebSocketConfig::new(url))
        .await
        .map_err(|e| js_error(format!("websocket: {e}")))?;

    // 2. Build a Standard-Security Config. Builder defaults are sane; we
    //    only override auth/security flags and the browser-sourced
    //    client_random.
    let mut client_random = [0u8; 32];
    getrandom::getrandom(&mut client_random)
        .map_err(|e| js_error(format!("crypto.getRandomValues: {e}")))?;

    let mut builder =
        Config::builder(&username, &password).security_protocol(SecurityProtocol::RDP);
    if let Some(d) = domain.as_deref().filter(|s| !s.is_empty()) {
        builder = builder.domain(d);
    }
    let mut config = builder.build();
    config.client_random = Some(client_random);

    // 3. Drive the handshake.
    let client = WebClient::new(transport);
    let (result, _transport) = client
        .connect(config)
        .await
        .map_err(|e| js_error(format!("handshake: {e}")))?;

    // S2 lets the transport drop here; S3 will retain it on a JsClient
    // handle for the active-session pump. WebSocketTransport sends a
    // close frame on Drop via its retained event-handler closures.
    Ok(serialize_summary(&result))
}

fn js_error(msg: impl Into<String>) -> JsValue {
    js_sys::Error::new(&msg.into()).into()
}

fn serialize_summary(result: &justrdp_connector::ConnectionResult) -> JsValue {
    let obj = Object::new();
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("shareId"),
        &JsValue::from_f64(result.share_id as f64),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("ioChannelId"),
        &JsValue::from_f64(result.io_channel_id as f64),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("userChannelId"),
        &JsValue::from_f64(result.user_channel_id as f64),
    );
    let channels = js_sys::Array::new();
    for (name, _id) in &result.channel_ids {
        channels.push(&JsValue::from_str(name));
    }
    let _ = Reflect::set(&obj, &JsValue::from_str("channels"), &channels);
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("selectedProtocol"),
        &JsValue::from_str(&format!("{:?}", result.selected_protocol)),
    );
    obj.into()
}


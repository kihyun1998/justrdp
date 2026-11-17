#![no_main]
//! Fuzz the RD Gateway client sequence (#613). Sibling of
//! `receive_never_panics_and_never_buffers_past_the_limit` in `justrdp::gateway`.
//!
//! `GatewayStateMachine::receive` frames the gateway's bytes into packets by `packetLength`,
//! decodes each with `tsgu::Packet::decode_with_unread` and acts on it by stage. The first input byte picks
//! what arrives first, so the arms behind it are reached: the four responses of the sequence
//! (the open channel), or a handshake response and a tunnel response with a consent message
//! (the pending answer). It also picks how the rest is split across reads. A consent answer
//! follows every read.

use justrdp::gateway::{GatewayConfig, GatewayStateMachine, PaaCookie};
use justrdp_pdu::tsgu::{
    ChannelResponse, HandshakeResponse, Packet, TunnelAuthResponse, TunnelResponse, UnicodeString,
};
use libfuzzer_sys::fuzz_target;

fn opening_responses() -> Vec<u8> {
    let packets = [
        Packet::HandshakeResponse(HandshakeResponse {
            error_code: 0,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: 2,
        }),
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(1),
            caps_flags: Some(2),
            soh_request: None,
            consent_msg: None,
        }),
        Packet::TunnelAuthResponse(TunnelAuthResponse {
            error_code: 0,
            redir_flags: Some(0),
            idle_timeout: Some(0),
            soh_response: None,
        }),
        Packet::ChannelResponse(ChannelResponse {
            error_code: 0,
            channel_id: Some(1),
            udp_port: None,
            authn_cookie: None,
        }),
    ];
    packets
        .iter()
        .flat_map(|packet| packet.encode().expect("fixed-size responses encode"))
        .collect()
}

fn consent_responses() -> Vec<u8> {
    let packets = [
        Packet::HandshakeResponse(HandshakeResponse {
            error_code: 0,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: 2,
        }),
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(1),
            caps_flags: Some(4),
            soh_request: None,
            consent_msg: Some(UnicodeString::from_str_nul("consent")),
        }),
    ];
    packets
        .iter()
        .flat_map(|packet| packet.encode().expect("short responses encode"))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let mut machine = GatewayStateMachine::new(GatewayConfig {
        paa_cookie: PaaCookie::from_token("cookie"),
        target_host: "target".to_string(),
        target_port: 3389,
        client_name: "client".to_string(),
    })
    .expect("a short config encodes");
    machine.start();
    match shape & 3 {
        1 => drop(machine.receive(&opening_responses())),
        2 => drop(machine.receive(&consent_responses())),
        _ => {}
    }
    for read in rest.chunks(usize::from(shape >> 2) + 1) {
        let _ = machine.receive(read);
        let _ = if read.len() % 2 == 0 {
            machine.accept_consent()
        } else {
            machine.decline_consent()
        };
        let _ = machine.send(read);
    }
    let _ = machine.close();
});

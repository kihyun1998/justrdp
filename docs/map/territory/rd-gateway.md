# RD Gateway

## What it is

Reaching a server that only an RD Gateway can reach (`[MS-TSGU]`, HTTP transport over
WebSocket). The client opens TLS to the gateway, upgrades an HTTP request to WebSocket, and runs
four request/response pairs: handshake, tunnel create, tunnel authorize, channel create. After
that the gateway relays opaque bytes, and the whole RDP connection (X.224, the target's own TLS,
CredSSP) runs end to end with the target inside data packets.

One combination is built: the WebSocket transport, authenticated by a PAA cookie the host
already holds. See `## Known holes / open` for the rest.

## Governing decisions

- [ADR-0001](../../adr/0001-sans-io-state-machine-core.md) — the MS-TSGU sequence is a sans-IO
  machine in the core; sockets, TLS and the WebSocket are the adapter's.
- [ADR-0002](../../adr/0002-dependency-boundary.md), 2026-11-16 amendment — the WebSocket client
  is owned, inside `justrdp-tokio`, with no new dependency.
- [ADR-0005](../../adr/0005-tls-trust-policy.md), 2026-11-16 amendment — the gateway's
  certificate is checked under a `TrustPolicy` of its own, chosen by the host.
- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) — `capsFlags` is an implementation
  flag: the core advertises what it handles, not what `mstsc.exe` sends.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — every parser here reads
  the gateway's bytes.

## Design model

- **Three layers, and each owns one framing.** `justrdp_pdu::tsgu` is bytes to packets.
  `justrdp::gateway::GatewayStateMachine` is the sequence, and it frames the gateway's bytes
  into packets by `packetLength`. `justrdp_tokio::GatewayStream` is TLS, the WebSocket and the
  stream a connect runs over.
- **WebSocket frames carry a byte stream, not messages.** The payload of every binary frame is
  appended to one stream and split by `packetLength`, as FreeRDP does (`rdg.c`,
  `rdg_read_all`/`rdg_process_packet`). A packet may span frames and a frame may hold several
  packets. IronRDP's `ironrdp-mstsgu` assumes one message is one packet.
- **`packetLength` is capped in the core, at `MAX_PACKET_LEN` = 131,116 bytes**: the longest
  packet whose layout `tsgu` knows, a tunnel response with two 65,535-byte strings. The header
  alone refuses a longer one, so its body is never awaited. `tsgu::Packet::decode` itself
  answers `NotEnoughBytes` for any `u32`; a caller that buffers until `needed` without this cap
  holds up to 4 GiB.
- **Binary frame payload is never held whole.** `FrameDecoder` hands payload on as it arrives, so
  a frame's 63-bit length needs no cap. What is capped: a control frame at 125 bytes (RFC 6455
  5.5), the upgrade response header at 16 KiB, and replies not yet written at 256 KiB.
- **`capsFlags` is one constant, `ADVERTISED_CAPS`, and it is 0.** Each of the six capabilities
  asks the client for something it does not do: a statement of health, a consent or service
  message put in front of a user, reauthentication, UDP, and for `HTTP_CAPABILITY_IDLE_TIMEOUT`
  a timer. That timer is the client's: `[MS-TSGU]` 3.5.2.1 has the client end the protocol when
  it expires, and a product note says idle timeout "is configured on the RDG server and is
  enforced on the RDG client". Nothing here runs one. A gateway that negotiates it anyway has its `idleTimeout`
  handed to the host in `GatewayChannel`, whose timer it then is.
  `mstsc.exe` sends 0x3f, FreeRDP 0x0D (`rdg.c`, `rdg_send_tunnel_request`) and IronRDP 0x14,
  consent and reauth, under the comment "No observed server works without this capability"
  (`ironrdp-mstsgu`, `src/lib.rs`). **No client known here sends 0, and no gateway has been
  asked to accept it.**
- **A non-zero `errorCode` or `statusCode` ends the sequence**, as `[MS-TSGU]` 3.7.5.2 says.
  FreeRDP ends the handshake, the tunnel create and the channel create on `FAILED(hr)` only, so
  it carries on past a positive non-zero code there; its tunnel authorization admits `S_OK` and
  `E_PROXY_QUARANTINE_ACCESSDENIED`. No server has been seen to send a positive code.
- **`fieldsPresent` of the tunnel create is 0x1 for a PAA cookie.** The spec contradicts itself:
  2.2.5.3.6 defines `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` as 0x1, and 3.7.5.2 step 1 says "set
  fieldsPresent to 2". `mstsc.exe` and FreeRDP send 0x1.
- **The gateway's trust policy is separate from the target's.** `GatewayOptions::trust` is
  applied to the gateway's certificate, `ConnectOptions::trust` to the target's inside the
  tunnel. A TOFU pin store keys by host name, so a host that pins both gives each its own store
  when the two names could collide.
- **Replies go out while the stream is read.** A keep-alive or a WebSocket ping is answered from
  `poll_read`, ahead of the bytes it returns, and flushed, since a TLS stream can hold a write
  until the next one. The answer to the gateway's close goes out the same way, with the read
  that saw it. A session that stops reading stops answering. When the gateway does not read
  the replies, reading pauses at 256 KiB of them.
- **The two directions may run on different tasks.** A reader held back by unsent replies and a
  writer waiting for them share the connection's one write registration, so the stream keeps a
  waker for each and the drain wakes both.
- **Why the gateway closed is on the stream.** A non-zero close status is the read's error
  (`ConnectionAborted`, the status in its text), and `GatewayStream::close_status` returns the
  code. The session runners take the stream by reference, so a host can ask after they return.
- **The client answers keep-alives and does not originate them**, as FreeRDP
  (`rdg_process_keep_alive_packet`). `[MS-TSGU]` 3.3.3.1 and 3.3.6.4 give the client a
  keep-alive timer of its own (15 minutes by default, 8 in the clients note <53> lists). It is
  not run.
- **Shutting down does not wait for the gateway's close response.** `[MS-TSGU]` 3.7.5.4 has the
  client wait for `PKT_TYPE_CLOSE_CHANNEL_RESPONSE`. `poll_shutdown` sends the close packet and
  the WebSocket close frame and shuts the connection, so a dead gateway cannot hold it.
- **A text frame is dropped**, as FreeRDP drops what is not binary. A masked frame, a reserved
  bit or opcode, and a malformed control frame end the tunnel (RFC 6455 5.1, 5.2, 5.5).
- **The upgrade request carries what RFC 6455, `[MS-TSGU]` 3.3.5.1 and the observed client
  require**: `Host`, `Connection`, `Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`,
  `RDG-Connection-Id`, `RDG-Auth-Scheme: PAA`, and `Accept: */*`, `Cache-Control: no-cache` and
  `Pragma: no-cache`, since 3.3.5.1 has the client disallow caching and accept `*/*`. The
  scheme header is spelled as FreeRDP spells it; #613 records `mstsc.exe`'s as
  `Rdg-Auth-Scheme`, and header names compare without case. FreeRDP
  also sends `User-Agent: MS-RDGateway/1.0`, `RDG-Correlation-Id` and a `Content-Length`
  (`http.c`, `http_request_write`). Whether a Windows gateway needs any of those is not measured.
- **What the tunnel costs, measured** (#613, 2026-11-16, `--release`, 256 MiB in 16 KiB writes
  over an in-memory pipe on one thread, three runs, other work running on the host): the bare
  pipe moved 21,990 to 22,380 MiB/s, a `GatewayStream` read 5,360 to 5,680 MiB/s and wrote
  1,250 to 1,330 MiB/s. Writing is the slower way because every client frame draws a mask from
  the OS and is masked byte by byte. The session's writes are input events.
- **`connect_over_gateway` announces `tcp-connect`**, which completes at once: the core's
  `Action::Connect` says "open the stream", and the tunnel is that stream. The core connect
  machine is unchanged.
- **The cookie is written to the gateway and to nothing else.** `PaaCookie`, `GatewayConfig`,
  `GatewayStateMachine`, `GatewayAction` and `GatewayStream` print no cookie byte in `Debug`:
  an action prints the length of the bytes it carries. No log line and no error carries a
  packet's bytes. The cookie's memory is not zeroed when it is dropped.
- **A failure names the stage the machine was in when it failed.** One read can carry several
  responses, so `open_over` asks the machine after each step, and announces every stage a step
  passed through before it reports the outcome.

## Code

- `justrdp-pdu/src/tsgu.rs` — `Packet`, `PacketHeader`, `PaaCookie`, `UnicodeString`,
  `TunnelCreate`, `TunnelResponse`, `SohRequest`, `TunnelAuth`, `TunnelAuthResponse`,
  `ChannelCreate`, `ChannelResponse`, `EncodeError`
- `justrdp/src/gateway.rs` — `GatewayStateMachine`, `GatewayConfig`, `GatewayAction`,
  `GatewayChannel`, `GatewayError`, `GatewayErrorKind`, `ADVERTISED_CAPS`, `MAX_PACKET_LEN`,
  `MAX_DATA_LEN`
- `justrdp-tokio/src/gateway.rs` — `open_gateway`, `open_over`, `host_header`,
  `announce_up_to`, `GatewayStream`, `close_status`, `GatewayOptions`, `GatewayFailure`,
  `GatewayFailureKind`, `MAX_PENDING_OUT`, `GATEWAY_CAPTURE_FILE`
- `justrdp-tokio/src/websocket.rs` — `upgrade_request`, `parse_upgrade_response`, `accept_for`,
  `base64`, `encode_frame`, `FrameDecoder`, `FrameError`, `UpgradeError`,
  `MAX_UPGRADE_RESPONSE_LEN`
- `justrdp-tokio/src/lib.rs` — `connect_over_gateway`, `ConnectWire`, `SessionStream`,
  `relay_gateway`, `a_real_rd_gateway_reaches_the_target_server`
- `fuzz/fuzz_targets/tsgu.rs`, `fuzz/fuzz_targets/gateway.rs`, `fuzz/fuzz_targets/websocket.rs`
- Stage strings: `gateway-tcp-connect`, `gateway-tls-handshake`, `gateway-websocket-upgrade`,
  `gateway-handshake`, `gateway-tunnel-create`, `gateway-tunnel-auth`, `gateway-channel-create`,
  `gateway-channel-open`
- Spec sections cited inline: `[MS-TSGU]` 2.2.5.3, 2.2.10, 3.3.5.1, 3.7.5.2 to 3.7.5.4;
  RFC 6455 1.3, 4.1, 5.1 to 5.5

## Reference behaviour

**What `mstsc.exe` sends** (#613, captured with a stand-in gateway, `gatewaycredentialssource:i:5`):
`RDG_OUT_DATA /remoteDesktopGateway/` with a WebSocket upgrade, a `Rdg-Auth-Scheme: PAA` header
and no `Authorization` header; handshake `extendedAuth` 0x2; tunnel create with `capsFlags` 0x3f
and `fieldsPresent` 0x1; the cookie as UTF-16LE with a terminating NUL. No capture bytes are in
the repo: the tests' expected requests are written out from these values and the spec layouts.
This client's requests are those bytes except `capsFlags`.

**No run against a real RD Gateway is recorded here yet.** #613 carries it. The run reads its
gateway, target and cookie from the environment, so none is committed:

| Variable | Holds |
|---|---|
| `JUSTRDP_TEST_GATEWAY` | the gateway, `host` or `host:port` (443 when omitted) |
| `JUSTRDP_TEST_GATEWAY_TARGET` | the target as the gateway resolves it, `host` or `host:port` (3389 when omitted) |
| `JUSTRDP_TEST_GATEWAY_COOKIE` | the PAA cookie |
| `JUSTRDP_TEST_USERNAME`, `JUSTRDP_TEST_PASSWORD`, `JUSTRDP_TEST_DOMAIN` | the target's logon |
| `JUSTRDP_GATEWAY_CAPTURE_FILE` | optional: a file every MS-TSGU byte the gateway sends is appended to |

```sh
cargo test -p justrdp-tokio --lib a_real_rd_gateway_reaches_the_target_server -- --ignored --nocapture
```

The capture is server-to-client, after the WebSocket frames are read, so the cookie is not in
it. A channel response's `authnCookie` would be, and so are the target's bytes (TLS records).
Read it before committing it.

**What that run should settle**, none of it measured:

- whether a Windows gateway opens a tunnel for `capsFlags` 0. IronRDP's comment says none it
  saw worked without consent signing (0x4). A refusal would be a tunnel response status such as
  `E_PROXY_CAPABILITYMISMATCH` (0x800759E9) in `gateway-tunnel-create`, and the way past it is
  handing consent messages to the host, then advertising 0x4;
- whether it accepts the upgrade request without the headers FreeRDP adds. IronRDP's request
  carries about the same set as this one;
- what the gateway sends when the target ends the connection: a close packet and its status, or
  the end of the stream;
- **the nonce length of the tunnel response.** `[MS-TSGU]` 2.2.10.21 says 16 bytes (a GUID) and
  `tsgu` follows it; FreeRDP's `rdg.c` skips 20 and IronRDP's `ironrdp-mstsgu` reads a `u16`,
  neither with a reason. It is present only under `fieldsPresent` 0x4
  (`HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ`), which a gateway should not set for a client that did
  not advertise `HTTP_CAPABILITY_TYPE_QUAR_SOH`. If the capture shows that bit, keep the bytes:
  they settle it.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — four parsers
  read the gateway's bytes: `tsgu::Packet::decode`, `GatewayStateMachine::receive`,
  `FrameDecoder::feed` and `parse_upgrade_response`. Each has a property and a fuzz target.
  **`tsgu`'s undirected property reaches only the header** (#612): random bytes rarely form a
  `packetLength` that covers a body, so the bodies are reached by its corrupted-packet property,
  which overwrites and truncates valid packets. The properties here are built the same way, from
  well-formed packets and frames with fields overwritten.
- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md) —
  `ADVERTISED_CAPS`, which is why it is 0. It was 0x2 while this change was written, on the
  reading that the gateway enforces the idle timer; the timer in 3.3.6.1 is the server's session
  timeout, and the idle one is the client's.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — the tunnel response's `serverVersion`, `nonce`, `serverCert` and `consentMsg`, the tunnel
  authorization's `SoHResponse`, and the channel response's `udpPort` and `authnCookie` are
  decoded and not read. Each belongs to a capability that is not advertised or a transport that
  is not built. `redirFlags`, `idleTimeout`, the ids and the negotiated capabilities reach the
  host in `GatewayChannel`.
  **The handshake response's version and `ExtendedAuth` are decoded and not read, and that one
  is undecided.** The client asked for PAA and `ExtendedAuth` is the gateway's answer.
  `[MS-TSGU]` 3.7.3 has the version match. FreeRDP reads neither (`rdg.c`,
  `rdg_process_handshake_response`), IronRDP checks the version, and the maintainer's IronRDP
  fork fails when the PAA bit is missing (commit `12b9822f`). A gateway without PAA fails the
  tunnel create one stage later, with its own code.

## Blast radius

- [TLS transport security & server trust](tls-transport-security.md) — `client_config` and
  `TrustPolicy` now serve two handshakes, the gateway's and the target's.
- [Adapter drive loop](adapter-drive-loop.md) — `connect_inner` is generic over the wire it
  dials, and `SessionStream` has two variants for a session inside a tunnel.
- [X.224 negotiation](x224-negotiation.md) — the first bytes inside the tunnel.
- [NLA / CredSSP authentication](nla-credssp.md) — runs over `TlsStream<GatewayStream>`.
- [Session loop & PDU dispatch](session-loop-dispatch.md) — the session runners read and write a
  `SessionStream`; keep-alives are answered only while they read.
- [Wire framing primitives](wire-framing.md) — `tsgu` reads through `ReadCursor`.
- [Verification harness](verification-harness.md) — the stand-in gateway (`StandIn`,
  `relay_gateway`) and the `JUSTRDP_TEST_GATEWAY*` variables.
- [Supply chain and gates](supply-chain-and-gates.md) — the fuzz crate now depends on
  `justrdp-tokio`, through its `fuzzing` feature.

## Known holes / open

- **Not built**: NTLM, Negotiate and Basic HTTP authentication, `SSPI_NTLM` extended
  authentication, the legacy dual-channel HTTP transport and the RPC transport, reauthentication,
  consent and service messages, UDP, and HTTP proxies. A service message or a reauth message
  that arrives is skipped; a gateway that then closes for a failed reauthentication says so only
  in its close status.
- **The session runners do not report why the gateway closed.** A read error ends them as an
  unexpected disconnect, as for a socket. The host asks `GatewayStream::close_status`.
- **No test reaches session-active through a tunnel.** The loopback connect ends after CredSSP,
  where the mock target hangs up, so `ConnectWire`'s two conversions to a `SessionStream` run
  only in the real-gateway test. A session runner over `SessionStream::GatewayTls` is tested
  (`a_session_runs_inside_a_gateway_tunnel`).
- **Standard RDP Security through a tunnel is untested.** `SessionStream::Gateway` exists
  because `connect_inner` is generic; the server's refusal of that protection is recognised by
  a reset or an end of the socket, which a tunnel may report differently.
- **`RDG-User-Id` is not sent.** `[MS-TSGU]` 3.3.5.1 says the request SHOULD carry it; it is
  the user's name, for the gateway's event log.
- **No real gateway has answered this client** (see `## Reference behaviour`).
- **`RDG-Correlation-Id` is not sent.** `[MS-TSGU]` 2.2.3.2.2 makes it optional, and equal to
  the Connection Request's `RDP_NEG_CORRELATION_INFO` when present. `open_gateway` runs before
  the connect config exists, so it does not know that id
  ([X.224 negotiation](x224-negotiation.md)).
- **The client's keep-alive timer is not run**, so a gateway that expects the client to
  originate keep-alives would see none.
- **`JUSTRDP_GATEWAY_CAPTURE_FILE` has no test of its own**: it calls the same `append_capture`
  the connect and session captures use.

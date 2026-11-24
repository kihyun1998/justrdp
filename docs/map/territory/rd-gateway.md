# RD Gateway

## What it is

Reaching a server that only an RD Gateway can reach (`[MS-TSGU]`, HTTP transport over
WebSocket). The client opens TLS to the gateway, upgrades an HTTP request to WebSocket, and runs
four request/response pairs: handshake, tunnel create, tunnel authorize, channel create. A
gateway may put a consent message in its tunnel response, which the host accepts or declines
before the tunnel is authorized. After
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
  flag: the core advertises what it handles, not what `mstsc.exe` sends. Whether a consent
  message is accepted is the host's policy, so nothing here accepts one for it.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — every parser here reads
  the gateway's bytes.

## Design model

- **Three layers, and each owns one framing.** `justrdp_pdu::tsgu` is bytes to packets.
  `justrdp::gateway::GatewayStateMachine` is the sequence, and it frames the gateway's bytes
  into packets by `packetLength`. `justrdp_tokio::GatewayStream` is TLS, the WebSocket and the
  stream a connect runs over.
- **WebSocket frames carry a byte stream, not messages.** The payload of every binary frame is
  appended to one stream and split by `packetLength`, as FreeRDP does for every packet but a
  data packet (`rdg.c`, `rdg_read_all`/`rdg_process_packet`; its data path reads `cbDataLen`
  bytes instead, below). A packet may span frames and a frame may hold several
  packets. IronRDP's `ironrdp-mstsgu` assumes one message is one packet.
- **`packetLength` is capped in the core, at `MAX_PACKET_LEN` = 131,116 bytes**: the longest
  packet whose layout `tsgu` knows, a tunnel response with two 65,535-byte strings. The header
  alone refuses a longer one, so its body is never awaited. `tsgu::Packet::decode` itself
  answers `NotEnoughBytes` for any `u32`; a caller that buffers until `needed` without this cap
  holds up to 4 GiB.
- **Body bytes after a packet's last field are logged, not refused.**
  `tsgu::Packet::decode_with_unread` returns the packet and how many bytes inside
  `packetLength` follow its last field: after `Data`'s `cbDataLen`-prefixed data too, the
  whole body of a keep-alive, and none for `Other`, which keeps its body. `receive` acts on the
  packet as it would without them, and when the count is not zero writes one debug record under
  the `rdg_packet` target with `packet_type` and `unread`, never the bytes. A field that runs
  past `packetLength` is still `InvalidField`, and a packet the padding takes past
  `MAX_PACKET_LEN` is still `PacketTooLong`.
  - Ground: `[MS-TSGU]` 2.2.10.9 calls `packetLength` "the length of the packet" and has no
    MUST that the fields fill it, nor anything about extra bytes. FreeRDP master warns
    "unparsed data detected" with the type and the count and carries on, for the packets
    `rdg_process_packet` handles (`rdg.c`, commit `de4109b0a7`, first in 3.22.0); its data
    path reads `cbDataLen` bytes and does not look at `packetLength`. `ironrdp-mstsgu`
    (`lib.rs`) differs per packet: an error after the handshake response and an extended auth
    message, an `assert!` on the tunnel and channel responses, and no check on the tunnel
    authorization response or a data packet. A decode failure ends the tunnel in every state,
    so a refusal would put a session-ending failure on a path nothing has observed, the ground
    ADR-0009's 2026-09-18 amendment kept a skip on. The Windows Server 2019 gateway's
    committed packets (`## Reference behaviour`) fill `packetLength` exactly; the success
    run's packets were not committed.
  - The record catches a layout this decoder gets wrong as much as a gateway that pads:
    FreeRDP's warning fired on its own unparsed channel response optional fields, and commit
    `3d8bcd1c71` parsed them "just to avoid warnings about incompletely parsed packets". That
    is the risk ADR-0009's Consequences names, tolerance masking a bug in our own decoder.
  - Every occurrence is logged, not the first per machine. The record is at debug under a
    target the host enables, `rdg_packet` already writes one record per skipped packet, a
    once-flag would be state on the machine kept for a log line, and it would hide a second
    packet type that pads after the first.
  - Tolerating and logging is **the maintainer's judgement** (#629), chosen over refusing
    trailing bytes in every packet, refusing them after the handshake response only, and
    recording the tolerance here with no log, with each option's consequences shown. Logging
    every occurrence is a technical call, made on the reasons above.
- **Binary frame payload is never held whole.** `FrameDecoder` hands payload on as it arrives, so
  a frame's 63-bit length needs no cap. What is capped: a control frame at 125 bytes (RFC 6455
  5.5), the upgrade response header at 16 KiB, and replies not yet written at 256 KiB.
- **`capsFlags` is one constant, `ADVERTISED_CAPS`, and it is 0x4,
  `HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN`.** That one is handled: a consent message goes to
  the host (next point). Each of the other five asks the client for something it does not do: a
  statement of health, a service message put in front of a user, reauthentication, UDP, and for
  `HTTP_CAPABILITY_IDLE_TIMEOUT` a timer. That timer is the client's: `[MS-TSGU]` 3.5.2.1 has
  the client end the protocol when it expires, and a product note says idle timeout "is
  configured on the RDG server and is enforced on the RDG client". Nothing here runs one. A
  gateway that negotiates it anyway has its `idleTimeout` handed to the host in
  `GatewayChannel`, whose timer it then is.
  `mstsc.exe` sends 0x3f, FreeRDP 0x0D (`rdg.c`, `rdg_send_tunnel_request`) and IronRDP 0x14,
  consent and reauth, under the comment "No observed server works without this capability"
  (`ironrdp-mstsgu`, `src/lib.rs`). **It was 0 until a Windows gateway refused it** (see
  `## Reference behaviour`): `[MS-TSGU]` 2.2.6 gives `E_PROXY_CAPABILITYMISMATCH` to a client
  without consent signing when the gateway is configured to allow only clients that have it.
  **A negotiated `capsFlags` bit outside `ADVERTISED_CAPS` is logged, not refused.** The
  tunnel response stores the value as received in `negotiated_caps`; when it holds a bit this
  client did not advertise, one debug record under the `rdg_tunnel` target names those bits
  (`unadvertised`) and the value (`negotiated`). 2.2.10.21 calls the field "the capabilities
  negotiated by the RDG server" and has no MUST that it be a subset of the client's, so the
  record marks a mismatch with what this client advertised, not a spec violation (unlike the
  handshake `serverVersion` record). 3.7.5.2 step 4 has the client "initialize the ADM element
  Negotiated Capabilities with capsFlags" as received, which is why the value is stored
  unfiltered. The nearest case in ADR-0009 §2's list is "a capability
  the server under- or over-advertises"; that list is scoped to rendering-feature
  self-inconsistency (its 2026-08-25 amendment), so this applies it by analogy, and §3(b)
  asks for the record. FreeRDP logs every negotiated value at debug
  with no subset check (`rdg.c`, `rdg_process_tunnel_response_optional`); `ironrdp-mstsgu`
  decodes the field and reads none (`proto.rs`). Logging only the bits outside
  `ADVERTISED_CAPS` is **the maintainer's judgement** (#634), confirmed again once the
  2026-08-25 scoping of §2 was put to them, and chosen over logging every
  negotiated value as FreeRDP does and over no record with this note alone. It does not cover
  the `idleTimeout` filter, which drops an `idleTimeout` without the capability negotiated and
  stays silent.
- **A consent message stops the sequence until the host answers.** `[MS-TSGU]` 3.7.5.2 step 5
  has the client "pass the consentMsg to the higher layer if it is present" in the tunnel
  response (`fieldsPresent` 0x10, 2.2.10.21). The core emits
  `GatewayAction::ConsentRequested` and sends nothing; `accept_consent` sends the tunnel
  authorization and `decline_consent` fails the tunnel create with `ConsentDeclined`. The HTTP
  transport has no field that tells the gateway the answer: `HTTP_TUNNEL_AUTH_PACKET`
  (2.2.10.14) carries the client name and a statement of health, so accepting is carrying on
  and declining is ending the protocol. No Gateway Channel exists at that point, so 3.7.5.4
  leaves only "closes the HTTP connection": the adapter sends the WebSocket close frame and
  shuts the connection, and no MS-TSGU packet.
  - `open_gateway` takes the answer as `on_consent`, an async callback with no default. It is a
    required argument so that no value of `GatewayOptions` accepts by omission. FreeRDP's
    callback is optional and its absence accepts (`rdg.c`, `IFCALLRESULT(TRUE, ...
    PresentGatewayMessage ...)`); the `ironrdp-mstsgu` source read for this change accepts
    when no callback is given (`evaluate_consent_message`, `ConsentFallback::Accept`).
  - The answer is not under the stage timeout, since a person may be reading the message. The
    gateway is not read while it is awaited, so a keep-alive or a WebSocket ping it sends then
    goes unanswered until the answer. A gateway that gives up meanwhile shows as a failure of
    `gateway-tunnel-auth` after an accept. How long a Windows gateway waits is not measured.
  - The host is asked once the requests before it are written and only while the gateway is
    still there. A gateway may answer ahead of the requests (the responses can share a read
    with the 101), and asking first would send the tunnel create, cookie included, after a
    decline. A gateway that closes in the read that carried the message fails
    `gateway-tunnel-create` as closed, unasked.
  - The message is what the gateway sent, unchecked: control characters reach the host, whose
    display it is.
  - The message is the text up to its first NUL. One that is present and empty is still
    handed over: the field's presence is what the spec keys on. IronRDP treats an empty one as
    absent. What a Windows gateway with no message configured sends is not measured.
  - A tunnel response with a non-zero `statusCode` asks for no consent, whatever its fields.
  - The stage stays `gateway-tunnel-create` while the answer is awaited; there is no ninth
    stage.
- **A non-zero `errorCode` or `statusCode` ends the sequence**, as `[MS-TSGU]` 3.7.5.2 says.
  FreeRDP ends the handshake, the tunnel create and the channel create on `FAILED(hr)` only, so
  it carries on past a positive non-zero code there; its tunnel authorization admits `S_OK` and
  `E_PROXY_QUARANTINE_ACCESSDENIED`. No server has been seen to send a positive code.
- **The handshake response has to answer version 1.0 and offer PAA, or the cookie is not
  sent.** `[MS-TSGU]` 3.7.3: "The RDG client MUST match the version and capabilities of the RDG
  server. If no match can be made, the RDG client SHOULD stop further progress on the protocol
  connection." The client sends 1.0 and asks for PAA alone, so a response with another
  `verMajor`.`verMinor` fails `gateway-handshake` with `VersionMismatch`, and one whose
  `ExtendedAuth` lacks `HTTP_EXTENDED_AUTH_PAA` fails it with `PaaNotOffered`. Both fail before
  the tunnel create, the request that carries the cookie, is written.
  - What licenses the refusal is ADR-0009 §3(a), as its 2026-08-25 amendment reads it for a
    field whose legal values the spec fixes; §1 and §2 are not a partition. It is not a defence
    against a hostile gateway: the gateway that would receive the cookie is the one that writes
    `ExtendedAuth`, and it passes by setting 0x2. It keeps the cookie from a gateway that does
    not offer PAA.
  - PAA is a bit test, because the response carries what the gateway offers. 2.2.10.11 words
    `ExtendedAuth` as "the extended authentication requested by the RDG client", which reads as
    an echo; 3.3.5.3.2 has the gateway include `HTTP_EXTENDED_AUTH_SSPI_NTLM` when it supports
    NTLM, and the Windows Server 2019 gateway of #613 answered 0x7 (smart card, PAA, NTLM) to a
    request of 0x2. The measurement decides it, and that gateway passes. 3.3.5.3.2 also has the
    same rule for NTLM: a client that negotiated it and gets a response without the bit "MUST
    close the connection".
  - The version and the flag checked are the ones `start` sends (`VERSION`, `EXTENDED_AUTH`).
  - A refusal is checked first, so a gateway that refuses with the version zeroed is reported by
    its code.
  - `serverVersion` is not checked. 2.2.10.11: "This field is not used and MUST be set to
    zero." Nothing acts on it, so a non-zero value changes nothing this client does. Accepting
    one is a divergence, so it is logged under the `rdg_handshake` target with the value seen
    (ADR-0009 §3(b), per-area target as its amendment reads it). The Windows Server 2019
    gateway of #613 sent 0.
  - Prior art: FreeRDP logs both fields and acts on neither (`rdg.c`,
    `rdg_process_handshake_response`); it takes the NTLM path on what it asked for.
    `ironrdp-mstsgu` (`lib.rs`, `handshake`) fails on a version other than 1.0 and on a
    non-zero `serverVersion`, and requires the NTLM bit when it asked for NTLM. The
    maintainer's IronRDP fork also fails when it asked for PAA and the bit is missing (commit
    `12b9822f`).
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
- **Why the gateway closed is the session's terminal value** (#622). A non-zero close status
  fails every later read with `ConnectionAborted` and every later write with `BrokenPipe`,
  each carrying a `GatewayClosed`. The write can come first: data that arrived with the close is
  read before the close is reported, and the runner may answer it, as it answers a `drdynvc`
  Capabilities Request. The target's TLS stream hands either error on unchanged (`tokio-rustls`
  0.26.6, `common/mod.rs`, `read_io` and `poll_write`; on a read,
  `a_gateway_close_reaches_the_runner_through_the_targets_tls`; on a write,
  `a_reply_written_after_the_gateway_close_ends_the_session_through_the_targets_tls`), and the session runners
  recover it with `GatewayClosed::from_io_error` into `DisconnectReason::GatewayClosed`, so
  they stay generic over the stream. A server attribution that arrived before the close
  outranks it on a read and on a write, the higher layer's word over the lower's
  ([Session loop & dispatch](session-loop-dispatch.md)). A close with status 0 is an orderly end
  and stays an unexpected disconnect. `class()` puts every status in `DisconnectClass::Unknown`:
  mapping HRESULTs to host reactions was left out of #622 at its confirm stop, and what a
  Windows gateway sends when it ends a session is not measured. `GatewayStream::close_status`
  still returns the code.
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
  an action prints the length of the bytes or the consent text it carries. No log line and no
  error carries a packet's bytes. The cookie's memory is not zeroed when it is dropped.
- **A failure names the stage the machine was in when it failed.** One read can carry several
  responses, so `open_over` asks the machine after each step, and announces every stage a step
  passed through before it reports the outcome.

## Code

- `justrdp-pdu/src/tsgu.rs` — `Packet`, `decode_with_unread`, `PacketHeader`, `PaaCookie`,
  `UnicodeString`, `TunnelCreate`, `TunnelResponse`, `SohRequest`, `TunnelAuth`, `TunnelAuthResponse`,
  `ChannelCreate`, `ChannelResponse`, `EncodeError`
- `justrdp/src/gateway.rs` — `GatewayStateMachine`, `GatewayConfig`, `GatewayAction`,
  `GatewayChannel`, `GatewayError`, `GatewayErrorKind`, `ADVERTISED_CAPS`, `MAX_PACKET_LEN`,
  `MAX_DATA_LEN`, `accept_consent`, `decline_consent`
- `justrdp-tokio/src/gateway.rs` — `open_gateway`, `open_over`, `act`, `host_header`,
  `announce_up_to`, `GatewayStream`, `close_status`, `GatewayClosed`, `GatewayOptions`,
  `GatewayFailure`, `GatewayFailureKind`, `MAX_PENDING_OUT`, `GATEWAY_CAPTURE_FILE`
- `justrdp-tokio/src/websocket.rs` — `upgrade_request`, `parse_upgrade_response`, `accept_for`,
  `base64`, `encode_frame`, `FrameDecoder`, `FrameError`, `UpgradeError`,
  `MAX_UPGRADE_RESPONSE_LEN`
- `justrdp-tokio/src/lib.rs` — `connect_over_gateway`, `ConnectWire`, `SessionStream`,
  `ended_by`, `settle_session_end`, `relay_gateway`, `relay_gateway_closing`,
  `relay_gateway_closing_with_next_data`, `gated_session_server`,
  `a_real_rd_gateway_reaches_the_target_server`
- `fuzz/fuzz_targets/tsgu.rs`, `fuzz/fuzz_targets/gateway.rs`, `fuzz/fuzz_targets/websocket.rs`
- Stage strings: `gateway-tcp-connect`, `gateway-tls-handshake`, `gateway-websocket-upgrade`,
  `gateway-handshake`, `gateway-tunnel-create`, `gateway-tunnel-auth`, `gateway-channel-create`,
  `gateway-channel-open`
- Spec sections cited inline: `[MS-TSGU]` 2.2.5.3, 2.2.6, 2.2.10, 3.3.5.1, 3.3.5.3.2, 3.7.3,
  3.7.5.2 to 3.7.5.4;
  RFC 6455 1.3, 4.1, 5.1 to 5.5

## Reference behaviour

**What `mstsc.exe` sends** (#613, captured with a stand-in gateway, `gatewaycredentialssource:i:5`):
`RDG_OUT_DATA /remoteDesktopGateway/` with a WebSocket upgrade, a `Rdg-Auth-Scheme: PAA` header
and no `Authorization` header; handshake `extendedAuth` 0x2; tunnel create with `capsFlags` 0x3f
and `fieldsPresent` 0x1; the cookie as UTF-16LE with a terminating NUL. No capture bytes are in
the repo: the tests' expected requests are written out from these values and the spec layouts.
This client's requests are those bytes except `capsFlags`.

**A Windows gateway refused `capsFlags` 0** (#613, 2026-11-16, the RD Gateway role on Windows
Server 2019 with Microsoft's sample PAA plugins). The client reached `gateway-tcp-connect`,
`gateway-tls-handshake`, `gateway-websocket-upgrade` and `gateway-handshake`, and failed in
`gateway-tunnel-create` with `Refused { code: 0x800759E9 }`, `E_PROXY_CAPABILITYMISMATCH`. The
gateway sent 36 bytes:

```text
02 00 00 00 12 00 00 00 | 00 00 00 00  01 00  00 00  07 00
05 00 00 00 12 00 00 00 | 00 00  e9 59 07 80  00 00  00 00
```

A handshake response (`errorCode` 0, version 1.0, `serverVersion` 0, `ExtendedAuth` 0x7: smart
card, PAA and NTLM) and a tunnel response (`statusCode` 0x800759E9, `fieldsPresent` 0). Whether
the gateway checked the cookie before it refused is not known. The bytes are replayed by
`the_refusal_a_windows_gateway_sent_names_the_tunnel_create_and_its_code`.

**The same gateway opened a tunnel for `capsFlags` 0x4 and the connect reached session-active**
(#613, 2026-11-16, the gateway relaying to its own listener). Every gateway stage passed, then
`tcp-connect` to `session-active` ran inside the tunnel: X.224, the target's TLS, NLA (NTLM) and
activation, desktop 1280×800. The gateway's MS-TSGU packets before the first data packet:

- tunnel response: `statusCode` 0, `fieldsPresent` 0x3 (tunnel id 2, `capsFlags` 0x4). No
  consent message and no `SOH_REQ`;
- tunnel authorize response: `errorCode` 0, `fieldsPresent` 0x3, `redirFlags` 0x9 (drive and
  clipboard redirection disabled), `idleTimeout` 0;
- channel response: `errorCode` 0, `fieldsPresent` 0x7: channel id 1, UDP port 3391 and a
  1,451-byte `authnCookie`, read in that order.

The refusal of 0 and this run used the role's messaging settings as installed: the lab setup
changed none of them. The run reads its gateway, target and cookie from the environment, so
none is committed:

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

The test accepts a consent message and prints it. The capture is server-to-client, after the
WebSocket frames are read, so the cookie is not in it. A consent message would be, a channel
response's `authnCookie` would be, and so are the target's bytes (TLS records). Read it before
committing it.

**What the run settled**: a Windows gateway opens a tunnel for `capsFlags` 0x4 alone; with no
logon message configured its tunnel response carries no consent field at all, not an empty one;
it refuses 0 with the messaging settings as installed; and it accepts the upgrade request
without FreeRDP's `User-Agent` and `Content-Length`.

**A consent message, accepted** (#613, 2026-11-16, the same gateway with a logon message set in
its Messaging properties to a file holding `justrdp consent test`). The tunnel response came
with `fieldsPresent` 0x13 (tunnel id, caps, consent message), and the message as 42 bytes:
UTF-16LE with a terminating NUL, the length counting the NUL. The test accepted it and the
connect reached session-active.

**Still open after it**:

- what the gateway sends when the target ends the connection: a close packet and its status, or
  the end of the stream. The run ended at session-active;
- **the nonce length of the tunnel response.** `[MS-TSGU]` 2.2.10.21 says 16 bytes (a GUID) and
  `tsgu` follows it; FreeRDP's `rdg.c` skips 20 and IronRDP's `ironrdp-mstsgu` reads a `u16`,
  neither with a reason. It is present only under `fieldsPresent` 0x4
  (`HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ`), which a gateway should not set for a client that did
  not advertise `HTTP_CAPABILITY_TYPE_QUAR_SOH`. If the capture shows that bit, keep the bytes:
  they settle it. The run's tunnel response did not set it.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — four parsers
  read the gateway's bytes: `tsgu::Packet::decode`, `GatewayStateMachine::receive`,
  `FrameDecoder::feed` and `parse_upgrade_response`. Each has a property and a fuzz target.
  **`tsgu`'s undirected property reaches only the header** (#612): random bytes rarely form a
  `packetLength` that covers a body, so the bodies are reached by its corrupted-packet property,
  which overwrites and truncates valid packets. The properties here are built the same way, from
  well-formed packets and frames with fields overwritten.
- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md) —
  `ADVERTISED_CAPS`, which is why it is consent signing alone. It was 0x2 while #613 was
  written, on the reading that the gateway enforces the idle timer; the timer in 3.3.6.1 is the
  server's session timeout, and the idle one is the client's.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — the tunnel response's `nonce` and `serverCert`, the tunnel authorization's
  `SoHResponse`, and the channel response's `udpPort` and `authnCookie` are decoded and not
  read. Each belongs to a capability that is not advertised or a transport that is not built.
  The tunnel response's `serverVersion` is decoded and not read for another reason: 2.2.10.20
  calls it the version of the RDGHTTP protocol and fixes no value, so no value it carries is a
  divergence, and none is logged. `redirFlags`, `idleTimeout`, the ids and the negotiated
  capabilities reach the host in `GatewayChannel`, and `consentMsg` in `on_consent`.
  The handshake response's version and `ExtendedAuth` are enforced, and its `serverVersion` is
  recorded on `HandshakeResponse::server_version` as unchecked and logged when non-zero; all
  three are under `## Design model`.

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
  service messages, UDP, and HTTP proxies. A service message or a reauth message
  that arrives is skipped; a gateway that then closes for a failed reauthentication says so only
  in its close status.
- **A write that fails on the gateway's close ends the session before the rest of the data
  that came with it is read.** A runner reads at most 16 KiB at a time. When that data is
  longer and the answer to its first part fails, a server attribution further on is never fed,
  and the end is `GatewayClosed`. Traced, not tested.
- **No test reaches session-active through a tunnel.** The loopback connect ends after CredSSP,
  where the mock target hangs up, so `ConnectWire`'s two conversions to a `SessionStream` run
  only in the real-gateway test. A session runner over `SessionStream::GatewayTls` is tested
  (`a_session_runs_inside_a_gateway_tunnel`).
- **Standard RDP Security through a tunnel is untested.** `SessionStream::Gateway` exists
  because `connect_inner` is generic; the server's refusal of that protection is recognised by
  a reset or an end of the socket, which a tunnel may report differently.
- **`RDG-User-Id` is not sent.** `[MS-TSGU]` 3.3.5.1 says the request SHOULD carry it; it is
  the user's name, for the gateway's event log.
- **Only the real-gateway test runs a whole connect after an accepted consent message.** The
  stand-in gateway of the adapter's unit tests sends one and opens the tunnel; `relay_gateway`,
  which the loopback connect runs through, sends none.
- **`RDG-Correlation-Id` is not sent.** `[MS-TSGU]` 2.2.3.2.2 makes it optional, and equal to
  the Connection Request's `RDP_NEG_CORRELATION_INFO` when present. `open_gateway` runs before
  the connect config exists, so it does not know that id
  ([X.224 negotiation](x224-negotiation.md)).
- **The client's keep-alive timer is not run**, so a gateway that expects the client to
  originate keep-alives would see none.
- **`JUSTRDP_GATEWAY_CAPTURE_FILE` has no test of its own**: it calls the same `append_capture`
  the connect and session captures use.

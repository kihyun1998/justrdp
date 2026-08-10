# Wire framing primitives

## What it is

The bottom of the stack: deciding where one message ends and the next begins, and
the two ASN.1-ish encodings the connect sequence needs. TPKT headers, X.224 data
TPDUs, the fast-path header (which is distinguished from a TPKT header by its first
byte), and the BER/PER readers used by MCS and GCC. Everything else in the repo is
built on the assumption that this layer hands it exactly one well-delimited message.

## Governing decisions

**None.** No ADR is about framing.

Adjacent but not governing: [ADR-0002](../../adr/0002-dependency-boundary.md)
decides that no external ASN.1 crate is pulled in — which is *why* BER and PER are
hand-rolled here, but it decides the dependency, not the encoders.

## Design model

- **Framing is length-first and must be safe before it is correct.** `frame_len`
  answers "do I have a whole message yet?" from a partial buffer; every caller feeds
  it attacker-controlled bytes, so it returns a need-more-bytes answer rather than
  panicking or over-reading.
- **Fast-path and slow-path are distinguished by the first byte** (`is_fastpath`).
  A misread here silently reinterprets a graphics stream as a TPKT header.
- **`ReadCursor` is the single read primitive**, and it is read-side only for now —
  there is no `WriteCursor` and no object-safe `Encode`/`Decode` trait pair; encoders
  build `Vec<u8>` directly.
- **BER and PER are implemented only as far as the connect sequence needs.** They
  are not general codecs, and nothing says so at their module boundary.

## Code

- `justrdp-pdu/src/tpkt.rs` — `encode`, `decode`, `frame_len`
- `justrdp-pdu/src/x224.rs` — `encode_data`, `decode_data`,
  `encode_connection_request`, `decode_connection_confirm`
- `justrdp-pdu/src/fastpath.rs` — `is_fastpath`, `frame_len`, `decode_updates`,
  `encode_pdu`
- `justrdp-pdu/src/cursor.rs` — `ReadCursor`
- `justrdp-pdu/src/ber.rs` — `read_length`, `read_integer`, `read_octet_string`,
  `read_sequence_tag`, `read_application_tag`, `read_bool`, `read_enumerated`
- `justrdp-pdu/src/per.rs` — `read_length`, `read_choice`, `read_enum`,
  `read_octet_string`, `read_numeric_string`, `read_object_id`, `read_u16`,
  `read_padding`
- `justrdp-pdu/src/error.rs` — `DecodeError`

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  this territory is the invariant's widest surface: every byte in the process passes
  through it.

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — its read loop is built
  on `frame_len` / `is_fastpath`.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the only consumer of BER and
  PER.
- [X.224 negotiation](x224-negotiation.md) — the connection request/confirm framing.
- [Virtual channels](virtual-channels.md) — chunk lengths sit inside these frames.
- [Adapter drive loop](adapter-drive-loop.md) — decides how much to read before
  handing bytes over, so a framing change is a read-loop change.

## Known holes / open

- **No `WriteCursor` / `Encode` trait pair** — stated in the module doc as "for
  now"; encoders duplicate bounds logic instead.
- BER/PER coverage is need-driven and undocumented: nothing states which subset is
  supported, so a new PDU can silently need a missing primitive.
- Fast-path *input* encoding and fast-path *update* decoding live in the same module
  with no separation of the client-sent from the server-sent halves.

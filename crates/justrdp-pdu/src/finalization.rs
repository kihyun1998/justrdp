//! Connection finalization PDUs (MS-RDPBCGR 2.2.1.14–2.2.1.22): Synchronize, Control, Font
//! List / Font Map — the `activation` stage. The client pipelines Synchronize →
//! Control(Cooperate) → Control(Request Control) → Font List in one batch; the server's Font
//! Map is the session-active gate. These are Share **Data** PDU bodies — frame them with
//! [`crate::share::encode_share_data`].

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `messageType` of the Synchronize PDU — always 1 (SYNCMSGTYPE_SYNC).
const SYNC_MSG_TYPE: u16 = 1;

/// `action`: Request Control.
pub const CTRLACTION_REQUEST_CONTROL: u16 = 0x0001;
/// `action`: Granted Control.
pub const CTRLACTION_GRANTED_CONTROL: u16 = 0x0002;
/// `action`: Detach.
pub const CTRLACTION_DETACH: u16 = 0x0003;
/// `action`: Cooperate.
pub const CTRLACTION_COOPERATE: u16 = 0x0004;

/// A Synchronize PDU (TS_SYNCHRONIZE_PDU). `target_user` echoes the server's user channel ID
/// in the client copy; the server's copy targets the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Synchronize {
    /// `targetUser` — an MCS user channel ID.
    pub target_user: u16,
}

impl Synchronize {
    /// Encode the Share Data body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&SYNC_MSG_TYPE.to_le_bytes());
        out.extend_from_slice(&self.target_user.to_le_bytes());
        out
    }

    /// Decode the Share Data body.
    ///
    /// `messageType` is checked, `targetUser` is not. That is the way round `[MS-RDPBCGR]`
    /// puts it and the reverse of what this function used to claim (#252): 3.2.5.3.19 says
    /// *"the contents of the **targetUser** field MUST be ignored"* and says nothing of
    /// `messageType`, whose only legal value 2.2.1.14.1 fixes at `SYNCMSGTYPE_SYNC`. Both
    /// references reject a wrong one and justrdp was the only client that did not.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let message_type = cur.read_u16_le()?;
        if message_type != SYNC_MSG_TYPE {
            return Err(DecodeError::InvalidField {
                field: "Synchronize.messageType",
                reason: "not SYNCMSGTYPE_SYNC",
            });
        }
        let target_user = cur.read_u16_le()?;
        Ok(Self { target_user })
    }
}

/// A Control PDU (TS_CONTROL_PDU) — used for Cooperate, Request Control, and Granted Control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    /// `action` (one of the `CTRLACTION_*` constants).
    pub action: u16,
    /// `grantId` — the granted user's channel ID in Granted Control; 0 in client copies.
    pub grant_id: u16,
    /// `controlId` — the granting user's ID in Granted Control; 0 in client copies.
    pub control_id: u32,
}

impl Control {
    /// A client-side Control PDU: only the action is meaningful.
    pub fn new(action: u16) -> Self {
        Self {
            action,
            grant_id: 0,
            control_id: 0,
        }
    }

    /// Encode the Share Data body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.action.to_le_bytes());
        out.extend_from_slice(&self.grant_id.to_le_bytes());
        out.extend_from_slice(&self.control_id.to_le_bytes());
        out
    }

    /// Check the `action` a **server** sent during finalization.
    ///
    /// Direction-specific, which is why it is not folded into [`Control::decode`]: the client's
    /// own copies legitimately carry `CTRLACTION_REQUEST_CONTROL`, while `[MS-RDPBCGR]` 2.2.1.20
    /// and 2.2.1.21 fix the server's at Cooperate and Granted Control respectively. Kept here
    /// rather than at each call site so the connect path and the reactivation path cannot answer
    /// the same question two ways (#252).
    pub fn check_server_action(&self) -> Result<(), DecodeError> {
        match self.action {
            CTRLACTION_COOPERATE | CTRLACTION_GRANTED_CONTROL => Ok(()),
            _ => Err(DecodeError::InvalidField {
                field: "Control.action",
                reason: "not a server finalization action (Cooperate or Granted Control)",
            }),
        }
    }

    /// Decode the Share Data body.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let action = cur.read_u16_le()?;
        let grant_id = cur.read_u16_le()?;
        let control_id = cur.read_u32_le()?;
        Ok(Self {
            action,
            grant_id,
            control_id,
        })
    }
}

/// `listFlags` / `mapFlags`: this PDU is the first in the sequence.
const FONTLIST_FIRST: u16 = 0x0001;
/// `listFlags` / `mapFlags`: this PDU is the last in the sequence.
const FONTLIST_LAST: u16 = 0x0002;

/// Encode a Font List PDU body (TS_FONT_LIST_PDU). All fields carry the fixed values
/// MS-RDPBCGR mandates for the (only) single-PDU form: no actual font entries, FIRST|LAST,
/// entry size 0x0032.
pub fn encode_font_list() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&0u16.to_le_bytes()); // numberFonts (SHOULD 0)
    out.extend_from_slice(&0u16.to_le_bytes()); // totalNumFonts (SHOULD 0)
    out.extend_from_slice(&(FONTLIST_FIRST | FONTLIST_LAST).to_le_bytes());
    out.extend_from_slice(&0x0032u16.to_le_bytes()); // entrySize (SHOULD 0x0032)
    out
}

/// `bBitMask`: the first Persistent Key List PDU of a sequence.
pub const PERSIST_PDU_FIRST: u8 = 0x01;
/// `bBitMask`: the last Persistent Key List PDU of a sequence.
pub const PERSIST_PDU_LAST: u8 = 0x02;
/// The most keys one Persistent Key List PDU carries (`[MS-RDPBCGR]` 2.2.1.17.1: SHOULD).
pub const PERSISTENT_KEYS_PER_PDU: usize = 169;

/// Encode the Persistent Key List PDU bodies (TS_BITMAPCACHE_PERSISTENT_LIST_PDU) for `keys`,
/// one slice per Revision 2 cache, at most five, each key in the order of the entry it fills.
/// The keys run in cache order across the sequence, [`PERSISTENT_KEYS_PER_PDU`] a PDU; no key at
/// all is one PDU of none.
pub fn encode_persistent_key_lists(keys: &[&[u64]]) -> Vec<Vec<u8>> {
    let mut totals = [0u16; 5];
    for (total, cache) in totals.iter_mut().zip(keys) {
        *total = u16::try_from(cache.len()).unwrap_or(u16::MAX);
    }
    let all: Vec<(usize, u64)> = keys
        .iter()
        .take(5)
        .enumerate()
        .flat_map(|(cache, list)| list.iter().map(move |&key| (cache, key)))
        .collect();
    let chunks: Vec<&[(usize, u64)]> = if all.is_empty() {
        vec![&[]]
    } else {
        all.chunks(PERSISTENT_KEYS_PER_PDU).collect()
    };
    let last = chunks.len() - 1;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut entries = [0u16; 5];
            for &(cache, _) in *chunk {
                entries[cache] += 1;
            }
            let mut out = Vec::with_capacity(24 + 8 * chunk.len());
            for count in entries.iter().chain(&totals) {
                out.extend_from_slice(&count.to_le_bytes());
            }
            let first = if i == 0 { PERSIST_PDU_FIRST } else { 0 };
            let end = if i == last { PERSIST_PDU_LAST } else { 0 };
            out.extend_from_slice(&[first | end, 0, 0, 0]); // bBitMask, Pad2, Pad3
            for &(_, key) in *chunk {
                out.extend_from_slice(&(key as u32).to_le_bytes());
                out.extend_from_slice(&((key >> 32) as u32).to_le_bytes());
            }
            out
        })
        .collect()
}

/// A Font Map PDU (TS_FONT_MAP_PDU) — the server's last finalization message, and on its own the
/// session-active gate (#252 decided that deliberately rather than inheriting it). We keep only
/// `mapFlags` and **that is our choice, not a spec instruction**: `[MS-RDPBCGR]` 2.2.1.22.1 marks
/// all four body fields `SHOULD` and names none of them ignorable — IronRDP rejects unknown
/// `SequenceFlags` bits on exactly that reading. This doc said "ignored per spec" until #252,
/// which is the same citation `Synchronize::decode` carried thirty lines up and did not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FontMap {
    /// `mapFlags` — FIRST|LAST (0x0003) in practice.
    pub map_flags: u16,
}

impl FontMap {
    /// Decode the Share Data body. Windows sends 8 bytes; all but `mapFlags` are ignored.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u16_le()?; // numberEntries (ignored)
        cur.read_u16_le()?; // totalNumEntries (ignored)
        let map_flags = cur.read_u16_le()?;
        cur.read_u16_le()?; // entrySize (ignored)
        Ok(Self { map_flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ReadCursor;
    use proptest::prelude::*;

    /// `[MS-RDPBCGR]` 4.1.17's Persistent Key List PDU, decrypted, from the Share Data Header on:
    /// 25 keys for cache 2 in one PDU.
    #[test]
    fn the_spec_example_persistent_key_list_encodes_byte_for_byte() {
        let expected: Vec<u8> = [
            "000000001900000000000000000019000000000003000000a31e51164829227861f7899ccda966a8444eb7bdb46d9ef6",
            "399164afbcc370029faafafd6eba58dc7bafde06563ac2ce68ba54b6bf9ebcd6d122c09863e941fe386c50350edbb3f5",
            "45cc182d3044fc88e5c35d2363f6cf530aa801b61051a52870816c59192900c9e2b5e7a746044e1b728d4add81bb1416",
            "536a4e3c487266c96c774b4a32482cc6025456f281c985562c0a3d54869d2b97630f0a36f863793ec970414beca87c7b",
            "7928b6b4a64324decb9cffa2293c025664df80b00d6ee71a83c75431aa8a90b3",
        ]
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
        let keys: Vec<u64> = expected[24..]
            .chunks(8)
            .map(|key| u64::from_le_bytes(key.try_into().unwrap()))
            .collect();
        assert_eq!(keys.len(), 25);
        let pdus = encode_persistent_key_lists(&[&[], &[], &keys]);
        assert_eq!(pdus, [expected]);
    }

    /// More than 169 keys go in several PDUs: first and last marked, the totals the same in
    /// each, and the keys in cache order across the sequence.
    #[test]
    fn a_long_key_list_is_split_at_169_keys() {
        let cache0: Vec<u64> = (0..100).collect();
        let cache2: Vec<u64> = (1000..1250).collect();
        let pdus = encode_persistent_key_lists(&[&cache0, &[], &cache2]);
        assert_eq!(pdus.len(), 3, "350 keys");
        let field = |pdu: &[u8], at: usize| u16::from_le_bytes([pdu[at], pdu[at + 1]]);
        let mut keys = Vec::new();
        for (i, pdu) in pdus.iter().enumerate() {
            let entries: Vec<u16> = (0..5).map(|c| field(pdu, 2 * c)).collect();
            let totals: Vec<u16> = (0..5).map(|c| field(pdu, 10 + 2 * c)).collect();
            assert_eq!(totals, [100, 0, 250, 0, 0]);
            let flags = pdu[20];
            assert_eq!(flags & PERSIST_PDU_FIRST != 0, i == 0);
            assert_eq!(flags & PERSIST_PDU_LAST != 0, i == 2);
            let count: usize = entries.iter().map(|&n| usize::from(n)).sum();
            assert!(count <= 169);
            assert_eq!(pdu.len(), 24 + 8 * count);
            keys.extend(
                pdu[24..]
                    .chunks(8)
                    .map(|key| u64::from_le_bytes(key.try_into().unwrap())),
            );
        }
        assert_eq!(keys, [cache0, cache2].concat());
        assert_eq!(field(&pdus[0], 0), 100);
        assert_eq!(field(&pdus[0], 4), 69);
    }

    /// No key at all is still one PDU, first and last.
    #[test]
    fn an_empty_key_list_is_one_pdu() {
        let pdus = encode_persistent_key_lists(&[]);
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0], {
            let mut pdu = vec![0; 24];
            pdu[20] = PERSIST_PDU_FIRST | PERSIST_PDU_LAST;
            pdu
        });
    }

    // ADR-0008 / issue #237 -- the no-panic robustness properties for the connect sequence's last
    // three server parses. All three are `pub fn`s driven straight off server bytes
    // (`ConnectStateMachine::finalization_step`, and `SessionStateMachine::on_data_pdu` for
    // `FontMap` on reactivation) and none carried either artifact.
    //
    // What made this module invisible is worth keeping, because it is *not* the failure #230
    // closed. There the roster matched by module name and a name lied -- `pointer` and `license`
    // both appeared covered because a file of that name existed on each side. `finalization`
    // appeared nowhere at all: not in the fuzz roster, not in the uncovered enumeration, not in
    // this territory's known holes. The reason is one edge in the map:
    // `docs/map/territory/capability-exchange-activation.md`, which owns this module, never
    // claimed [untrusted decode never panics], so the invariant's own list of territories could
    // not point anyone here. `check_map.py`'s reciprocity gate cannot see that -- it verifies
    // that edges which *exist* run both ways.
    //
    // The generators were plain `vec(any::<u8>(), 0..=512)`, and that was measured rather than
    // assumed. #230 found four properties that could not reach the arithmetic they were named
    // after, every one of them behind an exact-match gate (a version byte, a flags mask, ASN.1
    // tags, a `messageType` dispatch plus a dimension cap). `Control` and `FontMap` still have
    // **no gate at all**: every read is unconditional and fixed-width, so the only thing needed
    // to drive a bounds check is a short buffer, which a `0..=512` length hits in ~1.6% of cases.
    // Mutation-checked at 5 runs each, rebuild asserted: an unchecked read in either turns its
    // own property red every time, and that holds for **every** read rather than the first one
    // -- all seven were mutated, because #230's second round came from stopping at the first red.
    //
    // **`Synchronize` stopped being one of them in #252, and this repo wrote the rule it broke.**
    // The `messageType` guard added there is the fifth instance of the list above -- and the list
    // literally names "a `messageType` dispatch" -- so undirected bytes now clear `01 00` once in
    // 65536 and the `targetUser` read behind it went from unconditional to ~0.03 expected hits
    // per 2048-case run. An out-of-bounds read injected there would have shipped green.
    // [untrusted decode never panics] prescribes the repair and it is applied below: **weight the
    // generator, do not substitute it** -- an `any` arm keeps the gate's own reject branch driven
    // (that branch is a guard too), a shape arm reaches past it, and both keep the *lengths*
    // hostile so the truncation behind the shape stays reachable.
    //
    // Seen, not asserted, because the note's corollary is that a property is done when a mutation
    // of the read it names has been *watched* to redden it. Replacing `targetUser`'s checked read
    // with one that panics on a short buffer: **RED with the weighted generator, GREEN with the
    // plain one.** The green run is the interesting half -- it is what the first version of #252
    // would have shipped, and it is why this arm exists rather than a comment saying it should.
    //
    // "No gate" was true of all three parsers and is still false of the *path*, which is why these
    // drive the `pub fn` rather than `justrdp::connect::finalization_step`. Through the live
    // path a body must first satisfy `ShareControlHeader.pduType & 0x000F == 0x7` and then an
    // exact `ShareDataHeader.pduType2`, so undirected bytes reach `FontMap::decode`'s first read
    // with P ~ 2.4e-4 and its *fourth* with P ~ 9.5e-7 -- about two thousandths of a hit across a
    // whole 2048-case run. A live-path property would have been green over the `entrySize`
    // mutation. ADR-0008 targets the entry point a server can reach, and the entry point is what
    // this crate publishes.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn synchronize_decode_never_panics_on_arbitrary_input(
            body in prop_oneof![
                // 70%: undirected. Almost all of these are rejected at the gate, which is what
                // keeps the guard's own reject branch driven rather than assumed.
                7 => proptest::collection::vec(any::<u8>(), 0..=512),
                // 30%: past the gate, with a hostile tail. The short tails are the point --
                // a one-byte tail is a `targetUser` read with only half its bytes present,
                // the shallow truncation the shape would otherwise hide.
                3 => proptest::collection::vec(any::<u8>(), 0..=510).prop_map(|tail| {
                    let mut body = vec![0x01, 0x00];
                    body.extend_from_slice(&tail);
                    body
                }),
            ],
        ) {
            let mut cur = ReadCursor::new(&body, "proptest synchronize");
            let _ = Synchronize::decode(&mut cur);
        }

        #[test]
        fn control_decode_never_panics_on_arbitrary_input(
            body in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let mut cur = ReadCursor::new(&body, "proptest control");
            let _ = Control::decode(&mut cur);
        }

        #[test]
        fn font_map_decode_never_panics_on_arbitrary_input(
            body in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let mut cur = ReadCursor::new(&body, "proptest font map");
            let _ = FontMap::decode(&mut cur);
        }
    }

    #[test]
    fn synchronize_round_trips() {
        let body = Synchronize { target_user: 1002 }.encode();
        assert_eq!(body, [0x01, 0x00, 0xEA, 0x03]);
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            Synchronize::decode(&mut cur).unwrap(),
            Synchronize { target_user: 1002 }
        );
    }

    #[test]
    fn control_round_trips() {
        let body = Control::new(CTRLACTION_COOPERATE).encode();
        assert_eq!(body, [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let granted = [0x02, 0x00, 0xEB, 0x03, 0xEA, 0x03, 0x00, 0x00];
        let mut cur = ReadCursor::new(&granted, "test");
        let control = Control::decode(&mut cur).unwrap();
        assert_eq!(control.action, CTRLACTION_GRANTED_CONTROL);
        assert_eq!(control.grant_id, 1003);
        assert_eq!(control.control_id, 1002);
    }

    /// Issue #252. `[MS-RDPBCGR]` 3.2.5.3.19 names exactly one field the client MUST ignore in
    /// this PDU -- **`targetUser`** -- and `messageType` is not it. Both references treat a wrong
    /// `messageType` as fatal (FreeRDP `activation.c:57-63` `return FALSE`; IronRDP
    /// `finalization_messages.rs` `invalid_field_err!("messageType")`), and justrdp was the sole
    /// outlier: it discarded `messageType` under a spec citation it did not have, while keeping
    /// the one field the spec does say to ignore. Measured on the real VM (#252): the server
    /// sends `messageType=1, targetUser=0` on all four observed activations.
    #[test]
    fn synchronize_rejects_a_message_type_the_spec_fixes_at_one() {
        // The only thing changed from the round-trip body above is messageType.
        let body = [0x02, 0x00, 0xEA, 0x03];
        let mut cur = ReadCursor::new(&body, "test");
        let err = Synchronize::decode(&mut cur).expect_err("messageType 2 is not SYNCMSGTYPE_SYNC");
        assert!(
            matches!(
                err,
                DecodeError::InvalidField {
                    field: "Synchronize.messageType",
                    ..
                }
            ),
            "expected a typed field error, got {err:?}"
        );
        // Below the mandated value as well as above it. `messageType == 0` is what separates
        // `!= SYNC_MSG_TYPE` from the plausible-but-wrong `> SYNC_MSG_TYPE`, and without this
        // case the guard passes its own test while asking the wrong question.
        let body = [0x00, 0x00, 0xEA, 0x03];
        let mut cur = ReadCursor::new(&body, "test");
        assert!(
            Synchronize::decode(&mut cur).is_err(),
            "messageType 0 is not SYNCMSGTYPE_SYNC either"
        );
        // And the value the spec *does* mandate is still accepted, so the guard is not blanket.
        let ok = [0x01, 0x00, 0xEA, 0x03];
        let mut cur = ReadCursor::new(&ok, "test");
        assert_eq!(Synchronize::decode(&mut cur).unwrap().target_user, 1002);
    }

    #[test]
    fn font_list_pins_mandated_values() {
        assert_eq!(
            encode_font_list(),
            [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00]
        );
    }

    #[test]
    fn font_map_decodes() {
        let body = [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00];
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(FontMap::decode(&mut cur).unwrap().map_flags, 0x0003);
    }
}

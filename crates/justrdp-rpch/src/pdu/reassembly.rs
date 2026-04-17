#![forbid(unsafe_code)]

//! Multi-fragment REQUEST / RESPONSE reassembly per C706 §12.4.3 and
//! MS-RPCE §2.2.2.12.
//!
//! A CO PDU whose serialized size exceeds the peer's negotiated
//! `max_xmit_frag` / `max_recv_frag` is split into multiple wire
//! fragments:
//!
//! - The **first** fragment has `PFC_FIRST_FRAG` set and
//!   `PFC_LAST_FRAG` clear.
//! - Each **middle** fragment has neither flag.
//! - The **last** fragment has `PFC_LAST_FRAG` set and
//!   `PFC_FIRST_FRAG` clear.
//! - A **single** fragment has both flags set.
//!
//! All fragments of a logical call share the same `call_id`. The
//! `opnum` / `p_cont_id` / `alloc_hint` live only on the first
//! fragment; middle and last fragments repeat the same header shape
//! but only their `stub_data` (and, on the last fragment, the
//! optional auth_verifier) is load-bearing.
//!
//! This module provides [`ReassemblyBuffer`] — an append-only
//! accumulator with call_id-pinning, ordering checks, and a size
//! cap. TsProxy in practice never sees multi-fragment responses
//! because every one of its stub payloads fits inside the default
//! 5840-byte fragment cap, so this code exists mostly to handle
//! aberrant / future servers correctly instead of UB'ing when a
//! middle fragment lands.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::ReadCursor;

use super::body::{FaultPdu, RequestPdu, ResponsePdu, FAULT_PTYPE, REQUEST_PTYPE, RESPONSE_PTYPE};
use super::common::{CommonHeader, COMMON_HEADER_SIZE, PFC_FIRST_FRAG, PFC_LAST_FRAG};

// =============================================================================
// Error type
// =============================================================================

/// Errors emitted by [`ReassemblyBuffer`].
#[derive(Debug, Clone)]
pub enum ReassemblyError {
    /// A fragment arrived with a `call_id` different from the one
    /// the buffer was pinned to by an earlier PFC_FIRST_FRAG.
    CallIdMismatch { expected: u32, got: u32 },
    /// The first fragment did not carry `PFC_FIRST_FRAG`.
    MissingFirstFrag,
    /// `PFC_FIRST_FRAG` arrived after an earlier first fragment
    /// without an intervening `PFC_LAST_FRAG` — the peer started a
    /// new call without ending the previous one.
    UnexpectedRestart,
    /// The accumulated stub_data would exceed the configured size
    /// cap. Guards against hostile / runaway streams.
    CapExceeded { cap: usize, needed: usize },
    /// The fragment's PTYPE is not one this buffer accepts (only
    /// REQUEST / RESPONSE / FAULT carry stub data worth
    /// reassembling).
    UnsupportedPtype { got: u8 },
    /// Decoding the underlying PDU failed.
    Decode(justrdp_core::DecodeError),
}

impl core::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CallIdMismatch { expected, got } => write!(
                f,
                "fragment call_id {got} does not match the call in progress ({expected})"
            ),
            Self::MissingFirstFrag => f.write_str("first fragment is missing PFC_FIRST_FRAG"),
            Self::UnexpectedRestart => {
                f.write_str("PFC_FIRST_FRAG arrived before the previous call's PFC_LAST_FRAG")
            }
            Self::CapExceeded { cap, needed } => write!(
                f,
                "reassembled stub_data would be {needed} bytes, cap is {cap}"
            ),
            Self::UnsupportedPtype { got } => {
                write!(f, "ptype {got:#04x} cannot be reassembled")
            }
            Self::Decode(e) => write!(f, "fragment decode failed: {e}"),
        }
    }
}

impl core::error::Error for ReassemblyError {}

impl From<justrdp_core::DecodeError> for ReassemblyError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

// =============================================================================
// Reassembled PDU
// =============================================================================

/// A fully reassembled REQUEST / RESPONSE / FAULT — the logical
/// PDU the caller gets back once [`ReassemblyBuffer::feed`] reports
/// completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassembledPdu {
    Request(RequestPdu),
    Response(ResponsePdu),
    Fault(FaultPdu),
}

impl ReassembledPdu {
    /// The `call_id` shared by every fragment of this logical PDU.
    pub fn call_id(&self) -> u32 {
        match self {
            Self::Request(r) => r.call_id,
            Self::Response(r) => r.call_id,
            Self::Fault(r) => r.call_id,
        }
    }

    /// Borrow the stub_data accumulated across all fragments.
    pub fn stub_data(&self) -> &[u8] {
        match self {
            Self::Request(r) => &r.stub_data,
            Self::Response(r) => &r.stub_data,
            Self::Fault(r) => &r.stub_data,
        }
    }
}

// =============================================================================
// Buffer
// =============================================================================

/// The default cap on a single reassembled PDU's stub_data — 64
/// MiB. Matches roughly what Windows RPCRT4 accepts and is large
/// enough that no legitimate TsProxy response approaches it.
pub const DEFAULT_REASSEMBLY_CAP: usize = 64 * 1024 * 1024;

/// Append-only fragment accumulator. The caller drives it by
/// feeding each inbound CO PDU's raw bytes to [`Self::feed`] and
/// inspects the return:
///
/// - `Ok(None)` — fragment accepted, waiting for more.
/// - `Ok(Some(reassembled))` — this fragment had `PFC_LAST_FRAG`;
///   the buffer reset itself and the returned PDU is the complete
///   call.
/// - `Err(_)` — ordering / sizing violation; the buffer is now in
///   an indeterminate state and should be discarded (construct a
///   fresh one for the next call).
#[derive(Debug)]
pub struct ReassemblyBuffer {
    /// Maximum size a single reassembled stub_data may reach.
    cap: usize,
    /// When `Some`, a call is in progress: this is the call_id
    /// captured from the first fragment, plus the accumulated
    /// stub_data and the PTYPE we're building up. `None` means the
    /// buffer is idle and expects `PFC_FIRST_FRAG` next.
    state: Option<InFlight>,
}

#[derive(Debug)]
struct InFlight {
    call_id: u32,
    ptype: u8,
    /// First fragment's full header so we can reconstruct the
    /// structured PDU once all fragments are in.
    first_pdu_bytes: Vec<u8>,
    /// Accumulated stub_data across fragments (grows on each feed).
    stub: Vec<u8>,
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyBuffer {
    /// Create a buffer with the default cap.
    pub fn new() -> Self {
        Self {
            cap: DEFAULT_REASSEMBLY_CAP,
            state: None,
        }
    }

    /// Create a buffer with a custom stub_data cap.
    pub fn with_cap(cap: usize) -> Self {
        Self { cap, state: None }
    }

    /// Is a call currently in progress?
    pub fn in_progress(&self) -> bool {
        self.state.is_some()
    }

    /// The call_id of the call currently being reassembled, if any.
    pub fn current_call_id(&self) -> Option<u32> {
        self.state.as_ref().map(|s| s.call_id)
    }

    /// Feed one raw PDU's bytes. See [`Self`] for the return-value
    /// contract.
    pub fn feed(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<Option<ReassembledPdu>, ReassemblyError> {
        if pdu_bytes.len() < COMMON_HEADER_SIZE {
            return Err(ReassemblyError::Decode(
                justrdp_core::DecodeError::invalid_value(
                    "CommonHeader",
                    "fragment shorter than common header",
                ),
            ));
        }
        let mut c = ReadCursor::new(pdu_bytes);
        let (hdr, _frag_len, _auth_len) = CommonHeader::decode(&mut c)?;

        match hdr.ptype {
            REQUEST_PTYPE | RESPONSE_PTYPE | FAULT_PTYPE => {}
            other => return Err(ReassemblyError::UnsupportedPtype { got: other }),
        }

        let is_first = hdr.pfc_flags & PFC_FIRST_FRAG != 0;
        let is_last = hdr.pfc_flags & PFC_LAST_FRAG != 0;

        // Dispatch on whether a call is in progress.
        let next_state = match self.state.take() {
            None => {
                if !is_first {
                    return Err(ReassemblyError::MissingFirstFrag);
                }
                let pdu = ReassembledPdu::decode(&pdu_bytes, hdr.ptype)?;
                let stub = pdu.stub_data().to_vec();
                if stub.len() > self.cap {
                    return Err(ReassemblyError::CapExceeded {
                        cap: self.cap,
                        needed: stub.len(),
                    });
                }
                if is_last {
                    // Single-fragment PDU — return immediately.
                    return Ok(Some(pdu));
                }
                Some(InFlight {
                    call_id: hdr.call_id,
                    ptype: hdr.ptype,
                    first_pdu_bytes: pdu_bytes.to_vec(),
                    stub,
                })
            }
            Some(mut s) => {
                if is_first {
                    return Err(ReassemblyError::UnexpectedRestart);
                }
                if hdr.call_id != s.call_id {
                    return Err(ReassemblyError::CallIdMismatch {
                        expected: s.call_id,
                        got: hdr.call_id,
                    });
                }
                if hdr.ptype != s.ptype {
                    return Err(ReassemblyError::UnsupportedPtype { got: hdr.ptype });
                }
                // Pull stub bytes off this fragment and append.
                let fragment = ReassembledPdu::decode(&pdu_bytes, hdr.ptype)?;
                let new_len = s.stub.len() + fragment.stub_data().len();
                if new_len > self.cap {
                    return Err(ReassemblyError::CapExceeded {
                        cap: self.cap,
                        needed: new_len,
                    });
                }
                s.stub.extend_from_slice(fragment.stub_data());
                if is_last {
                    // Rebuild the logical PDU by taking the first
                    // fragment's header and swapping in the full
                    // accumulated stub_data.
                    let first_pdu = ReassembledPdu::decode(&s.first_pdu_bytes, s.ptype)?;
                    return Ok(Some(first_pdu.with_stub(s.stub)));
                }
                Some(s)
            }
        };
        self.state = next_state;
        Ok(None)
    }

    /// Throw away any in-flight call (e.g. after an unrelated error
    /// on the transport).
    pub fn reset(&mut self) {
        self.state = None;
    }
}

impl ReassembledPdu {
    fn decode(pdu_bytes: &[u8], ptype: u8) -> Result<Self, justrdp_core::DecodeError> {
        let mut c = ReadCursor::new(pdu_bytes);
        match ptype {
            REQUEST_PTYPE => Ok(Self::Request(RequestPdu::decode(&mut c)?)),
            RESPONSE_PTYPE => Ok(Self::Response(ResponsePdu::decode(&mut c)?)),
            FAULT_PTYPE => Ok(Self::Fault(FaultPdu::decode(&mut c)?)),
            _ => Err(justrdp_core::DecodeError::invalid_value(
                "ReassembledPdu",
                "unsupported ptype",
            )),
        }
    }

    fn with_stub(self, stub: Vec<u8>) -> Self {
        match self {
            Self::Request(mut r) => {
                r.stub_data = stub;
                Self::Request(r)
            }
            Self::Response(mut r) => {
                r.stub_data = stub;
                Self::Response(r)
            }
            Self::Fault(mut r) => {
                r.stub_data = stub;
                Self::Fault(r)
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::body::{RequestPdu, ResponsePdu};
    use alloc::vec;
    use justrdp_core::WriteCursor;

    fn encode_pdu<F: FnOnce(&mut WriteCursor<'_>)>(size: usize, f: F) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        let mut w = WriteCursor::new(&mut buf);
        f(&mut w);
        buf
    }

    fn make_response_frag(call_id: u32, pfc: u8, stub: Vec<u8>) -> Vec<u8> {
        let r = ResponsePdu {
            pfc_flags: pfc,
            call_id,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: stub,
            auth: None,
        };
        encode_pdu(r.size(), |w| r.encode(w).unwrap())
    }

    fn make_request_frag(call_id: u32, pfc: u8, stub: Vec<u8>) -> Vec<u8> {
        let r = RequestPdu {
            pfc_flags: pfc,
            call_id,
            alloc_hint: 0,
            context_id: 0,
            opnum: 42,
            object: None,
            stub_data: stub,
            auth: None,
        };
        encode_pdu(r.size(), |w| r.encode(w).unwrap())
    }

    #[test]
    fn single_fragment_passes_through() {
        let mut b = ReassemblyBuffer::new();
        let bytes = make_response_frag(
            7,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        let got = b.feed(&bytes).unwrap().expect("single-frag returns pdu");
        assert_eq!(got.call_id(), 7);
        assert_eq!(got.stub_data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(!b.in_progress());
    }

    #[test]
    fn three_fragment_response_reassembles() {
        let mut b = ReassemblyBuffer::new();
        let f1 = make_response_frag(9, PFC_FIRST_FRAG, vec![0x01, 0x02, 0x03]);
        let f2 = make_response_frag(9, 0, vec![0x04, 0x05]);
        let f3 = make_response_frag(9, PFC_LAST_FRAG, vec![0x06, 0x07, 0x08, 0x09]);

        assert!(b.feed(&f1).unwrap().is_none());
        assert_eq!(b.current_call_id(), Some(9));
        assert!(b.feed(&f2).unwrap().is_none());
        let out = b.feed(&f3).unwrap().expect("last frag completes");
        assert_eq!(
            out.stub_data(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
        );
        assert!(!b.in_progress(), "buffer resets after completion");
    }

    #[test]
    fn two_fragment_request_reassembles_and_preserves_opnum() {
        let mut b = ReassemblyBuffer::new();
        let f1 = make_request_frag(11, PFC_FIRST_FRAG, vec![0xAA; 4]);
        let f2 = make_request_frag(11, PFC_LAST_FRAG, vec![0xBB; 4]);
        b.feed(&f1).unwrap();
        let out = b.feed(&f2).unwrap().unwrap();
        match out {
            ReassembledPdu::Request(r) => {
                assert_eq!(r.opnum, 42, "opnum comes from the first fragment");
                assert_eq!(r.stub_data, vec![0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
            }
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn middle_fragment_first_is_error() {
        let mut b = ReassemblyBuffer::new();
        let f = make_response_frag(1, 0, vec![0x00]);
        assert!(matches!(
            b.feed(&f).unwrap_err(),
            ReassemblyError::MissingFirstFrag
        ));
    }

    #[test]
    fn call_id_mismatch_mid_reassembly_is_error() {
        let mut b = ReassemblyBuffer::new();
        b.feed(&make_response_frag(5, PFC_FIRST_FRAG, vec![0x11])).unwrap();
        let err = b
            .feed(&make_response_frag(6, PFC_LAST_FRAG, vec![0x22]))
            .unwrap_err();
        assert!(matches!(
            err,
            ReassemblyError::CallIdMismatch {
                expected: 5,
                got: 6,
            }
        ));
    }

    #[test]
    fn unexpected_restart_is_error() {
        let mut b = ReassemblyBuffer::new();
        b.feed(&make_response_frag(5, PFC_FIRST_FRAG, vec![0x11])).unwrap();
        let err = b
            .feed(&make_response_frag(5, PFC_FIRST_FRAG, vec![0x22]))
            .unwrap_err();
        assert!(matches!(err, ReassemblyError::UnexpectedRestart));
    }

    #[test]
    fn mixed_ptype_mid_reassembly_is_error() {
        let mut b = ReassemblyBuffer::new();
        b.feed(&make_request_frag(1, PFC_FIRST_FRAG, vec![0x11])).unwrap();
        let err = b
            .feed(&make_response_frag(1, PFC_LAST_FRAG, vec![0x22]))
            .unwrap_err();
        assert!(matches!(err, ReassemblyError::UnsupportedPtype { .. }));
    }

    #[test]
    fn cap_exceeded_on_single_frag_is_error() {
        let mut b = ReassemblyBuffer::with_cap(2);
        let f = make_response_frag(1, PFC_FIRST_FRAG | PFC_LAST_FRAG, vec![0; 4]);
        let err = b.feed(&f).unwrap_err();
        assert!(matches!(
            err,
            ReassemblyError::CapExceeded {
                cap: 2,
                needed: 4,
            }
        ));
    }

    #[test]
    fn cap_exceeded_on_accumulation_is_error() {
        let mut b = ReassemblyBuffer::with_cap(6);
        b.feed(&make_response_frag(1, PFC_FIRST_FRAG, vec![0; 4])).unwrap();
        let err = b
            .feed(&make_response_frag(1, PFC_LAST_FRAG, vec![0; 4]))
            .unwrap_err();
        assert!(matches!(err, ReassemblyError::CapExceeded { cap: 6, needed: 8 }));
    }

    #[test]
    fn unsupported_ptype_is_error() {
        let mut b = ReassemblyBuffer::new();
        // Hand-build a BIND PDU — ptype 0x0B is not reassemblable.
        use crate::pdu::{BindPdu, ContextElement, SyntaxId};
        use crate::pdu::uuid::RpcUuid;
        let bind = BindPdu {
            ptype: crate::pdu::BIND_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            contexts: vec![ContextElement {
                context_id: 0,
                abstract_syntax: SyntaxId {
                    uuid: RpcUuid::NIL,
                    version_major: 1,
                    version_minor: 0,
                },
                transfer_syntaxes: vec![SyntaxId {
                    uuid: RpcUuid::NIL,
                    version_major: 2,
                    version_minor: 0,
                }],
            }],
            auth: None,
        };
        let bytes = encode_pdu(bind.size(), |w| bind.encode(w).unwrap());
        let err = b.feed(&bytes).unwrap_err();
        assert!(matches!(err, ReassemblyError::UnsupportedPtype { .. }));
    }

    #[test]
    fn reset_clears_in_flight_state() {
        let mut b = ReassemblyBuffer::new();
        b.feed(&make_response_frag(1, PFC_FIRST_FRAG, vec![0xAB])).unwrap();
        assert!(b.in_progress());
        b.reset();
        assert!(!b.in_progress());
        // Next call can start fresh.
        let out = b
            .feed(&make_response_frag(
                2,
                PFC_FIRST_FRAG | PFC_LAST_FRAG,
                vec![0xCD],
            ))
            .unwrap()
            .unwrap();
        assert_eq!(out.call_id(), 2);
    }

    #[test]
    fn short_pdu_is_decode_error() {
        let mut b = ReassemblyBuffer::new();
        let err = b.feed(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ReassemblyError::Decode(_)));
    }

    #[test]
    fn fault_pdu_passes_through() {
        use crate::pdu::FaultPdu;
        let flt = FaultPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 9,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            status: 0x1c01_0006,
            stub_data: vec![],
        };
        let bytes = encode_pdu(flt.size(), |w| flt.encode(w).unwrap());
        let mut b = ReassemblyBuffer::new();
        let got = b.feed(&bytes).unwrap().unwrap();
        match got {
            ReassembledPdu::Fault(f) => assert_eq!(f.status, 0x1c01_0006),
            other => panic!("expected Fault, got {other:?}"),
        }
    }
}

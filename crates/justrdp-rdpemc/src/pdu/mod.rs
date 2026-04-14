//! Wire-format PDU structs for MS-RDPEMC §2.2.
//!
//! All message types share the 4-byte [`OrderHeader`] (MS-RDPEMC §2.2.1).
//! The `Length` field of the header is inclusive of the header itself,
//! so `Length == 4` for header-only PDUs like [`OdGraphicsStreamPaused`].
//!
//! Multiple PDUs may be concatenated back-to-back in a single SVC
//! payload; use [`decode_all`] to drain a whole buffer.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{odtype, ORDER_HDR_SIZE};

mod app;
mod filter;
mod graphics;
mod header;
mod participant;
mod window;

pub use app::{OdAppCreated, OdAppRemoved};
pub use filter::OdFilterStateUpdated;
pub use graphics::{OdGraphicsStreamPaused, OdGraphicsStreamResumed};
pub use header::{OrderHeader, UnicodeString};
pub use participant::{
    OdParticipantCreated, OdParticipantCtrlChange, OdParticipantCtrlChangeResponse,
    OdParticipantRemoved,
};
pub use window::{OdWndCreated, OdWndRegionUpdate, OdWndRemoved, OdWndShow};

/// Tagged union covering all 13 MS-RDPEMC PDU types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncomspPdu {
    FilterStateUpdated(OdFilterStateUpdated),
    AppCreated(OdAppCreated),
    AppRemoved(OdAppRemoved),
    WndCreated(OdWndCreated),
    WndRemoved(OdWndRemoved),
    WndShow(OdWndShow),
    WndRegionUpdate(OdWndRegionUpdate),
    ParticipantCreated(OdParticipantCreated),
    ParticipantRemoved(OdParticipantRemoved),
    ParticipantCtrlChange(OdParticipantCtrlChange),
    ParticipantCtrlChangeResponse(OdParticipantCtrlChangeResponse),
    GraphicsStreamPaused(OdGraphicsStreamPaused),
    GraphicsStreamResumed(OdGraphicsStreamResumed),
}

const CTX: &str = "EncomspPdu";

impl EncomspPdu {
    /// Total encoded size in bytes (including the 4-byte order header).
    pub fn size(&self) -> usize {
        match self {
            Self::FilterStateUpdated(p) => p.size(),
            Self::AppCreated(p) => p.size(),
            Self::AppRemoved(p) => p.size(),
            Self::WndCreated(p) => p.size(),
            Self::WndRemoved(p) => p.size(),
            Self::WndShow(p) => p.size(),
            Self::WndRegionUpdate(p) => p.size(),
            Self::ParticipantCreated(p) => p.size(),
            Self::ParticipantRemoved(p) => p.size(),
            Self::ParticipantCtrlChange(p) => p.size(),
            Self::ParticipantCtrlChangeResponse(p) => p.size(),
            Self::GraphicsStreamPaused(p) => p.size(),
            Self::GraphicsStreamResumed(p) => p.size(),
        }
    }
}

impl Encode for EncomspPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::FilterStateUpdated(p) => p.encode(dst),
            Self::AppCreated(p) => p.encode(dst),
            Self::AppRemoved(p) => p.encode(dst),
            Self::WndCreated(p) => p.encode(dst),
            Self::WndRemoved(p) => p.encode(dst),
            Self::WndShow(p) => p.encode(dst),
            Self::WndRegionUpdate(p) => p.encode(dst),
            Self::ParticipantCreated(p) => p.encode(dst),
            Self::ParticipantRemoved(p) => p.encode(dst),
            Self::ParticipantCtrlChange(p) => p.encode(dst),
            Self::ParticipantCtrlChangeResponse(p) => p.encode(dst),
            Self::GraphicsStreamPaused(p) => p.encode(dst),
            Self::GraphicsStreamResumed(p) => p.encode(dst),
        }
    }

    fn name(&self) -> &'static str {
        "EncomspPdu"
    }

    fn size(&self) -> usize {
        EncomspPdu::size(self)
    }
}

/// Outcome of [`decode_all`] for a single PDU slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPdu {
    /// A known, fully-parsed PDU.
    Known(EncomspPdu),
    /// An unknown or forward-compat `Type` that was skipped using the
    /// `Length` field (MS-RDPEMC §3.1.5.1, Appendix A <7>). The `type_`
    /// and `length` fields are preserved so callers can log the skip.
    Skipped { type_: u16, length: u16 },
}

/// Drain a buffer containing one or more concatenated MS-RDPEMC PDUs
/// (MS-RDPEMC §3.1.5.1).
///
/// Unknown `Type` values are forward-compat skipped using the `Length`
/// field (Appendix A <7>) and reported as [`DecodedPdu::Skipped`]. A
/// malformed PDU (insufficient data, `Length < 4`, inconsistent body
/// size) is surfaced as a [`DecodeError`].
pub fn decode_all(src: &mut ReadCursor<'_>) -> DecodeResult<Vec<DecodedPdu>> {
    let mut out: Vec<DecodedPdu> = Vec::new();
    while !src.peek_remaining().is_empty() {
        // Peek the header without consuming so that individual PDU
        // decoders can re-read it from a clean cursor.
        let rest = src.peek_remaining();
        if rest.len() < ORDER_HDR_SIZE {
            return Err(DecodeError::not_enough_bytes(CTX, ORDER_HDR_SIZE, rest.len()));
        }
        let type_ = u16::from_le_bytes([rest[0], rest[1]]);
        let length = u16::from_le_bytes([rest[2], rest[3]]);
        let length_usize = length as usize;
        if length_usize < ORDER_HDR_SIZE {
            return Err(DecodeError::invalid_value(CTX, "length < 4"));
        }
        if rest.len() < length_usize {
            return Err(DecodeError::not_enough_bytes(CTX, length_usize, rest.len()));
        }

        let pdu = match type_ {
            odtype::FILTER_STATE_UPDATED => {
                DecodedPdu::Known(EncomspPdu::FilterStateUpdated(OdFilterStateUpdated::decode(
                    src,
                )?))
            }
            odtype::APP_REMOVED => {
                DecodedPdu::Known(EncomspPdu::AppRemoved(OdAppRemoved::decode(src)?))
            }
            odtype::APP_CREATED => {
                DecodedPdu::Known(EncomspPdu::AppCreated(OdAppCreated::decode(src)?))
            }
            odtype::WND_REMOVED => {
                DecodedPdu::Known(EncomspPdu::WndRemoved(OdWndRemoved::decode(src)?))
            }
            odtype::WND_CREATED => {
                DecodedPdu::Known(EncomspPdu::WndCreated(OdWndCreated::decode(src)?))
            }
            odtype::WND_SHOW => DecodedPdu::Known(EncomspPdu::WndShow(OdWndShow::decode(src)?)),
            odtype::PARTICIPANT_REMOVED => DecodedPdu::Known(EncomspPdu::ParticipantRemoved(
                OdParticipantRemoved::decode(src)?,
            )),
            odtype::PARTICIPANT_CREATED => DecodedPdu::Known(EncomspPdu::ParticipantCreated(
                OdParticipantCreated::decode(src)?,
            )),
            odtype::PARTICIPANT_CTRL_CHANGED => DecodedPdu::Known(
                EncomspPdu::ParticipantCtrlChange(OdParticipantCtrlChange::decode(src)?),
            ),
            odtype::GRAPHICS_STREAM_PAUSED => DecodedPdu::Known(EncomspPdu::GraphicsStreamPaused(
                OdGraphicsStreamPaused::decode(src)?,
            )),
            odtype::GRAPHICS_STREAM_RESUMED => DecodedPdu::Known(
                EncomspPdu::GraphicsStreamResumed(OdGraphicsStreamResumed::decode(src)?),
            ),
            odtype::WND_RGN_UPDATE => {
                DecodedPdu::Known(EncomspPdu::WndRegionUpdate(OdWndRegionUpdate::decode(src)?))
            }
            odtype::PARTICIPANT_CTRL_CHANGE_RESPONSE => DecodedPdu::Known(
                EncomspPdu::ParticipantCtrlChangeResponse(OdParticipantCtrlChangeResponse::decode(
                    src,
                )?),
            ),
            _ => {
                // Forward-compat skip: advance by the declared length.
                let _ = src.read_slice(length_usize, CTX)?;
                DecodedPdu::Skipped {
                    type_,
                    length,
                }
            }
        };
        out.push(pdu);
    }
    Ok(out)
}

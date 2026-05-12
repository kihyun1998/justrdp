#![forbid(unsafe_code)]

//! Capability advertisement audit (PRD #35 Module A2).
//!
//! Pure-logic check that every capability bit a channel processor
//! advertises to the server is paired with a real handler. A
//! `feedback_no_partial_protocol_enable` violation manifests as an
//! advertised bit whose declared-handler counterpart is missing —
//! the audit returns an error listing exactly which bits.
//!
//! The audit is data-only: it does not introspect processor state.
//! Callers pass in two sets (`advertised`, `declared`) and the audit
//! computes the set difference. This keeps it reusable across
//! channel-level (cliprdr `GeneralCapabilityFlags`), connector-level
//! (`EarlyCapabilityFlags`, `CapabilitySet`), or any future axis.

use alloc::vec::Vec;

/// One capability the wire layer advertises or the runtime handles.
///
/// Variants are tagged by *axis* (which protocol layer the bit lives
/// in) so audits can compare like with like — a cliprdr file-cap bit
/// will never accidentally match an EarlyCap flag with the same numeric
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvertisedCap {
    /// MS-RDPECLIP General Capability Set `generalFlags` bit (cliprdr).
    CliprdrGeneralFlag(u32),
    /// MS-RDPBCGR `ClientCoreData::earlyCapabilityFlags` bit.
    EarlyCapability(u16),
    /// MS-RDPBCGR Capability Set type in `ConfirmActivePdu`.
    CapabilitySetType(u16),
}

/// Outcome of an audit run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// Bits advertised on the wire that no handler declared.
    /// Each such bit is a `feedback_no_partial_protocol_enable` violation.
    pub orphan_advertised: Vec<AdvertisedCap>,
}

impl AuditReport {
    /// `true` when every advertised bit had a matching declaration.
    pub fn is_clean(&self) -> bool {
        self.orphan_advertised.is_empty()
    }
}

/// Run the audit.
///
/// Returns a report listing every advertised capability that did not
/// appear in the declared set. The reverse direction (declared but not
/// advertised) is intentionally *not* an error — a processor may
/// implement more than it currently announces, which is the safe shape
/// for `feedback_no_partial_protocol_enable`.
pub fn audit(
    advertised: &[AdvertisedCap],
    declared: &[AdvertisedCap],
) -> AuditReport {
    let orphan_advertised = advertised
        .iter()
        .filter(|cap| !declared.contains(cap))
        .copied()
        .collect();
    AuditReport { orphan_advertised }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// PRD #35 Module A2: every `SvcProcessor` declares its handler bits
    /// through the new `declared_caps()` trait method. Default is empty,
    /// matching purely reactive processors that don't carry any
    /// capability semantics of their own.
    #[test]
    fn default_processor_declares_no_caps() {
        // Use a minimal SvcProcessor impl with no overrides.
        use crate::{ChannelName, CompressionCondition, SvcMessage, SvcProcessor, SvcResult};
        use justrdp_core::AsAny;
        use core::any::Any;
        #[derive(Debug)]
        struct Bare;
        impl AsAny for Bare {
            fn as_any(&self) -> &dyn Any { self }
            fn as_any_mut(&mut self) -> &mut dyn Any { self }
        }
        impl SvcProcessor for Bare {
            fn channel_name(&self) -> ChannelName { ChannelName::new(b"bare") }
            fn start(&mut self) -> SvcResult<Vec<SvcMessage>> { Ok(Vec::new()) }
            fn process(&mut self, _payload: &[u8]) -> SvcResult<Vec<SvcMessage>> { Ok(Vec::new()) }
            fn compression_condition(&self) -> CompressionCondition { CompressionCondition::Never }
        }
        let bare = Bare;
        assert!(bare.declared_caps().is_empty(), "default declared_caps must be empty");
    }

    /// PRD #35 Module A2 tracer: the audit's central contract — an
    /// advertised cap whose handler is *not* declared is flagged.
    /// `feedback_no_partial_protocol_enable` violations look exactly
    /// like this.
    #[test]
    fn audit_flags_advertised_cap_without_declared_handler() {
        // cliprdr advertises USE_LONG_FORMAT_NAMES (0x02), backend
        // declares nothing — simulates the pre-Module-C state where
        // file/lock caps were advertised without handlers.
        let advertised = vec![AdvertisedCap::CliprdrGeneralFlag(0x02)];
        let declared: Vec<AdvertisedCap> = vec![];
        let report = audit(&advertised, &declared);
        assert!(!report.is_clean(), "audit must surface orphan advertisements");
        assert_eq!(
            report.orphan_advertised,
            vec![AdvertisedCap::CliprdrGeneralFlag(0x02)]
        );
    }
}

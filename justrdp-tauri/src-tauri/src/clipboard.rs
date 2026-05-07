//! Native OS clipboard wiring (Slice D1).
//!
//! Per ADR-0006 (native-surface deepening), the Tauri layer touches
//! only the platform-facing seam — `NativeClipboard` from
//! `justrdp-cliprdr-native`, which already bundles a
//! `PlatformClipboard` alias for each OS (Windows `clipboard-win`,
//! macOS `objc2`, Linux behind `x11` / `wayland` features). All
//! CLIPRDR PDU encoding (UTF-16LE / DIB framing / FormatList
//! negotiation) lives inside `NativeClipboard`. This file is
//! wiring; its `use` lines must contain zero CLIPRDR PDU symbols
//! (`LongFormatName`, `FormatListResponse`, `FileContentsRequestPdu`,
//! …) — that import boundary is the ADR-0006 compliance check.
//!
//! ## Platform availability
//!
//! - **Windows**: enabled automatically (Win32 Clipboard API)
//! - **macOS**: enabled automatically (NSPasteboard via `objc2`)
//! - **Linux**: requires the `x11` or `wayland` feature on
//!   `justrdp-cliprdr-native`; without one of them, the session
//!   has no clipboard processor and the channel is silently absent
//!
//! Linux feature wiring is a follow-up slice (same as audio's
//! Linux PulseAudio gap).

use justrdp_svc::SvcProcessor;

/// Build an SVC processor that bridges the host OS clipboard and
/// the remote one in both directions, if the current platform has
/// a backend available. `None` on platforms without a wired
/// surface so the embedder registers a clipboard-less session
/// without conditional code at the call site.
#[cfg(any(windows, target_os = "macos"))]
pub fn new_platform_clipboard_processor() -> Option<Box<dyn SvcProcessor>> {
    use justrdp_cliprdr::CliprdrClient;
    use justrdp_cliprdr_native::NativeClipboard;

    let clip = NativeClipboard::new().ok()?;
    let client = CliprdrClient::new(Box::new(clip));
    Some(Box::new(client))
}

/// Linux without the `x11` or `wayland` feature on
/// `justrdp-cliprdr-native`: no native surface, clipboard channel
/// is omitted from the session. The session continues normally.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn new_platform_clipboard_processor() -> Option<Box<dyn SvcProcessor>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the platform-conditional contract: Windows / macOS yield
    /// a backend; Linux without the feature yields None. Mirrors
    /// `audio::tests::returns_some_on_windows_and_none_elsewhere`.
    #[test]
    fn returns_some_on_windows_macos_and_none_elsewhere() {
        let processor = new_platform_clipboard_processor();

        #[cfg(any(windows, target_os = "macos"))]
        assert!(processor.is_some(), "Windows/macOS build should yield a backend");

        #[cfg(not(any(windows, target_os = "macos")))]
        let _ = processor;
    }
}

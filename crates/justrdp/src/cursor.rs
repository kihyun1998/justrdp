//! Host-facing cursor events (issue #41) — the pointer half of the session's output, next to
//! [`crate::framebuffer::FrameUpdate`]. The session machine decodes the five pointer update
//! messages (MS-RDPBCGR 2.2.9.1.1.4) into these; how a cursor is actually shown (an OS cursor,
//! a software-composited sprite, …) is the host's business.

/// One decoded cursor shape, ready to install: straight-alpha RGBA with its hotspot. Inverted
/// pixels (the AND=1/XOR=white screen-inversion mode RGBA cannot express) arrive as a
/// contrasting black/white checkerboard — see `justrdp_codecs::pointer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorImage {
    /// Shape width in pixels.
    pub width: u16,
    /// Shape height in pixels.
    pub height: u16,
    /// Hotspot X within the shape.
    pub hotspot_x: u16,
    /// Hotspot Y within the shape.
    pub hotspot_y: u16,
    /// `width × height × 4` straight-alpha RGBA bytes, top-down.
    pub rgba: Vec<u8>,
}

/// A cursor change the host should apply, in stream order relative to frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorEvent {
    /// Install this shape as the cursor.
    Set(CursorImage),
    /// The server moved the pointer (desktop coordinates).
    Move {
        /// X in desktop coordinates.
        x: u16,
        /// Y in desktop coordinates.
        y: u16,
    },
    /// Hide the cursor entirely (SYSPTR_NULL — e.g. full-screen video, hidden by the remote
    /// app).
    Hidden,
    /// Show the host's default cursor (SYSPTR_DEFAULT).
    Default,
}

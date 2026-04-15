//! `.rdp` file → [`Config`] mapping.
//!
//! Windows `mstsc.exe` persists connection settings in `.rdp` files — a
//! flat list of `key:type:value` entries parsed by [`justrdp_rdpfile`].
//! This module translates the subset of fields we currently understand
//! into [`ConfigBuilder`] mutations so callers can bootstrap a
//! connection from an existing `.rdp` file instead of hand-wiring every
//! setting.
//!
//! ## Usage
//!
//! ```ignore
//! use justrdp_connector::{Config, rdpfile};
//! use justrdp_rdpfile::RdpFile;
//!
//! let contents = std::fs::read_to_string("session.rdp")?;
//! let file = RdpFile::parse(&contents)?;
//! let (host, port) = rdpfile::server_address(&file)
//!     .ok_or("no server in rdp file")?;
//!
//! let config = Config::builder(&username, &password)
//!     .apply_rdp_file(&file)
//!     .build();
//! // Use (host, port) with the blocking runtime's connect().
//! ```
//!
//! ## Mapping
//!
//! | `.rdp` key                     | `Config` field                    |
//! | ------------------------------ | --------------------------------- |
//! | `domain` (s)                   | `domain`                          |
//! | `desktopwidth` / `desktopheight` (i) | `desktop_size`              |
//! | `session bpp` (i)              | `color_depth` (8/15/16/24/32)     |
//! | `compression` (i)              | `compression.enabled`             |
//! | `enablecredsspsupport` (i)     | `security_protocol` (HYBRID bit)  |
//! | `authentication level` (i)     | — (informational, not applied)    |
//! | `disable wallpaper` (i)        | `performance_flags` DISABLE_WALLPAPER |
//! | `disable full window drag` (i) | `performance_flags` DISABLE_FULLWINDOWDRAG |
//! | `disable menu anims` (i)       | `performance_flags` DISABLE_MENUANIMATIONS |
//! | `disable themes` (i)           | `performance_flags` DISABLE_THEMING |
//! | `disable cursor setting` (i)   | `performance_flags` DISABLE_CURSORSETTINGS |
//! | `allow font smoothing` (i)     | `performance_flags` ENABLE_FONT_SMOOTHING |
//! | `allow desktop composition` (i)| `performance_flags` ENABLE_DESKTOP_COMPOSITION |
//!
//! Fields deliberately **not** applied:
//!
//! * `username` — credentials come from [`Config::builder`], which
//!   requires them up front; letting the `.rdp` file overwrite them
//!   would create ambiguity about which source wins.
//! * `full address` / `server port` — callers extract these with
//!   [`server_address`] and pass the resulting `(host, port)` tuple to
//!   the runtime's `connect()` call; they are not stored in [`Config`].
//! * `redirectdrives` / `redirectclipboard` / `audiomode` / ... —
//!   channel routing requires the caller to register SVC processors
//!   (`cliprdr`, `rdpsnd`, `rdpdr`, ...), which is a runtime concern
//!   handled by `justrdp-blocking`. This module only populates the
//!   static-channel list when the processor wiring is unambiguous.
//! * Gateway / RemoteApp fields — deferred until §10.1 RD Gateway and a
//!   future RAIL launch helper land.

use alloc::string::String;

use justrdp_pdu::rdp::client_info::PerformanceFlags;
use justrdp_pdu::x224::SecurityProtocol;
use justrdp_rdpfile::RdpFile;

use crate::config::{ColorDepth, ConfigBuilder, DesktopSize};

/// Apply mapped fields from `file` onto `builder`.
///
/// Only fields present (`Some`) in the parsed file are touched. Fields
/// absent from the `.rdp` file leave the builder's current values alone.
pub(crate) fn apply_to_builder(mut builder: ConfigBuilder, file: &RdpFile) -> ConfigBuilder {
    if let Some(domain) = file.domain.as_deref() {
        if !domain.is_empty() {
            builder.config.domain = Some(String::from(domain));
        }
    }

    // Desktop size — both width and height must be present and positive
    // for us to override the default. `.rdp` files sometimes carry only
    // one of the two (partial configs), in which case we leave the
    // builder's default untouched rather than guessing.
    if let (Some(w), Some(h)) = (file.desktopwidth, file.desktopheight) {
        if let (Ok(w), Ok(h)) = (u16::try_from(w), u16::try_from(h)) {
            if w > 0 && h > 0 {
                builder.config.desktop_size = DesktopSize::new(w, h);
            }
        }
    }

    if let Some(bpp) = file.session_bpp {
        if let Some(depth) = color_depth_from_bpp(bpp) {
            builder.config.color_depth = depth;
        }
    }

    if let Some(enabled) = file.compression {
        builder.config.compression.enabled = enabled != 0;
    }

    // `.rdp` files encode the CredSSP preference via two independent
    // ints; mstsc treats "any 1" as "please use CredSSP". Only flip the
    // bit on — never flip it off — because HYBRID is in the default
    // builder set and callers may have other protocols layered in.
    let credssp_requested = file.enablecredsspsupport.unwrap_or(0) != 0;
    if credssp_requested {
        builder.config.security_protocol =
            builder.config.security_protocol.union(SecurityProtocol::HYBRID);
    }

    // Performance flags — the `.rdp` fields are all tri-valued in
    // principle (missing / 0 / 1) but mstsc only writes 0 or 1. Treat
    // missing as "don't change", 0 as "clear", 1 as "set", applied on
    // top of the builder's existing mask.
    let mut flags_bits = builder.config.performance_flags.bits();
    apply_flag_bit(&mut flags_bits, file.disable_wallpaper, PerformanceFlags::DISABLE_WALLPAPER);
    apply_flag_bit(
        &mut flags_bits,
        file.disable_full_window_drag,
        PerformanceFlags::DISABLE_FULLWINDOWDRAG,
    );
    apply_flag_bit(
        &mut flags_bits,
        file.disable_menu_anims,
        PerformanceFlags::DISABLE_MENUANIMATIONS,
    );
    apply_flag_bit(&mut flags_bits, file.disable_themes, PerformanceFlags::DISABLE_THEMING);
    apply_flag_bit(
        &mut flags_bits,
        file.disable_cursor_setting,
        PerformanceFlags::DISABLE_CURSORSETTINGS,
    );
    apply_flag_bit(
        &mut flags_bits,
        file.allow_font_smoothing,
        PerformanceFlags::ENABLE_FONT_SMOOTHING,
    );
    apply_flag_bit(
        &mut flags_bits,
        file.allow_desktop_composition,
        PerformanceFlags::ENABLE_DESKTOP_COMPOSITION,
    );
    builder.config.performance_flags = PerformanceFlags::from_bits(flags_bits);

    builder
}

fn color_depth_from_bpp(bpp: i32) -> Option<ColorDepth> {
    match bpp {
        // 8/15 aren't surfaced by ColorDepth but clients often store 15
        // for "high-color" — fall back to 16. 24 falls back to Bpp24.
        8 | 15 | 16 => Some(ColorDepth::Bpp16),
        24 => Some(ColorDepth::Bpp24),
        32 => Some(ColorDepth::Bpp32),
        _ => None,
    }
}

fn apply_flag_bit(bits: &mut u32, raw: Option<i32>, flag: PerformanceFlags) {
    match raw {
        Some(0) => *bits &= !flag.bits(),
        Some(_) => *bits |= flag.bits(),
        None => {}
    }
}

/// Extract the server host and TCP port from an [`RdpFile`].
///
/// The canonical source is the `full address` string field, which
/// mstsc writes in one of three forms:
///
/// * `host:port` — both captured directly
/// * `host` — port comes from the `server port` integer field, falling
///   back to RDP's default `3389` if that is also absent
/// * `[ipv6]:port` or `[ipv6]` — the brackets are stripped and the rest
///   follows the same rules
///
/// Returns `None` when no `full address` is present. Callers typically
/// pass the returned `(host, port)` to
/// `justrdp_blocking::RdpClient::connect`.
pub fn server_address(file: &RdpFile) -> Option<(String, u16)> {
    let raw = file.full_address.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }

    let default_port = file
        .server_port
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .unwrap_or(3389);

    // IPv6 literal form: `[::1]:3389` or `[::1]`. Bracket form is the
    // only way RFC 3986 allows a colon inside the host.
    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            let rest = &stripped[end + 1..];
            let port = rest
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return Some((String::from(host), port));
        }
        return None;
    }

    // IPv4 / hostname form: last `:` separates host from port iff there
    // is exactly one colon. More than one colon with no brackets is an
    // unbracketed IPv6 literal — we reject those because splitting
    // would be ambiguous.
    let colons = raw.bytes().filter(|b| *b == b':').count();
    match colons {
        0 => Some((String::from(raw), default_port)),
        1 => {
            let (host, port_str) = raw.rsplit_once(':')?;
            let port = port_str.parse::<u16>().ok()?;
            Some((String::from(host), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_rdpfile::RdpFile;

    fn parse(input: &str) -> RdpFile {
        RdpFile::parse(input).expect("parse rdp file")
    }

    #[test]
    fn domain_and_desktop_size() {
        let file = parse(
            "domain:s:EXAMPLE\r\n\
             desktopwidth:i:1920\r\n\
             desktopheight:i:1080\r\n",
        );
        let config = crate::Config::builder("alice", "pw")
            .apply_rdp_file(&file)
            .build();
        assert_eq!(config.domain.as_deref(), Some("EXAMPLE"));
        assert_eq!(config.desktop_size.width, 1920);
        assert_eq!(config.desktop_size.height, 1080);
    }

    #[test]
    fn session_bpp_maps_to_color_depth() {
        let file = parse("session bpp:i:32\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        assert_eq!(config.color_depth as u16, ColorDepth::Bpp32 as u16);
    }

    #[test]
    fn unknown_bpp_leaves_default_untouched() {
        let file = parse("session bpp:i:7\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        // Default is Bpp16.
        assert_eq!(config.color_depth as u16, ColorDepth::Bpp16 as u16);
    }

    #[test]
    fn partial_desktop_size_leaves_default() {
        let file = parse("desktopwidth:i:800\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        // Default builder size is 1024x768 — a lone `desktopwidth` must
        // not half-apply.
        assert_eq!(config.desktop_size.width, 1024);
        assert_eq!(config.desktop_size.height, 768);
    }

    #[test]
    fn performance_flags_set_and_clear() {
        let file = parse(
            "disable wallpaper:i:1\r\n\
             disable full window drag:i:1\r\n\
             allow font smoothing:i:1\r\n\
             allow desktop composition:i:0\r\n",
        );
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        let bits = config.performance_flags.bits();
        assert!(bits & PerformanceFlags::DISABLE_WALLPAPER.bits() != 0);
        assert!(bits & PerformanceFlags::DISABLE_FULLWINDOWDRAG.bits() != 0);
        assert!(bits & PerformanceFlags::ENABLE_FONT_SMOOTHING.bits() != 0);
        assert!(bits & PerformanceFlags::ENABLE_DESKTOP_COMPOSITION.bits() == 0);
    }

    #[test]
    fn credssp_flag_unions_hybrid() {
        let file = parse("enablecredsspsupport:i:1\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        assert!(config.security_protocol.contains(SecurityProtocol::HYBRID));
    }

    #[test]
    fn credssp_zero_does_not_clear_existing_hybrid() {
        let file = parse("enablecredsspsupport:i:0\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        // Default builder already includes HYBRID — apply must never
        // strip protocols that the caller opted into.
        assert!(config.security_protocol.contains(SecurityProtocol::HYBRID));
    }

    #[test]
    fn compression_flag() {
        let file = parse("compression:i:1\r\n");
        let config = crate::Config::builder("u", "p").apply_rdp_file(&file).build();
        assert!(config.compression.enabled);
    }

    #[test]
    fn server_address_ipv4_with_port() {
        let file = parse("full address:s:192.168.1.10:3390\r\n");
        let (host, port) = server_address(&file).unwrap();
        assert_eq!(host, "192.168.1.10");
        assert_eq!(port, 3390);
    }

    #[test]
    fn server_address_hostname_without_port_uses_default() {
        let file = parse("full address:s:rds.example.com\r\n");
        let (host, port) = server_address(&file).unwrap();
        assert_eq!(host, "rds.example.com");
        assert_eq!(port, 3389);
    }

    #[test]
    fn server_address_hostname_uses_server_port_field() {
        let file = parse("full address:s:rds.example.com\r\nserver port:i:4000\r\n");
        let (host, port) = server_address(&file).unwrap();
        assert_eq!(host, "rds.example.com");
        assert_eq!(port, 4000);
    }

    #[test]
    fn server_address_ipv6_bracketed_with_port() {
        let file = parse("full address:s:[2001:db8::1]:3389\r\n");
        let (host, port) = server_address(&file).unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 3389);
    }

    #[test]
    fn server_address_ipv6_bracketed_no_port() {
        let file = parse("full address:s:[2001:db8::1]\r\nserver port:i:3390\r\n");
        let (host, port) = server_address(&file).unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 3390);
    }

    #[test]
    fn server_address_rejects_bare_ipv6() {
        // Unbracketed multi-colon string is ambiguous: we cannot tell
        // where the host ends and the port begins. Reject explicitly.
        let file = parse("full address:s:2001:db8::1\r\n");
        assert!(server_address(&file).is_none());
    }

    #[test]
    fn server_address_missing() {
        let file = parse("domain:s:CORP\r\n");
        assert!(server_address(&file).is_none());
    }

    #[test]
    fn server_address_empty() {
        let file = parse("full address:s:\r\n");
        assert!(server_address(&file).is_none());
    }
}

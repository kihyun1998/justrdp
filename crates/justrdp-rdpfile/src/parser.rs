#![forbid(unsafe_code)]

//! `.rdp` file parser and writer.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ── Limits ──

/// Maximum total input size in bytes (1 MiB).
const MAX_INPUT_SIZE: usize = 1024 * 1024;

/// Maximum number of lines to process.
const MAX_LINES: usize = 512;

/// Maximum length of a single line in bytes.
const MAX_LINE_LEN: usize = 4096;

/// Maximum number of extra (unknown-key) entries.
const MAX_EXTRA_ENTRIES: usize = 64;

// ── Error ──

/// Parse error for `.rdp` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MalformedLine { line_number: usize },
    InvalidInteger { line_number: usize, value: String },
    InvalidHex { line_number: usize, value: String },
    UnknownType { line_number: usize, type_char: char },
    InputTooLarge,
    TooManyLines { line_number: usize },
    LineTooLong { line_number: usize },
    TooManyExtraEntries { line_number: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedLine { line_number } => write!(f, "malformed line at {line_number}"),
            Self::InvalidInteger { line_number, value } => {
                write!(f, "invalid integer {value:?} at {line_number}")
            }
            Self::InvalidHex { line_number, value } => {
                write!(f, "invalid hex {value:?} at {line_number}")
            }
            Self::UnknownType { line_number, type_char } => {
                write!(f, "unknown type '{type_char}' at {line_number}")
            }
            Self::InputTooLarge => write!(f, "input exceeds maximum size"),
            Self::TooManyLines { line_number } => write!(f, "too many lines at {line_number}"),
            Self::LineTooLong { line_number } => write!(f, "line too long at {line_number}"),
            Self::TooManyExtraEntries { line_number } => {
                write!(f, "too many extra entries at {line_number}")
            }
        }
    }
}

// ── Shared helpers ──

/// Known type discriminator characters in the `.rdp` format: `i` (integer), `s` (string), `b` (binary hex).
const KNOWN_TYPE_CHARS: [char; 3] = ['i', 's', 'b'];

/// Normalizes the RDP type discriminator character to lowercase.
/// The `.rdp` format permits uppercase (`I`, `S`, `B`); we normalize for matching.
#[inline]
fn normalize_type_char(c: char) -> char {
    match c {
        'I' => 'i',
        'S' => 's',
        'B' => 'b',
        c => c,
    }
}

/// Splits a trimmed `.rdp` line into `(key, normalized_type, raw_type, value)`.
/// Returns `None` if the line is malformed.
fn split_rdp_line(line: &str) -> Option<(&str, char, char, &str)> {
    let first_colon = line.find(':')?;
    let rest = &line[first_colon + 1..];
    let second_colon = first_colon + 1 + rest.find(':')?;

    let key = line[..first_colon].trim();
    let type_str = line[first_colon + 1..second_colon].trim();
    let value = &line[second_colon + 1..];

    if type_str.len() != 1 {
        return None;
    }

    let raw_type = type_str.chars().next().unwrap();
    let normalized = normalize_type_char(raw_type);

    Some((key, normalized, raw_type, value))
}

/// Validates a binary (`b`) type hex value.
/// Returns `false` if the value has odd length or contains non-hex characters.
fn is_valid_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Strip a leading UTF-8 BOM if present.
fn strip_bom(input: &str) -> &str {
    input.strip_prefix('\u{FEFF}').unwrap_or(input)
}

// ── Entry ──

/// A single raw entry from an `.rdp` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpEntry {
    pub key: String,
    /// Type discriminator character, always normalized to lowercase (`i`, `s`, `b`, etc.).
    pub type_char: char,
    pub value: String,
}

// ── RdpFile ──

/// Macro to define RdpFile with typed fields and key-to-field mapping.
macro_rules! define_rdp_file {
    (
        integers: [ $( ($i_field:ident, $i_key:expr) ),* $(,)? ],
        strings:  [ $( ($s_field:ident, $s_key:expr) ),* $(,)? ],
    ) => {
        /// Parsed `.rdp` file with typed fields.
        ///
        /// # Security
        ///
        /// Fields such as `alternate_shell`, `remoteapplicationcmdline`, and
        /// `remoteapplicationprogram` originate from untrusted input. Callers **must not**
        /// pass these values to shell commands or process spawn functions without
        /// proper sanitization/validation.
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct RdpFile {
            // Integer fields
            $( pub $i_field: Option<i32>, )*
            // String fields
            $( pub $s_field: Option<String>, )*
            /// Entries not matched to a known typed field (roundtrip fidelity).
            pub extra_entries: Vec<RdpEntry>,
        }

        impl RdpFile {
            /// Try to set a typed field. Returns `Ok(true)` if matched, `Ok(false)` if not,
            /// `Err(())` if the value is invalid (e.g. bad integer).
            fn set_typed_field(&mut self, key_lower: &str, type_char: char, value: &str) -> Result<bool, ()> {
                match (key_lower, type_char) {
                    $(
                        ($i_key, 'i') => {
                            let v = value.trim().parse::<i32>().map_err(|_| ())?;
                            self.$i_field = Some(v);
                            Ok(true)
                        }
                    )*
                    $(
                        ($s_key, 's') => {
                            self.$s_field = Some(String::from(value));
                            Ok(true)
                        }
                    )*
                    _ => Ok(false),
                }
            }

            /// Write typed fields in declaration order: integers first, then strings.
            fn write_typed_fields(&self, out: &mut String) {
                $(
                    if let Some(ref v) = self.$i_field {
                        out.push_str($i_key);
                        out.push_str(":i:");
                        write_i32(out, *v);
                        out.push_str("\r\n");
                    }
                )*
                $(
                    if let Some(ref v) = self.$s_field {
                        out.push_str($s_key);
                        out.push_str(":s:");
                        out.push_str(v);
                        out.push_str("\r\n");
                    }
                )*
            }
        }
    };
}

define_rdp_file! {
    integers: [
        // Connection
        (server_port, "server port"),
        (authentication_level, "authentication level"),
        (enablecredsspsupport, "enablecredsspsupport"),
        (negotiate_security_layer, "negotiate security layer"),
        (prompt_for_credentials, "prompt for credentials"),
        (promptcredentialonce, "promptcredentialonce"),
        (enablerdsaadauth, "enablerdsaadauth"),
        (disableconnectionsharing, "disableconnectionsharing"),
        // Display
        (desktopwidth, "desktopwidth"),
        (desktopheight, "desktopheight"),
        (screen_mode_id, "screen mode id"),
        (desktop_size_id, "desktop size id"),
        (session_bpp, "session bpp"),
        (use_multimon, "use multimon"),
        (smart_sizing, "smart sizing"),
        (dynamic_resolution, "dynamic resolution"),
        (displayconnectionbar, "displayconnectionbar"),
        (desktopscalefactor, "desktopscalefactor"),
        (maximizetocurrentdisplays, "maximizetocurrentdisplays"),
        (singlemoninwindowedmode, "singlemoninwindowedmode"),
        // Performance
        (connection_type, "connection type"),
        (networkautodetect, "networkautodetect"),
        (bandwidthautodetect, "bandwidthautodetect"),
        (compression, "compression"),
        (autoreconnection_enabled, "autoreconnection enabled"),
        (videoplaybackmode, "videoplaybackmode"),
        (disable_wallpaper, "disable wallpaper"),
        (disable_full_window_drag, "disable full window drag"),
        (disable_menu_anims, "disable menu anims"),
        (disable_themes, "disable themes"),
        (disable_cursor_setting, "disable cursor setting"),
        (allow_font_smoothing, "allow font smoothing"),
        (allow_desktop_composition, "allow desktop composition"),
        (bitmapcachepersistenable, "bitmapcachepersistenable"),
        // Audio
        (audiomode, "audiomode"),
        (audiocapturemode, "audiocapturemode"),
        // Redirection
        (redirectdrives, "redirectdrives"),
        (redirectprinters, "redirectprinters"),
        (redirectcomports, "redirectcomports"),
        (redirectsmartcards, "redirectsmartcards"),
        (redirectclipboard, "redirectclipboard"),
        (redirectwebauthn, "redirectwebauthn"),
        (keyboardhook, "keyboardhook"),
        // Gateway
        (gatewayusagemethod, "gatewayusagemethod"),
        (gatewaycredentialssource, "gatewaycredentialssource"),
        (gatewayprofileusagemethod, "gatewayprofileusagemethod"),
        // RemoteApp
        (remoteapplicationmode, "remoteapplicationmode"),
        (remoteapplicationexpandcmdline, "remoteapplicationexpandcmdline"),
        (remoteapplicationexpandworkingdir, "remoteapplicationexpandworkingdir"),
        // Misc
        (auto_connect, "auto connect"),
    ],
    strings: [
        // Connection
        (full_address, "full address"),
        (alternate_full_address, "alternate full address"),
        (username, "username"),
        (domain, "domain"),
        (kdcproxyname, "kdcproxyname"),
        // Display
        (selectedmonitors, "selectedmonitors"),
        (winposstr, "winposstr"),
        // Redirection
        (drivestoredirect, "drivestoredirect"),
        (usbdevicestoredirect, "usbdevicestoredirect"),
        (camerastoredirect, "camerastoredirect"),
        (devicestoredirect, "devicestoredirect"),
        // Gateway
        (gatewayhostname, "gatewayhostname"),
        // RemoteApp
        (remoteapplicationprogram, "remoteapplicationprogram"),
        (remoteapplicationname, "remoteapplicationname"),
        (remoteapplicationcmdline, "remoteapplicationcmdline"),
        (remoteapplicationfile, "remoteapplicationfile"),
        // Misc
        (alternate_shell, "alternate shell"),
        (shell_working_directory, "shell working directory"),
    ],
}

/// Write an i32 as decimal into a String (no_std friendly).
fn write_i32(out: &mut String, v: i32) {
    use core::fmt::Write;
    let _ = write!(out, "{v}");
}

impl RdpFile {
    /// Parse an `.rdp` file from a string.
    ///
    /// Lines are `key:type:value` with CRLF or LF endings.
    /// Duplicate keys: last wins. Unknown keys stored in `extra_entries`.
    /// A leading UTF-8 BOM is stripped if present.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        if input.len() > MAX_INPUT_SIZE {
            return Err(ParseError::InputTooLarge);
        }

        let input = strip_bom(input);
        let mut file = RdpFile::default();

        for (line_idx, raw_line) in input.split('\n').enumerate() {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            let line_number = line_idx + 1;

            if line_number > MAX_LINES {
                return Err(ParseError::TooManyLines { line_number });
            }
            if line.len() > MAX_LINE_LEN {
                return Err(ParseError::LineTooLong { line_number });
            }

            let (key, type_tag, _raw_type, value) =
                split_rdp_line(line).ok_or(ParseError::MalformedLine { line_number })?;

            if !KNOWN_TYPE_CHARS.contains(&type_tag) {
                return Err(ParseError::UnknownType { line_number, type_char: type_tag });
            }

            if type_tag == 'b' && !is_valid_hex(value) {
                return Err(ParseError::InvalidHex { line_number, value: String::from(value) });
            }

            let normalized_key: String = key.chars().map(|c| c.to_ascii_lowercase()).collect();

            match file.set_typed_field(&normalized_key, type_tag, value) {
                Ok(true) => {}
                Ok(false) => {
                    if file.extra_entries.len() >= MAX_EXTRA_ENTRIES {
                        return Err(ParseError::TooManyExtraEntries { line_number });
                    }
                    file.extra_entries.push(RdpEntry {
                        key: String::from(key),
                        type_char: type_tag,
                        value: String::from(value),
                    });
                }
                Err(()) => {
                    return Err(ParseError::InvalidInteger {
                        line_number,
                        value: String::from(value),
                    })
                }
            }
        }

        Ok(file)
    }

    /// Parse an `.rdp` file, skipping malformed lines silently.
    /// A leading UTF-8 BOM is stripped if present.
    /// Input size limits are still enforced; oversized input returns a default `RdpFile`.
    pub fn parse_lossy(input: &str) -> Self {
        if input.len() > MAX_INPUT_SIZE {
            return RdpFile::default();
        }

        let input = strip_bom(input);
        let mut file = RdpFile::default();
        let mut line_count = 0usize;

        for raw_line in input.split('\n') {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            line_count += 1;
            if line_count > MAX_LINES || line.len() > MAX_LINE_LEN {
                continue;
            }

            let Some((key, type_tag, _raw_type, value)) = split_rdp_line(line) else {
                continue;
            };

            if !KNOWN_TYPE_CHARS.contains(&type_tag) {
                continue;
            }

            if type_tag == 'b' && !is_valid_hex(value) {
                continue;
            }

            let normalized_key: String = key.chars().map(|c| c.to_ascii_lowercase()).collect();

            match file.set_typed_field(&normalized_key, type_tag, value) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(()) => continue,
            }

            if file.extra_entries.len() >= MAX_EXTRA_ENTRIES {
                continue;
            }

            file.extra_entries.push(RdpEntry {
                key: String::from(key),
                type_char: type_tag,
                value: String::from(value),
            });
        }

        file
    }

    /// Serialize to `.rdp` format string (CRLF line endings).
    ///
    /// Keys and values with embedded newlines are sanitized (newlines stripped).
    pub fn to_rdp_string(&self) -> String {
        let mut out = String::new();
        self.write_typed_fields(&mut out);

        for entry in &self.extra_entries {
            // Sanitize embedded newlines to prevent format injection.
            let clean_key = sanitize_line(&entry.key);
            let clean_value = sanitize_line(&entry.value);
            out.push_str(&clean_key);
            out.push(':');
            out.push(entry.type_char);
            out.push(':');
            out.push_str(&clean_value);
            out.push_str("\r\n");
        }

        out
    }
}

/// Strip CR/LF characters from a string to prevent line injection in output.
fn sanitize_line(s: &str) -> String {
    if s.bytes().any(|b| b == b'\r' || b == b'\n') {
        s.chars().filter(|&c| c != '\r' && c != '\n').collect()
    } else {
        String::from(s)
    }
}

impl fmt::Display for RdpFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rdp_string())
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let input = "full address:s:192.168.1.100\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.full_address.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn parse_integer() {
        let input = "desktopwidth:i:1920\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, Some(1920));
    }

    #[test]
    fn parse_negative_integer() {
        let input = "server port:i:-1\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.server_port, Some(-1));
    }

    #[test]
    fn parse_invalid_integer() {
        let input = "desktopwidth:i:abc\n";
        let result = RdpFile::parse(input);
        assert_eq!(
            result,
            Err(ParseError::InvalidInteger { line_number: 1, value: String::from("abc") })
        );
    }

    #[test]
    fn parse_string_with_colons() {
        let input = "alternate shell:s:C:\\Program Files\\App:arg1\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.alternate_shell.as_deref(), Some("C:\\Program Files\\App:arg1"));
    }

    #[test]
    fn parse_binary_hex() {
        let input = "password 51:b:AABBCCDD\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries.len(), 1);
        assert_eq!(rdp.extra_entries[0].value, "AABBCCDD");
    }

    #[test]
    fn parse_invalid_hex() {
        let input = "password 51:b:GGHHII\n";
        let result = RdpFile::parse(input);
        assert_eq!(
            result,
            Err(ParseError::InvalidHex { line_number: 1, value: String::from("GGHHII") })
        );
    }

    #[test]
    fn parse_odd_length_hex_rejected() {
        let input = "password 51:b:ABC\n";
        let result = RdpFile::parse(input);
        assert_eq!(
            result,
            Err(ParseError::InvalidHex { line_number: 1, value: String::from("ABC") })
        );
    }

    #[test]
    fn parse_empty_hex_accepted() {
        let input = "password 51:b:\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries[0].value, "");
    }

    #[test]
    fn parse_crlf() {
        let input = "full address:s:host\r\nusername:s:user\r\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.full_address.as_deref(), Some("host"));
        assert_eq!(rdp.username.as_deref(), Some("user"));
    }

    #[test]
    fn parse_blank_lines_skipped() {
        let input = "full address:s:host1\n\nfull address:s:host2\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.full_address.as_deref(), Some("host2")); // last wins
    }

    #[test]
    fn parse_malformed_line() {
        let input = "no-colons-here\n";
        let result = RdpFile::parse(input);
        assert_eq!(result, Err(ParseError::MalformedLine { line_number: 1 }));
    }

    #[test]
    fn parse_unknown_key_preserved() {
        let input = "customkey:i:42\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries.len(), 1);
        assert_eq!(rdp.extra_entries[0].key, "customkey");
        assert_eq!(rdp.extra_entries[0].type_char, 'i');
        assert_eq!(rdp.extra_entries[0].value, "42");
    }

    #[test]
    fn parse_unknown_type_rejected() {
        let input = "mykey:x:myval\n";
        let result = RdpFile::parse(input);
        assert_eq!(
            result,
            Err(ParseError::UnknownType { line_number: 1, type_char: 'x' })
        );
    }

    #[test]
    fn parse_lossy_unknown_type_skipped() {
        let input = "mykey:x:myval\nfull address:s:host\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.extra_entries.len(), 0);
        assert_eq!(rdp.full_address.as_deref(), Some("host"));
    }

    #[test]
    fn parse_case_insensitive_keys() {
        let input = "Full Address:s:host\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.full_address.as_deref(), Some("host"));
    }

    #[test]
    fn parse_case_insensitive_type() {
        let input = "desktopwidth:I:1920\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, Some(1920));
    }

    #[test]
    fn write_roundtrip() {
        let input = "full address:s:192.168.1.100\r\ndesktopwidth:i:1920\r\nusername:s:admin\r\n";
        let rdp = RdpFile::parse(input).unwrap();
        let output = rdp.to_rdp_string();
        let rdp2 = RdpFile::parse(&output).unwrap();
        assert_eq!(rdp.full_address, rdp2.full_address);
        assert_eq!(rdp.desktopwidth, rdp2.desktopwidth);
        assert_eq!(rdp.username, rdp2.username);
    }

    #[test]
    fn write_extra_entries_preserved() {
        let input = "customkey:s:myval\r\n";
        let rdp = RdpFile::parse(input).unwrap();
        let output = rdp.to_rdp_string();
        assert!(output.contains("customkey:s:myval\r\n"));
    }

    #[test]
    fn parse_lossy_skips_malformed() {
        let input = "full address:s:host\nbadline\ndesktopwidth:i:1920\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.full_address.as_deref(), Some("host"));
        assert_eq!(rdp.desktopwidth, Some(1920));
    }

    #[test]
    fn parse_empty_string_value() {
        let input = "drivestoredirect:s:\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.drivestoredirect.as_deref(), Some(""));
    }

    #[test]
    fn parse_mstsc_style_file() {
        let input = "\
screen mode id:i:2\r\n\
desktopwidth:i:1920\r\n\
desktopheight:i:1080\r\n\
session bpp:i:32\r\n\
full address:s:192.168.1.100\r\n\
authentication level:i:2\r\n\
redirectclipboard:i:1\r\n\
alternate shell:s:\r\n\
shell working directory:s:\r\n\
";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.screen_mode_id, Some(2));
        assert_eq!(rdp.desktopwidth, Some(1920));
        assert_eq!(rdp.desktopheight, Some(1080));
        assert_eq!(rdp.session_bpp, Some(32));
        assert_eq!(rdp.full_address.as_deref(), Some("192.168.1.100"));
        assert_eq!(rdp.authentication_level, Some(2));
        assert_eq!(rdp.redirectclipboard, Some(1));
        assert_eq!(rdp.alternate_shell.as_deref(), Some(""));
        assert_eq!(rdp.shell_working_directory.as_deref(), Some(""));
    }

    #[test]
    fn display_impl() {
        let mut rdp = RdpFile::default();
        rdp.full_address = Some(String::from("host"));
        let s = alloc::format!("{rdp}");
        assert!(s.contains("full address:s:host\r\n"));
    }

    // ── Boundary / gap tests ──

    #[test]
    fn parse_integer_i32_max() {
        let input = "desktopwidth:i:2147483647\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, Some(i32::MAX));
    }

    #[test]
    fn parse_integer_i32_overflow() {
        let input = "desktopwidth:i:2147483648\n";
        assert_eq!(
            RdpFile::parse(input),
            Err(ParseError::InvalidInteger { line_number: 1, value: String::from("2147483648") })
        );
    }

    #[test]
    fn parse_known_key_wrong_type_goes_to_extra() {
        let input = "desktopwidth:s:1920\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, None);
        assert_eq!(rdp.extra_entries.len(), 1);
        assert_eq!(rdp.extra_entries[0].key, "desktopwidth");
    }

    #[test]
    fn parse_duplicate_integer_last_wins() {
        let input = "desktopwidth:i:800\r\ndesktopwidth:i:1920\r\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, Some(1920));
    }

    #[test]
    fn parse_lossy_invalid_integer_skipped() {
        let input = "desktopwidth:i:notanumber\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.desktopwidth, None);
        assert_eq!(rdp.extra_entries.len(), 0);
    }

    #[test]
    fn parse_lossy_invalid_hex_skipped() {
        let input = "password 51:b:GGZZ\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.extra_entries.len(), 0);
    }

    #[test]
    fn parse_lossy_odd_hex_skipped() {
        let input = "password 51:b:ABC\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.extra_entries.len(), 0);
    }

    #[test]
    fn parse_error_line_number() {
        let input = "full address:s:host\nbadline\n";
        let err = RdpFile::parse(input).unwrap_err();
        assert_eq!(err, ParseError::MalformedLine { line_number: 2 });
    }

    #[test]
    fn parse_empty_input() {
        let rdp = RdpFile::parse("").unwrap();
        assert_eq!(rdp, RdpFile::default());
    }

    // ── New tests: BOM, size limits, type normalization, duplicate unknown keys, output sanitization ──

    #[test]
    fn parse_utf8_bom_stripped() {
        let input = "\u{FEFF}full address:s:host\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.full_address.as_deref(), Some("host"));
    }

    #[test]
    fn parse_lossy_utf8_bom_stripped() {
        let input = "\u{FEFF}desktopwidth:i:1920\n";
        let rdp = RdpFile::parse_lossy(input);
        assert_eq!(rdp.desktopwidth, Some(1920));
    }

    #[test]
    fn parse_input_too_large() {
        let input = "a".repeat(MAX_INPUT_SIZE + 1);
        assert_eq!(RdpFile::parse(&input), Err(ParseError::InputTooLarge));
    }

    #[test]
    fn parse_lossy_input_too_large_returns_default() {
        let input = "a".repeat(MAX_INPUT_SIZE + 1);
        assert_eq!(RdpFile::parse_lossy(&input), RdpFile::default());
    }

    #[test]
    fn parse_extra_entries_capped() {
        let mut lines = String::new();
        for i in 0..=MAX_EXTRA_ENTRIES {
            lines.push_str(&alloc::format!("unknown{i}:s:val\n"));
        }
        let result = RdpFile::parse(&lines);
        assert!(matches!(result, Err(ParseError::TooManyExtraEntries { .. })));
    }

    #[test]
    fn parse_lossy_extra_entries_capped() {
        let mut lines = String::new();
        for i in 0..MAX_EXTRA_ENTRIES + 10 {
            lines.push_str(&alloc::format!("unknown{i}:s:val\n"));
        }
        let rdp = RdpFile::parse_lossy(&lines);
        assert_eq!(rdp.extra_entries.len(), MAX_EXTRA_ENTRIES);
    }

    #[test]
    fn parse_uppercase_type_normalized_in_extra() {
        let input = "customkey:I:42\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries[0].type_char, 'i'); // normalized
    }

    #[test]
    fn extra_entries_type_char_roundtrip() {
        let input = "customkey:B:AABB\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries[0].type_char, 'b');
        let output = rdp.to_rdp_string();
        let rdp2 = RdpFile::parse(&output).unwrap();
        assert_eq!(rdp2.extra_entries[0].type_char, rdp.extra_entries[0].type_char);
    }

    #[test]
    fn parse_duplicate_unknown_key_both_preserved() {
        let input = "customkey:s:val1\ncustomkey:s:val2\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries.len(), 2);
        assert_eq!(rdp.extra_entries[0].value, "val1");
        assert_eq!(rdp.extra_entries[1].value, "val2");
    }

    #[test]
    fn to_rdp_string_sanitizes_newlines_in_extra_entries() {
        let mut rdp = RdpFile::default();
        rdp.extra_entries.push(RdpEntry {
            key: String::from("evil"),
            type_char: 's',
            value: String::from("val\r\ninjected:i:1"),
        });
        let output = rdp.to_rdp_string();
        // Newlines must be stripped — output should be a single line
        assert_eq!(output.matches('\n').count(), 1); // only the trailing CRLF
        assert!(output.contains("evil:s:valinjected:i:1\r\n"));
    }

    #[test]
    fn to_rdp_string_sanitizes_newlines_in_key() {
        let mut rdp = RdpFile::default();
        rdp.extra_entries.push(RdpEntry {
            key: String::from("bad\nkey"),
            type_char: 's',
            value: String::from("val"),
        });
        let output = rdp.to_rdp_string();
        assert!(output.contains("badkey:s:val\r\n"));
    }
}

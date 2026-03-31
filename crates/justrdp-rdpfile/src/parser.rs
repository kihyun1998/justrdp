#![forbid(unsafe_code)]

//! `.rdp` file parser and writer.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ── Error ──

/// Parse error for `.rdp` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MalformedLine { line_number: usize },
    InvalidInteger { line_number: usize },
    InvalidHex { line_number: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedLine { line_number } => write!(f, "malformed line at {line_number}"),
            Self::InvalidInteger { line_number } => write!(f, "invalid integer at {line_number}"),
            Self::InvalidHex { line_number } => write!(f, "invalid hex at {line_number}"),
        }
    }
}

// ── Entry ──

/// A single raw entry from an `.rdp` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpEntry {
    pub key: String,
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
            fn set_typed_field(&mut self, key_lower: &str, type_char: char, value: &str, line_number: usize) -> Result<bool, ParseError> {
                match (key_lower, type_char) {
                    $(
                        ($i_key, 'i') => {
                            let v = value.trim().parse::<i32>().map_err(|_| ParseError::InvalidInteger { line_number })?;
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
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut file = RdpFile::default();

        for (line_idx, raw_line) in input.split('\n').enumerate() {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            let line_number = line_idx + 1;

            // Find first colon
            let first_colon = match line.find(':') {
                Some(pos) => pos,
                None => return Err(ParseError::MalformedLine { line_number }),
            };

            // Find second colon
            let rest = &line[first_colon + 1..];
            let second_colon = match rest.find(':') {
                Some(pos) => first_colon + 1 + pos,
                None => return Err(ParseError::MalformedLine { line_number }),
            };

            let key = line[..first_colon].trim();
            let type_str = line[first_colon + 1..second_colon].trim();
            let value = &line[second_colon + 1..];

            if type_str.len() != 1 {
                return Err(ParseError::MalformedLine { line_number });
            }

            let type_char = type_str.chars().next().unwrap();
            let type_lower = match type_char {
                'I' => 'i',
                'S' => 's',
                'B' => 'b',
                c => c,
            };

            // Validate binary type
            if type_lower == 'b' {
                if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ParseError::InvalidHex { line_number });
                }
            }

            let key_lower: String = key.chars().map(|c| c.to_ascii_lowercase()).collect();

            // Try to set a typed field
            let matched = file.set_typed_field(&key_lower, type_lower, value, line_number)?;

            if !matched {
                file.extra_entries.push(RdpEntry {
                    key: String::from(key),
                    type_char,
                    value: String::from(value),
                });
            }
        }

        Ok(file)
    }

    /// Parse an `.rdp` file, skipping malformed lines silently.
    pub fn parse_lossy(input: &str) -> Self {
        let mut file = RdpFile::default();

        for raw_line in input.split('\n') {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            let first_colon = match line.find(':') {
                Some(pos) => pos,
                None => continue,
            };
            let rest = &line[first_colon + 1..];
            let second_colon = match rest.find(':') {
                Some(pos) => first_colon + 1 + pos,
                None => continue,
            };

            let key = line[..first_colon].trim();
            let type_str = line[first_colon + 1..second_colon].trim();
            let value = &line[second_colon + 1..];

            if type_str.len() != 1 {
                continue;
            }

            let type_char = type_str.chars().next().unwrap();
            let type_lower = match type_char {
                'I' => 'i', 'S' => 's', 'B' => 'b', c => c,
            };

            // Validate hex for binary type
            if type_lower == 'b' && !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue; // skip invalid hex in lossy mode
            }

            let key_lower: String = key.chars().map(|c| c.to_ascii_lowercase()).collect();

            match file.set_typed_field(&key_lower, type_lower, value, 0) {
                Ok(true) => continue,  // matched typed field
                Ok(false) => {}        // unmatched → goes to extra_entries
                Err(_) => continue,    // invalid value (e.g. bad integer) → skip
            }

            file.extra_entries.push(RdpEntry {
                key: String::from(key),
                type_char,
                value: String::from(value),
            });
        }

        file
    }

    /// Serialize to `.rdp` format string (CRLF line endings).
    pub fn to_rdp_string(&self) -> String {
        let mut out = String::new();
        self.write_typed_fields(&mut out);

        for entry in &self.extra_entries {
            out.push_str(&entry.key);
            out.push(':');
            out.push(entry.type_char);
            out.push(':');
            out.push_str(&entry.value);
            out.push_str("\r\n");
        }

        out
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
        assert_eq!(result, Err(ParseError::InvalidInteger { line_number: 1 }));
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
        assert_eq!(result, Err(ParseError::InvalidHex { line_number: 1 }));
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
    fn parse_unknown_type_preserved() {
        let input = "mykey:x:myval\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.extra_entries[0].type_char, 'x');
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
        let input = "customkey:x:myval\r\n";
        let rdp = RdpFile::parse(input).unwrap();
        let output = rdp.to_rdp_string();
        assert!(output.contains("customkey:x:myval\r\n"));
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

    // ── Gap tests ──

    #[test]
    fn parse_integer_i32_max() {
        let input = "desktopwidth:i:2147483647\n";
        let rdp = RdpFile::parse(input).unwrap();
        assert_eq!(rdp.desktopwidth, Some(i32::MAX));
    }

    #[test]
    fn parse_integer_i32_overflow() {
        let input = "desktopwidth:i:2147483648\n";
        assert_eq!(RdpFile::parse(input), Err(ParseError::InvalidInteger { line_number: 1 }));
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
        // Invalid integer on known key: skipped entirely in lossy mode
        assert_eq!(rdp.extra_entries.len(), 0);
    }

    #[test]
    fn parse_lossy_invalid_hex_skipped() {
        let input = "password 51:b:GGZZ\n";
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
}

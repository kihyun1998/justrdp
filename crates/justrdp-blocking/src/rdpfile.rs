//! Synchronous helpers for loading `.rdp` files from disk.
//!
//! The no-I/O mapping lives in
//! [`justrdp_connector::rdpfile`](justrdp_connector::rdpfile); this
//! module layers a single `std::fs` + `std::path::Path` glue function
//! on top so callers don't have to repeat the read → parse → extract
//! → build sequence themselves.

use std::path::Path;

use justrdp_connector::rdpfile::server_address;
use justrdp_connector::Config;
use justrdp_rdpfile::{ParseError, RdpFile};

/// Errors raised by [`load_rdp_file`] / [`rdp_file_config`].
#[derive(Debug)]
pub enum RdpFileError {
    /// OS-level I/O failure while opening or reading the file.
    Io(std::io::Error),
    /// The file contents failed to parse as an `.rdp` key/type/value document.
    Parse(ParseError),
    /// The file parsed successfully but carries no `full address` entry, so
    /// there is no server to connect to.
    MissingServerAddress,
}

impl core::fmt::Display for RdpFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error reading .rdp file: {e}"),
            Self::Parse(e) => write!(f, ".rdp parse error: {e:?}"),
            Self::MissingServerAddress => f.write_str(".rdp file has no `full address` entry"),
        }
    }
}

impl std::error::Error for RdpFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RdpFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ParseError> for RdpFileError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

/// Read and parse an `.rdp` file from disk without applying it.
///
/// Use this when you want to inspect individual fields before handing
/// them off to a [`Config`] — e.g. to prompt the user to confirm the
/// target server. For the common "just connect me" path prefer
/// [`rdp_file_config`] which produces everything the runtime needs.
pub fn load_rdp_file(path: impl AsRef<Path>) -> Result<RdpFile, RdpFileError> {
    let contents = std::fs::read_to_string(path)?;
    Ok(RdpFile::parse(&contents)?)
}

/// Server + port + [`Config`] bundle produced from a parsed `.rdp` file.
///
/// Pass `address` directly to
/// [`RdpClient::connect`](crate::RdpClient::connect) (it implements
/// `ToSocketAddrs`), pass `hostname` as the TLS SNI name, and move
/// `config` in as the third argument.
#[derive(Debug)]
pub struct RdpFileConfig {
    /// `host:port` string suitable for TCP connect. Derived from the
    /// `full address` field and either an embedded port or the
    /// `server port` entry, falling back to `3389`.
    pub address: String,
    /// Bare host portion of `address`, without brackets or port. Use
    /// this as the TLS server name.
    pub hostname: String,
    /// Resolved TCP port.
    pub port: u16,
    /// Connector configuration with all mapped `.rdp` fields applied
    /// on top of the builder defaults.
    pub config: Config,
}

/// Load an `.rdp` file from `path` and produce an [`RdpFileConfig`]
/// ready to feed [`RdpClient::connect`](crate::RdpClient::connect).
///
/// `username` and `password` are passed through to
/// [`Config::builder`] unchanged — the `.rdp` file's own `username`
/// field is ignored because it cannot carry a password and mixing the
/// two sources creates an ambiguous precedence story. Callers who
/// want the file's username should extract it from the parsed
/// [`RdpFile`] via [`load_rdp_file`] first.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let bundle = justrdp_blocking::rdpfile::rdp_file_config(
///     "session.rdp",
///     "alice",
///     "hunter2",
/// )?;
/// let client = justrdp_blocking::RdpClient::connect(
///     bundle.address.as_str(),
///     &bundle.hostname,
///     bundle.config,
/// )?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
pub fn rdp_file_config(
    path: impl AsRef<Path>,
    username: &str,
    password: &str,
) -> Result<RdpFileConfig, RdpFileError> {
    let file = load_rdp_file(path)?;
    rdp_file_config_from_parsed(&file, username, password)
}

/// Build an [`RdpFileConfig`] from an already-parsed [`RdpFile`].
///
/// Split out from [`rdp_file_config`] so callers who already hold a
/// parsed file (e.g. after inspecting fields for a confirmation
/// prompt) don't have to read the file twice.
pub fn rdp_file_config_from_parsed(
    file: &RdpFile,
    username: &str,
    password: &str,
) -> Result<RdpFileConfig, RdpFileError> {
    let (hostname, port) = server_address(file).ok_or(RdpFileError::MissingServerAddress)?;
    let address = format!("{hostname}:{port}");
    let config = Config::builder(username, password).apply_rdp_file(file).build();
    Ok(RdpFileConfig { address, hostname, port, config })
}

// Re-export the parser types so callers don't need to add
// `justrdp-rdpfile` to their own Cargo.toml just to name `RdpFile`.
pub use justrdp_rdpfile::{ParseError as RdpFileParseError, RdpFile as ParsedRdpFile};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Per-test unique temp file path — no `tempfile` crate dep so the
    // runtime only pulls in what the library uses in production.
    fn temp_rdp_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "justrdp-blocking-test-{}-{}-{}.rdp",
            tag,
            std::process::id(),
            n,
        ))
    }

    fn write_rdp(tag: &str, contents: &str) -> PathBuf {
        let path = temp_rdp_path(tag);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn end_to_end_from_file() {
        let path = write_rdp(
            "e2e",
            "full address:s:rds.example.com:3390\r\n\
             domain:s:CORP\r\n\
             desktopwidth:i:1600\r\n\
             desktopheight:i:900\r\n\
             session bpp:i:32\r\n\
             compression:i:1\r\n",
        );
        let bundle = rdp_file_config(&path, "alice", "pw").unwrap();
        assert_eq!(bundle.hostname, "rds.example.com");
        assert_eq!(bundle.port, 3390);
        assert_eq!(bundle.address, "rds.example.com:3390");
        assert_eq!(bundle.config.domain.as_deref(), Some("CORP"));
        assert_eq!(bundle.config.desktop_size.width, 1600);
        assert_eq!(bundle.config.desktop_size.height, 900);
        assert!(bundle.config.compression.enabled);
        assert_eq!(bundle.config.credentials.username, "alice");
        assert_eq!(bundle.config.credentials.password, "pw");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_full_address_is_reported() {
        let path = write_rdp("nofull", "domain:s:CORP\r\n");
        let err = rdp_file_config(&path, "u", "p").unwrap_err();
        assert!(matches!(err, RdpFileError::MissingServerAddress));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn nonexistent_file_is_io_error() {
        let ghost = std::env::temp_dir().join("justrdp-blocking-does-not-exist-xyz.rdp");
        let err = rdp_file_config(&ghost, "u", "p").unwrap_err();
        assert!(matches!(err, RdpFileError::Io(_)));
    }

    #[test]
    fn oversized_file_is_parse_error() {
        // MAX_INPUT_SIZE in the parser rejects inputs larger than ~256 KiB,
        // so a 2 MiB blob is guaranteed to fail at parse time.
        let big = "x".repeat(2 * 1024 * 1024);
        let path = write_rdp("oversize", &big);
        let err = rdp_file_config(&path, "u", "p").unwrap_err();
        assert!(matches!(err, RdpFileError::Parse(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn username_from_builder_wins_over_file() {
        let path = write_rdp(
            "usernamewin",
            "full address:s:rds.example.com\r\n\
             username:s:bob\r\n",
        );
        let bundle = rdp_file_config(&path, "alice", "pw").unwrap();
        assert_eq!(bundle.config.credentials.username, "alice");
        let _ = std::fs::remove_file(&path);
    }
}

//! Client for symbol servers that speak the Microsoft symbol store protocol.
//!
//! A PDB lives at `<server>/<pdb name>/<GUID><age>/<pdb name>`. Microsoft's
//! public server answers with a redirect to blob storage when it has the file
//! and with 404 when it does not.

use std::collections::HashMap;
use std::error::Error as _;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use reqwest::blocking::{Client, Response};
use reqwest::{Method, StatusCode};

use crate::pdb;
use crate::pe::CodeView;

const USER_AGENT: &str = concat!("pdbwalker/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Applies to waiting for response headers and to each read of a body, not to
/// a whole transfer, so large PDBs are fine as long as data keeps flowing.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(300);
const COPY_BUFFER_LEN: usize = 128 * 1024;

/// Result of asking the server for a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    Found(T),
    /// The server answered and does not have the file.
    Missing,
    /// The question could not be settled (network trouble, unexpected status, I/O error).
    Failed(String),
}

pub struct SymbolServer {
    client: Client,
    /// What this run has learned about each URL.
    ///
    /// Many binaries share one PDB (think of runtime DLLs shipped with every
    /// application). A URL's slot stays locked while the server is asked
    /// about it, so concurrent tasks wait for one request instead of each
    /// sending their own.
    known: Mutex<HashMap<String, Slot>>,
}

type Slot = Arc<Mutex<Option<Known>>>;

/// A settled fact about a URL. Failures are not remembered.
enum Known {
    Available,
    Missing,
    /// Already downloaded to this path, which later requests can copy.
    Saved(PathBuf),
}

impl SymbolServer {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(IO_TIMEOUT)
            .build()
            .context("failed to initialise the HTTP client")?;
        Ok(Self {
            client,
            known: Mutex::default(),
        })
    }

    /// Asks whether `url` exists without transferring it.
    pub fn probe(&self, url: &str) -> Lookup<()> {
        let slot = self.slot(url);
        let mut known = lock(&slot);
        match *known {
            Some(Known::Available | Known::Saved(_)) => return Lookup::Found(()),
            Some(Known::Missing) => return Lookup::Missing,
            None => {}
        }
        match self.send(&Method::HEAD, url) {
            Ok(_) => {
                *known = Some(Known::Available);
                Lookup::Found(())
            }
            Err(Miss::NotFound) => {
                *known = Some(Known::Missing);
                Lookup::Missing
            }
            Err(Miss::Failed(reason)) => Lookup::Failed(reason),
        }
    }

    /// Downloads `url` to `dest`, returning the number of bytes written.
    ///
    /// The body is streamed to a temporary sibling of `dest` and renamed into
    /// place once complete, so `dest` is never left half-written. Responses
    /// that are not PDB files are rejected. A URL that was already downloaded
    /// during this run is copied from the earlier destination instead.
    pub fn download(&self, url: &str, dest: &Path) -> Lookup<u64> {
        let slot = self.slot(url);
        let mut known = lock(&slot);
        match &*known {
            Some(Known::Missing) => return Lookup::Missing,
            Some(Known::Saved(source)) => {
                // If the copy fails, a fresh download reports what is wrong.
                if let Ok(len) = copy_into_place(source, dest) {
                    return Lookup::Found(len);
                }
            }
            Some(Known::Available) | None => {}
        }

        let response = match self.send(&Method::GET, url) {
            Ok(response) => response,
            Err(Miss::NotFound) => {
                *known = Some(Known::Missing);
                return Lookup::Missing;
            }
            Err(Miss::Failed(reason)) => return Lookup::Failed(reason),
        };
        match save(response, dest) {
            Ok(len) => {
                *known = Some(Known::Saved(dest.to_owned()));
                Lookup::Found(len)
            }
            Err(err) => Lookup::Failed(err.to_string()),
        }
    }

    fn slot(&self, url: &str) -> Slot {
        Arc::clone(lock(&self.known).entry(url.to_owned()).or_default())
    }

    /// Sends a request, retrying transient failures, and returns the
    /// response if the server answered with success.
    fn send(&self, method: &Method, url: &str) -> Result<Response, Miss> {
        let mut delay = RETRY_DELAY;
        let mut attempt = 1;
        loop {
            let failure = match self.client.request(method.clone(), url).send() {
                Ok(response) => match response.status() {
                    status if status.is_success() => return Ok(response),
                    StatusCode::NOT_FOUND | StatusCode::GONE => return Err(Miss::NotFound),
                    status if is_transient(status) => format!("server answered {status}"),
                    status => return Err(Miss::Failed(format!("server answered {status}"))),
                },
                Err(err) if err.is_connect() || err.is_timeout() => describe(&err),
                Err(err) => return Err(Miss::Failed(describe(&err))),
            };
            if attempt == ATTEMPTS {
                return Err(Miss::Failed(failure));
            }
            thread::sleep(delay);
            delay *= 2;
            attempt += 1;
        }
    }
}

/// Why a request produced no usable response.
enum Miss {
    NotFound,
    Failed(String),
}

/// Locks a mutex, ignoring poisoning: the guarded maps stay consistent even
/// if a thread panicked while holding the lock.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Validates a symbol server base URL and strips trailing slashes.
pub fn normalize_base(base: &str) -> Result<&str> {
    let base = base.trim().trim_end_matches('/');
    ensure!(
        base.starts_with("https://") || base.starts_with("http://"),
        "symbol server must be an http(s) URL, got `{base}`"
    );
    Ok(base)
}

/// Builds the download URL of the PDB that `codeview` refers to.
pub fn pdb_url(base: &str, codeview: &CodeView) -> String {
    let name = percent_encode(codeview.pdb_file_name());
    format!("{base}/{name}/{}/{name}", codeview.symbol_key())
}

fn is_transient(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Flattens an error and its causes into one line, without the request URL.
fn describe(err: &reqwest::Error) -> String {
    let mut message = if err.is_timeout() {
        "request timed out".to_owned()
    } else if err.is_connect() {
        "connection failed".to_owned()
    } else {
        "request failed".to_owned()
    };
    let mut source = err.source();
    while let Some(cause) = source {
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
    message
}

fn save(mut body: Response, dest: &Path) -> io::Result<u64> {
    write_into_place(dest, |partial| write_body(&mut body, partial))
}

fn copy_into_place(source: &Path, dest: &Path) -> io::Result<u64> {
    write_into_place(dest, |partial| fs::copy(source, partial))
}

/// Has `write` produce a temporary sibling of `dest`, then renames it into
/// place. On failure nothing is left behind and `dest` is untouched.
fn write_into_place(dest: &Path, write: impl FnOnce(&Path) -> io::Result<u64>) -> io::Result<u64> {
    let partial = partial_path(dest);
    let result = write(&partial).and_then(|len| {
        fs::rename(&partial, dest)?;
        Ok(len)
    });
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

/// `dir/foo.pdb` -> `dir/.foo.pdb.<pid>.part`
fn partial_path(dest: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(dest.file_name().unwrap_or_default());
    name.push(format!(".{}.part", std::process::id()));
    dest.with_file_name(name)
}

fn write_body(body: &mut Response, path: &Path) -> io::Result<u64> {
    let expected = body.content_length();
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];

    // Look at the start of the body before creating anything on disk.
    let mut filled = 0;
    while filled < pdb::MAGIC_LEN {
        match body.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    if !pdb::has_pdb_magic(&buffer[..filled]) {
        let hint = if buffer[..filled].starts_with(b"MSCF") {
            " (compressed symbol files are not supported)"
        } else {
            ""
        };
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("server did not return a PDB file{hint}"),
        ));
    }

    let mut file = File::create(path)?;
    let mut written = 0u64;
    while filled > 0 {
        file.write_all(&buffer[..filled])?;
        written += filled as u64;
        filled = body.read(&mut buffer)?;
    }
    if expected.is_some_and(|expected| expected != written) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "download ended before the whole file arrived",
        ));
    }
    Ok(written)
}

/// Percent-encodes everything outside RFC 3986's unreserved set.
fn percent_encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{Guid, PdbId};

    fn codeview(pdb_path: &str) -> CodeView {
        CodeView {
            id: PdbId::Guid(Guid([
                0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])),
            age: 10,
            pdb_path: pdb_path.to_owned(),
        }
    }

    #[test]
    fn builds_symbol_store_urls() {
        assert_eq!(
            pdb_url("https://example.test/symbols", &codeview(r"d:\a\ntdll.pdb")),
            "https://example.test/symbols/ntdll.pdb/0123456789ABCDEF0123456789ABCDEFA/ntdll.pdb"
        );
    }

    #[test]
    fn encodes_unusual_file_names() {
        assert_eq!(
            pdb_url("http://s", &codeview("my app#1.pdb")),
            "http://s/my%20app%231.pdb/0123456789ABCDEF0123456789ABCDEFA/my%20app%231.pdb"
        );
    }

    #[test]
    fn normalizes_base_urls() {
        let normalized = normalize_base(" https://s/symbols// ").unwrap();
        assert_eq!(normalized, "https://s/symbols");
        assert!(normalize_base("ftp://s").is_err());
        assert!(normalize_base("msdl.microsoft.com").is_err());
    }

    #[test]
    fn partial_files_are_hidden_siblings() {
        let partial = partial_path(Path::new("dir/foo.pdb"));
        assert_eq!(partial.parent(), Some(Path::new("dir")));
        let name = partial.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".foo.pdb."), "{name}");
        assert!(name.ends_with(".part"), "{name}");
    }
}

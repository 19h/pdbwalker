//! End-to-end tests: the real binary against a local mock symbol server.

mod support;

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use support::PeSpec;
use tempfile::TempDir;

const GUID_A: [u8; 16] = [
    0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];
const KEY_A: &str = "0123456789ABCDEF0123456789ABCDEF2";
const GUID_B: [u8; 16] = [0x11; 16];
const KEY_B: &str = "111111111111111111111111111111111";

enum Route {
    Body(Vec<u8>),
    Redirect(&'static str),
    Status(u16),
}

/// A throwaway HTTP/1.1 server that records every request it receives.
struct MockServer {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn start(routes: Vec<(String, Route)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/symbols", listener.local_addr().unwrap());
        let routes: Arc<HashMap<String, Route>> = Arc::new(routes.into_iter().collect());
        let requests = Arc::new(Mutex::new(Vec::new()));

        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (routes, log) = (Arc::clone(&routes), Arc::clone(&log));
                thread::spawn(move || serve(stream, &routes, &log));
            }
        });
        Self { base, requests }
    }

    /// Requests seen so far, as `METHOD /path`, sorted for stable assertions.
    fn requests(&self) -> Vec<String> {
        let mut requests = self.requests.lock().unwrap().clone();
        requests.sort();
        requests
    }

    fn count(&self, method: &str) -> usize {
        self.requests()
            .iter()
            .filter(|request| request.starts_with(method))
            .count()
    }
}

fn serve(mut stream: TcpStream, routes: &HashMap<String, Route>, log: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut header = String::new();
    while reader.read_line(&mut header).unwrap_or(0) > 2 {
        header.clear();
    }

    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    log.lock().unwrap().push(format!("{method} {path}"));

    let (status, extra, body): (u16, String, &[u8]) = match routes.get(path) {
        Some(Route::Body(body)) => (200, String::new(), body),
        Some(Route::Redirect(to)) => (302, format!("Location: {to}\r\n"), b""),
        Some(Route::Status(status)) => (*status, String::new(), b""),
        None => (404, String::new(), b""),
    };
    let head = format!(
        "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    if method != "HEAD" {
        let _ = stream.write_all(body);
    }
}

fn symbol_path(pdb_name: &str, key: &str) -> String {
    format!("/symbols/{pdb_name}/{key}/{pdb_name}")
}

fn pe(guid: [u8; 16], age: u32, pdb: &'static str) -> Vec<u8> {
    support::pe_image(&PeSpec {
        pdb: Some((guid, age, pdb)),
        ..PeSpec::default()
    })
}

/// A directory with three binaries:
/// - `tool.exe`, built from `internal.pdb` (GUID A), which the server has;
/// - `lib/helper.dll`, built from `helper.pdb` (GUID B), which it lacks;
/// - `plain.exe`, without debug information.
fn fixture() -> (TempDir, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("lib")).unwrap();
    fs::write(
        dir.path().join("tool.exe"),
        pe(GUID_A, 2, r"C:\build\out\internal.pdb"),
    )
    .unwrap();
    fs::write(
        dir.path().join("lib/helper.dll"),
        pe(GUID_B, 1, "helper.pdb"),
    )
    .unwrap();
    fs::write(
        dir.path().join("plain.exe"),
        support::pe_image(&PeSpec::default()),
    )
    .unwrap();
    (dir, support::msf_pdb(GUID_A, 2))
}

/// Serves `pdb` for `tool.exe` the way Microsoft does: through a redirect.
fn server_with(pdb: &[u8]) -> MockServer {
    MockServer::start(vec![
        (
            symbol_path("internal.pdb", KEY_A),
            Route::Redirect("/blob/internal"),
        ),
        ("/blob/internal".to_owned(), Route::Body(pdb.to_vec())),
    ])
}

fn pdbwalker(server: &MockServer, args: &[&str], target: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pdbwalker"))
        .args(["--symbol-server", &server.base])
        .args(args)
        .arg(target)
        .env("NO_PROXY", "127.0.0.1")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// Parses JSON Lines output into records keyed by file name.
fn json_records(output: &Output) -> HashMap<String, Value> {
    stdout(output)
        .lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            let path = record["file_path"].as_str().unwrap().to_owned();
            let name = Path::new(&path).file_name().unwrap().to_str().unwrap();
            (name.to_owned(), record)
        })
        .collect()
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = walk(dir)
        .into_iter()
        .map(|path| {
            path.strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    names.sort();
    names
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .flat_map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

const ORIGINAL_FILES: [&str; 3] = ["lib/helper.dll", "plain.exe", "tool.exe"];

#[test]
fn plain_scan_reports_every_binary_without_touching_the_network() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = pdbwalker(&server, &["--json"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    let tool = &records["tool.exe"];
    assert_eq!(tool["architecture"], "x64");
    assert_eq!(tool["is_dll"], false);
    assert_eq!(tool["local_pdb"]["available"], false);
    assert_eq!(tool["remote_pdb"]["has_info"], true);
    assert_eq!(tool["remote_pdb"]["available"], Value::Null);
    assert_eq!(tool["remote_pdb"]["info"]["file_name"], "internal.pdb");
    assert_eq!(tool["remote_pdb"]["info"]["signature"], KEY_A);
    assert_eq!(
        tool["remote_pdb"]["info"]["url"],
        format!("{}/internal.pdb/{KEY_A}/internal.pdb", server.base)
    );
    assert_eq!(records["plain.exe"]["remote_pdb"]["has_info"], false);
    assert!(tool.get("download").is_none());

    assert!(server.requests().is_empty());
}

#[test]
fn search_lists_only_binaries_whose_pdb_the_server_has() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = pdbwalker(&server, &["--search", "--json"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    let records = json_records(&output);
    assert_eq!(records.keys().collect::<Vec<_>>(), ["tool.exe"]);
    assert_eq!(records["tool.exe"]["remote_pdb"]["available"], true);

    // Searching only asks; it neither downloads nor writes anything.
    assert_eq!(server.count("GET"), 0);
    assert_eq!(
        server.requests(),
        [
            "HEAD /blob/internal".to_owned(),
            format!("HEAD {}", symbol_path("helper.pdb", KEY_B)),
            format!("HEAD {}", symbol_path("internal.pdb", KEY_A)),
        ]
    );
    assert_eq!(file_names(dir.path()), ORIGINAL_FILES);
}

#[test]
fn download_stores_the_pdb_next_to_its_binary_under_the_binary_name() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = pdbwalker(&server, &["--download", "--json"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    // tool.exe -> tool.pdb, even though the debug record calls it internal.pdb.
    assert_eq!(fs::read(dir.path().join("tool.pdb")).unwrap(), pdb);
    assert_eq!(
        file_names(dir.path()),
        ["lib/helper.dll", "plain.exe", "tool.exe", "tool.pdb"]
    );

    let records = json_records(&output);
    let tool = &records["tool.exe"];
    assert_eq!(tool["download"]["status"], "downloaded");
    assert_eq!(tool["download"]["bytes"], pdb.len());
    assert_eq!(tool["local_pdb"]["available"], true);
    assert_eq!(tool["local_pdb"]["matches"], true);
    assert_eq!(tool["remote_pdb"]["available"], true);
    assert_eq!(records["helper.dll"]["download"]["status"], "not_found");
    assert_eq!(records["helper.dll"]["remote_pdb"]["available"], false);
    assert_eq!(records["plain.exe"]["download"]["status"], "no_debug_info");

    // One GET per candidate is enough: no separate existence check.
    assert_eq!(server.count("HEAD"), 0);

    // A second run finds the PDB in place, verifies it and leaves the server alone.
    let before = server.requests().len();
    let output = pdbwalker(&server, &["--download", "--json"], dir.path());
    assert!(output.status.success());
    let records = json_records(&output);
    assert_eq!(records["tool.exe"]["download"]["status"], "exists");
    assert_eq!(records["tool.exe"]["local_pdb"]["matches"], true);
    let new_requests = &server.requests()[..];
    assert_eq!(new_requests.len(), before + 1, "{new_requests:?}");
}

#[test]
fn search_and_download_combine() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = pdbwalker(&server, &["--search", "--download"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    let text = stdout(&output);
    assert!(text.contains("tool.exe"), "{text}");
    assert!(text.contains("downloaded tool.pdb"), "{text}");
    assert!(!text.contains("helper.dll"), "{text}");
    assert!(!text.contains("plain.exe"), "{text}");
    assert!(text.contains("1 (of 3 scanned)"), "{text}");
    assert!(!text.contains('\x1b'), "colours must be off when piped");
    assert!(dir.path().join("tool.pdb").exists());
}

#[test]
fn a_local_pdb_from_another_build_is_only_replaced_with_force() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);
    let stale = support::msf_pdb([0x99; 16], 1);
    let local = dir.path().join("tool.pdb");
    fs::write(&local, &stale).unwrap();

    let output = pdbwalker(&server, &["--download", "--json"], dir.path());
    assert!(output.status.success());
    let tool = &json_records(&output)["tool.exe"];
    assert_eq!(tool["download"]["status"], "exists");
    assert_eq!(tool["local_pdb"]["matches"], false);
    assert_eq!(fs::read(&local).unwrap(), stale);
    assert_eq!(server.count("GET /symbols/internal.pdb"), 0);

    let output = pdbwalker(&server, &["--download", "--force", "--json"], dir.path());
    assert!(output.status.success());
    assert_eq!(
        json_records(&output)["tool.exe"]["download"]["status"],
        "downloaded"
    );
    assert_eq!(fs::read(&local).unwrap(), pdb);
}

#[test]
fn responses_that_are_not_pdbs_are_rejected() {
    let (dir, _) = fixture();
    let server = server_with(b"<html>Sign in to continue</html>");

    let output = pdbwalker(&server, &["--download", "--json"], dir.path());
    assert!(!output.status.success());
    let tool = &json_records(&output)["tool.exe"];
    assert_eq!(tool["download"]["status"], "failed");
    assert!(
        tool["download"]["error"]
            .as_str()
            .unwrap()
            .contains("did not return a PDB")
    );
    assert_eq!(tool["local_pdb"]["available"], false);
    // Nothing is left behind, not even a partial file.
    assert_eq!(file_names(dir.path()), ORIGINAL_FILES);
}

#[test]
fn server_errors_are_retried_then_reported_and_fail_the_run() {
    let (dir, _) = fixture();
    let unavailable = (symbol_path("internal.pdb", KEY_A), Route::Status(503));
    let server = MockServer::start(vec![unavailable]);

    let output = pdbwalker(&server, &["--search"], dir.path());
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("tool.exe: symbol server lookup failed"),
        "{}",
        stderr(&output)
    );
    assert!(!stdout(&output).contains("tool.exe"));
    assert_eq!(server.count("HEAD /symbols/internal.pdb"), 3);
}

#[test]
fn output_directory_collects_files_and_writes_a_manifest() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);
    let out = tempfile::tempdir().unwrap();
    let out_arg = out.path().to_str().unwrap();

    let args = ["-o", out_arg, "--copy-binaries", "--download-remote"];
    let output = pdbwalker(&server, &args, dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    // Into an output directory the PDB keeps the name the binary refers to.
    let expected = [
        "helper.dll",
        "internal.pdb",
        "manifest.json",
        "plain.exe",
        "tool.exe",
    ];
    assert_eq!(file_names(out.path()), expected);
    assert_eq!(fs::read(out.path().join("internal.pdb")).unwrap(), pdb);
    assert_eq!(file_names(dir.path()), ORIGINAL_FILES);

    let manifest: Value =
        serde_json::from_slice(&fs::read(out.path().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["count"], 3);
    let tool = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["binary"].as_str().unwrap().ends_with("tool.exe"))
        .unwrap();
    let copied = tool["binary_copied"].as_str().unwrap();
    let downloaded = tool["pdb_downloaded"].as_str().unwrap();
    assert!(copied.ends_with("tool.exe"), "{copied}");
    assert!(downloaded.ends_with("internal.pdb"), "{downloaded}");
    assert_eq!(tool["pdb_copied"], Value::Null);
}

#[test]
fn download_and_output_directory_work_together() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);
    let out = tempfile::tempdir().unwrap();

    let output = pdbwalker(
        &server,
        &["--download", "-o", out.path().to_str().unwrap()],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));

    // Downloaded next to the binary first, then copied like any local PDB.
    assert_eq!(fs::read(dir.path().join("tool.pdb")).unwrap(), pdb);
    assert_eq!(fs::read(out.path().join("tool.pdb")).unwrap(), pdb);
    assert_eq!(server.count("GET /blob/internal"), 1);
}

#[test]
fn copy_binaries_puts_each_listed_binary_beside_its_pdb_in_the_output_directory() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);
    let out = tempfile::tempdir().unwrap();
    let out_arg = out.path().to_str().unwrap();

    let args = ["--search", "--download", "-b", "-o", out_arg];
    let output = pdbwalker(&server, &args, dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    // Only tool.exe has symbols on the server, so only it and its PDB are collected.
    let expected = ["manifest.json", "tool.exe", "tool.pdb"];
    assert_eq!(file_names(out.path()), expected);
    let original = fs::read(dir.path().join("tool.exe")).unwrap();
    assert_eq!(fs::read(out.path().join("tool.exe")).unwrap(), original);
    assert_eq!(fs::read(out.path().join("tool.pdb")).unwrap(), pdb);
}

#[test]
fn two_binaries_never_fight_over_one_pdb_name() {
    let dir = tempfile::tempdir().unwrap();
    // Both map to app.pdb; only the DLL's debug record actually names app.pdb.
    fs::write(dir.path().join("app.exe"), pe(GUID_B, 1, "apphost.pdb")).unwrap();
    fs::write(dir.path().join("app.dll"), pe(GUID_A, 2, "app.pdb")).unwrap();
    let pdb = support::msf_pdb(GUID_A, 2);
    let server = MockServer::start(vec![
        (symbol_path("app.pdb", KEY_A), Route::Body(pdb.clone())),
        (
            symbol_path("apphost.pdb", KEY_B),
            Route::Body(support::msf_pdb(GUID_B, 1)),
        ),
    ]);

    let output = pdbwalker(&server, &["--download", "--json"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));

    let records = json_records(&output);
    assert_eq!(records["app.dll"]["download"]["status"], "downloaded");
    assert_eq!(records["app.exe"]["download"]["status"], "name_conflict");
    assert_eq!(fs::read(dir.path().join("app.pdb")).unwrap(), pdb);
    assert_eq!(server.count("GET"), 1);
}

#[test]
fn binaries_sharing_a_pdb_cost_a_single_request() {
    let dir = tempfile::tempdir().unwrap();
    let pdb = support::msf_pdb(GUID_A, 2);
    for app in ["one", "two", "three"] {
        fs::create_dir(dir.path().join(app)).unwrap();
        fs::write(
            dir.path().join(app).join("runtime.dll"),
            pe(GUID_A, 2, "runtime.pdb"),
        )
        .unwrap();
    }
    let route = (symbol_path("runtime.pdb", KEY_A), Route::Body(pdb.clone()));
    let server = MockServer::start(vec![route]);

    let output = pdbwalker(&server, &["--search", "--json"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).lines().count(), 3);
    assert_eq!(server.requests().len(), 1);

    let output = pdbwalker(&server, &["--download"], dir.path());
    assert!(output.status.success(), "{}", stderr(&output));
    for app in ["one", "two", "three"] {
        let copy = dir.path().join(app).join("runtime.pdb");
        assert_eq!(fs::read(copy).unwrap(), pdb);
    }
    assert_eq!(server.count("GET"), 1);
    assert_eq!(file_names(dir.path()).len(), 6);
}

#[test]
fn a_single_file_can_be_given_instead_of_a_directory() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = pdbwalker(&server, &["-d"], &dir.path().join("tool.exe"));
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read(dir.path().join("tool.pdb")).unwrap(), pdb);
}

#[test]
fn missing_paths_fail_but_do_not_stop_the_scan() {
    let (dir, pdb) = fixture();
    let server = server_with(&pdb);

    let output = Command::new(env!("CARGO_BIN_EXE_pdbwalker"))
        .arg("--json")
        .arg(dir.path().join("does-not-exist"))
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("does-not-exist"));
    assert_eq!(json_records(&output).len(), 3);
    assert!(server.requests().is_empty());
}

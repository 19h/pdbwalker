//! Turns outcomes into text, JSON Lines, a summary and the output manifest.

use std::borrow::Cow;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anstyle::Style;
use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::Cli;
use crate::engine::{Collected, Download, Outcome, Remote, Task, Transfer};
use crate::pe::PdbId;
use crate::pool::Sink;
use crate::scan::{Entry, PdbMatch};
use crate::term::{
    BAD, BOLD, DIM, GOOD, HEADING, LABEL, MUTED_NOTICE, NOTICE, PLAIN, Progress, UtcTime, VALUE,
    format_size, paint,
};

/// Paths longer than this do not widen the path column of the compact listing.
const MAX_PATH_COLUMN: usize = 72;
const MANIFEST_NAME: &str = "manifest.json";

/// A labelled value in the detailed view or the summary.
type Row = (&'static str, Style, String);

/// Streams one report per binary to `out` and keeps the run's totals.
pub struct Reporter<'a, W: Write> {
    cli: &'a Cli,
    tasks: &'a [Task],
    /// Number of PE images found before any filtering.
    scanned: usize,
    out: W,
    /// Flush after every binary so results appear as they are produced.
    interactive: bool,
    progress: Progress,
    path_column: usize,
    totals: Totals,
    manifest: Vec<ManifestEntry>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub listed: usize,
    pub with_debug_info: usize,
    pub with_local_pdb: usize,
    pub on_server: usize,
    pub downloaded: usize,
    pub copied: usize,
    pub failures: usize,
}

impl<'a, W: Write> Reporter<'a, W> {
    pub fn new(cli: &'a Cli, tasks: &'a [Task], scanned: usize, out: W, interactive: bool) -> Self {
        let path_column = tasks
            .iter()
            .map(|task| display_width(&task.entry.path))
            .filter(|&width| width <= MAX_PATH_COLUMN)
            .max()
            .unwrap_or(0);
        let tracked = if cli.uses_network() { tasks.len() } else { 0 };
        Self {
            cli,
            tasks,
            scanned,
            out,
            interactive,
            progress: Progress::new("Querying symbol server", tracked),
            path_column,
            totals: Totals::default(),
            manifest: Vec::new(),
        }
    }

    /// Prints the summary, writes the manifest and returns the totals.
    pub fn finish(mut self) -> Result<Totals> {
        self.progress.clear();
        if !self.cli.json {
            self.write_summary()?;
        }
        self.out.flush()?;

        if let Some(dir) = &self.cli.output_dir
            && !self.manifest.is_empty()
        {
            let path = dir.join(MANIFEST_NAME);
            let manifest = Manifest {
                count: self.manifest.len(),
                files: &self.manifest,
            };
            let json = serde_json::to_string_pretty(&manifest)?;
            fs::write(&path, json)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
        Ok(self.totals)
    }

    fn record(&mut self, task: &Task, outcome: &Outcome) {
        let saved = matches!(outcome.download, Some(Download::Saved { .. }));
        let totals = &mut self.totals;
        totals.listed += 1;
        totals.with_debug_info += usize::from(task.entry.image.codeview.is_some());
        totals.with_local_pdb += usize::from(outcome.has_local_pdb(&task.entry));
        totals.on_server += usize::from(outcome.remote == Remote::Available);
        totals.downloaded += usize::from(saved);

        if let Some(collected) = &outcome.collected {
            totals.downloaded += usize::from(collected.pdb_download.done().is_some());
            totals.copied += usize::from(collected.binary.done().is_some());
            totals.copied += usize::from(collected.pdb_copy.done().is_some());
            self.manifest.push(ManifestEntry {
                binary: lossy(&task.entry.path).into_owned(),
                binary_copied: collected.binary.done().map(owned_lossy),
                pdb_copied: collected.pdb_copy.done().map(owned_lossy),
                pdb_downloaded: collected.pdb_download.done().map(owned_lossy),
            });
        }
    }

    fn write_compact(&mut self, task: &Task, outcome: &Outcome) -> io::Result<()> {
        let entry = &task.entry;
        let image = &entry.image;
        let padding = self.path_column.saturating_sub(display_width(&entry.path));
        let kind = format!("{:<5} {}", image.architecture(), image.kind());
        write!(
            self.out,
            "{} {}{:padding$}  {}",
            marker(task, outcome),
            entry.path.display(),
            "",
            paint(DIM, kind),
        )?;
        for (index, (style, text)) in status(self.cli, task, outcome).iter().enumerate() {
            let separator = if index == 0 { "  " } else { " · " };
            write!(self.out, "{}{}", paint(DIM, separator), paint(*style, text))?;
        }
        writeln!(self.out)
    }

    fn write_detailed(&mut self, task: &Task, outcome: &Outcome) -> io::Result<()> {
        let entry = &task.entry;
        writeln!(
            self.out,
            "{} {} {}",
            marker(task, outcome),
            paint(HEADING, entry.path.display()),
            paint(DIM, format_args!("({})", entry.image.kind())),
        )?;

        let mut rows = image_rows(entry);
        rows.extend(symbol_rows(task, outcome));
        if let Some(collected) = &outcome.collected {
            rows.extend(transfer_rows(collected));
        }
        write_rows(&mut self.out, LABEL, &rows)?;
        writeln!(self.out)
    }

    fn write_json(&mut self, task: &Task, outcome: &Outcome) -> io::Result<()> {
        serde_json::to_writer(&mut self.out, &JsonRecord::new(task, outcome))?;
        writeln!(self.out)
    }

    fn write_summary(&mut self) -> io::Result<()> {
        let totals = self.totals;
        if totals.listed == 0 {
            let message = "No binaries found matching criteria.";
            writeln!(self.out, "{}", paint(DIM, message))?;
            if totals.failures > 0 {
                let message = format!("{} operation(s) failed.", totals.failures);
                writeln!(self.out, "{}", paint(BAD, message))?;
            }
            return Ok(());
        }

        let binaries = if totals.listed == self.scanned {
            totals.listed.to_string()
        } else {
            format!("{} (of {} scanned)", totals.listed, self.scanned)
        };
        let mut rows: Vec<Row> = vec![
            ("PE binaries", VALUE, binaries),
            ("With PDB info", VALUE, totals.with_debug_info.to_string()),
            ("With local PDB", GOOD, totals.with_local_pdb.to_string()),
        ];
        if self.cli.probes_server() || totals.on_server > 0 {
            rows.push(("On symbol server", NOTICE, totals.on_server.to_string()));
        }
        if self.cli.download || self.cli.download_remote {
            rows.push(("PDBs downloaded", GOOD, totals.downloaded.to_string()));
        }
        if self.cli.output_dir.is_some() {
            rows.push(("Files copied", GOOD, totals.copied.to_string()));
        }
        if totals.failures > 0 {
            rows.push(("Failed", BAD, totals.failures.to_string()));
        }

        if !self.cli.verbose {
            writeln!(self.out)?;
        }
        writeln!(self.out, "{}", paint(LABEL, "─".repeat(60)))?;
        writeln!(self.out, "{}\n", paint(HEADING, "Summary"))?;
        write_rows(&mut self.out, BOLD, &rows)
    }
}

impl<W: Write> Sink<Outcome> for Reporter<'_, W> {
    fn progress(&mut self, finished: usize) {
        self.progress.set(finished);
    }

    fn accept(&mut self, index: usize, outcome: Outcome) -> io::Result<()> {
        let task = &self.tasks[index];
        let failures = outcome.failures();
        self.totals.failures += failures.len();

        if !outcome.listed {
            // Nothing is printed for a filtered-out binary, so its problems go to stderr.
            if !failures.is_empty() {
                self.progress.clear();
                for failure in &failures {
                    eprintln!("pdbwalker: {}: {failure}", task.entry.path.display());
                }
                self.progress.resume();
            }
            return Ok(());
        }

        self.record(task, &outcome);
        self.progress.clear();
        if self.cli.json {
            self.write_json(task, &outcome)?;
        } else if self.cli.verbose {
            self.write_detailed(task, &outcome)?;
        } else {
            self.write_compact(task, &outcome)?;
        }
        if self.interactive {
            self.out.flush()?;
        }
        self.progress.resume();
        Ok(())
    }
}

/// Writes rows as an indented, aligned `Label: value` block.
fn write_rows(out: &mut impl Write, label_style: Style, rows: &[Row]) -> io::Result<()> {
    let width = rows.iter().map(|row| row.0.len()).max().unwrap_or(0) + 1;
    for (label, style, value) in rows {
        let label = format!("{label}:");
        writeln!(
            out,
            "   {} {}",
            paint(label_style, format_args!("{label:<width$}")),
            paint(*style, value),
        )?;
    }
    Ok(())
}

/// The coloured bullet that opens each binary's report.
fn marker(task: &Task, outcome: &Outcome) -> impl std::fmt::Display {
    if outcome.has_local_pdb(&task.entry) {
        paint(GOOD, "●")
    } else if outcome.remote == Remote::Available {
        paint(NOTICE, "●")
    } else if task.entry.image.codeview.is_some() {
        paint(MUTED_NOTICE, "●")
    } else {
        paint(DIM, "○")
    }
}

/// The phrases that make up the status column of the compact listing.
fn status(cli: &Cli, task: &Task, outcome: &Outcome) -> Vec<(Style, String)> {
    let entry = &task.entry;
    let has_debug_info = entry.image.codeview.is_some();
    let pdb_name = file_name(&entry.pdb_path);
    let saved = matches!(outcome.download, Some(Download::Saved { .. }));
    let mut parts = Vec::new();

    match (&outcome.download, entry.local_pdb) {
        (Some(Download::Saved { bytes }), _) => {
            let size = format_size(*bytes);
            parts.push((GOOD, format!("downloaded {pdb_name} ({size})")));
        }
        (_, Some(PdbMatch::Matches)) => parts.push((GOOD, "local PDB".to_owned())),
        (_, Some(PdbMatch::Unverified)) => {
            parts.push((GOOD, "local PDB (not verified)".to_owned()));
        }
        (_, Some(PdbMatch::Differs)) => {
            let hint = if cli.download && !cli.force {
                ", --force replaces it"
            } else {
                ""
            };
            parts.push((NOTICE, format!("local PDB is from a different build{hint}")));
        }
        (_, None) if !has_debug_info => parts.push((DIM, "no debug info".to_owned())),
        (_, None) => {}
    }

    if has_debug_info {
        match (&outcome.remote, &outcome.download) {
            (_, Some(Download::Failed(reason))) => {
                parts.push((BAD, format!("download failed: {reason}")));
            }
            (Remote::Failed(reason), _) => {
                parts.push((BAD, format!("symbol server lookup failed: {reason}")));
            }
            (Remote::Available, _) if !saved => parts.push((NOTICE, "on symbol server".to_owned())),
            (Remote::Missing, _) => parts.push((DIM, "not on symbol server".to_owned())),
            (Remote::Unchecked, _) if entry.local_pdb.is_none() => {
                parts.push((DIM, "no local PDB".to_owned()));
            }
            _ => {}
        }
    }

    if let Some(Download::Yielded { to }) = &outcome.download {
        let owner = file_name(to);
        parts.push((MUTED_NOTICE, format!("{pdb_name} is reserved for {owner}")));
    }

    let transfers = outcome.collected.iter().flat_map(Collected::transfers);
    for (_, transfer) in transfers {
        match transfer {
            Transfer::Done(path) => parts.push((PLAIN, format!("→ {}", path.display()))),
            Transfer::NameTaken(path) => {
                let text = format!("{} comes from another binary", path.display());
                parts.push((MUTED_NOTICE, text));
            }
            // A failed PDB download is already reported above.
            Transfer::Failed(reason) if !reason.starts_with("download failed") => {
                parts.push((BAD, reason.clone()));
            }
            _ => {}
        }
    }
    parts
}

/// Detailed view: what the file and its PE headers say.
fn image_rows(entry: &Entry) -> Vec<Row> {
    let image = &entry.image;
    let built = UtcTime::from_unix(i64::from(image.timestamp));
    let mut rows = vec![
        ("Size", VALUE, format_size(entry.len)),
        ("Architecture", VALUE, image.architecture().to_owned()),
    ];
    if let Some(modified) = entry.modified.and_then(UtcTime::from_system_time) {
        rows.push(("Modified", VALUE, modified.to_string()));
    }
    rows.extend([
        ("Image base", VALUE, format!("0x{:X}", image.image_base)),
        ("Entry point", VALUE, format!("0x{:X}", image.entry_point)),
        ("Subsystem", VALUE, image.subsystem_name().to_owned()),
        ("Timestamp", VALUE, built.to_string()),
    ]);
    rows
}

/// Detailed view: the debug record and where its PDB can be found.
fn symbol_rows(task: &Task, outcome: &Outcome) -> Vec<Row> {
    let entry = &task.entry;
    let pdb_path = entry.pdb_path.display();
    let mut rows = Vec::new();

    match &entry.image.codeview {
        Some(codeview) => {
            rows.push(("Debug info", VALUE, codeview.pdb_file_name().to_owned()));
            if let PdbId::Guid(guid) = &codeview.id {
                rows.push(("GUID", VALUE, guid.to_string()));
            }
            rows.push(("Age", VALUE, codeview.age.to_string()));
            rows.push(("Signature", VALUE, codeview.symbol_key()));
        }
        None => rows.push(("Debug info", DIM, "none".to_owned())),
    }
    if let Some(url) = &task.url {
        rows.push(("URL", VALUE, url.clone()));
    }

    rows.push(match (&outcome.download, entry.local_pdb) {
        (Some(Download::Saved { bytes }), _) => {
            let note = format!("downloaded, {}", format_size(*bytes));
            ("Local PDB", GOOD, format!("{pdb_path} ({note})"))
        }
        (_, Some(PdbMatch::Matches)) => ("Local PDB", GOOD, format!("{pdb_path} (matches)")),
        (_, Some(PdbMatch::Unverified)) => {
            ("Local PDB", GOOD, format!("{pdb_path} (not verified)"))
        }
        (_, Some(PdbMatch::Differs)) => {
            let note = "from a different build";
            ("Local PDB", NOTICE, format!("{pdb_path} ({note})"))
        }
        (_, None) => ("Local PDB", DIM, "not found".to_owned()),
    });

    if entry.image.codeview.is_some() {
        rows.push(match &outcome.remote {
            Remote::Available => ("Symbol server", GOOD, "available".to_owned()),
            Remote::Missing => ("Symbol server", DIM, "not available".to_owned()),
            Remote::Unchecked => ("Symbol server", DIM, "not checked".to_owned()),
            Remote::Failed(reason) => ("Symbol server", BAD, format!("error: {reason}")),
        });
    }

    match &outcome.download {
        Some(Download::Yielded { to }) => {
            let text = format!("skipped, {pdb_path} is reserved for {}", to.display());
            rows.push(("Download", MUTED_NOTICE, text));
        }
        Some(Download::Failed(reason)) => {
            rows.push(("Download", BAD, format!("failed: {reason}")));
        }
        Some(Download::Kept) if entry.local_pdb == Some(PdbMatch::Differs) => {
            let text = "skipped, use --force to replace the local PDB";
            rows.push(("Download", MUTED_NOTICE, text.to_owned()));
        }
        _ => {}
    }
    rows
}

/// Detailed view: what went into the output directory.
fn transfer_rows(collected: &Collected) -> Vec<Row> {
    collected
        .transfers()
        .into_iter()
        .filter_map(|(label, transfer)| {
            let (style, text) = match transfer {
                Transfer::NotPlanned => return None,
                Transfer::Done(path) => (GOOD, path.display().to_string()),
                Transfer::Exists(path) => (DIM, format!("{} already exists", path.display())),
                Transfer::NameTaken(path) => {
                    let text = format!("skipped, {} comes from another binary", path.display());
                    (MUTED_NOTICE, text)
                }
                Transfer::NotOnServer => (DIM, "not on symbol server".to_owned()),
                Transfer::Failed(reason) => (BAD, reason.clone()),
            };
            Some((label, style, text))
        })
        .collect()
}

fn display_width(path: &Path) -> usize {
    path.to_string_lossy().chars().count()
}

/// The final component of `path`, for messages where the directory is obvious.
fn file_name(path: &Path) -> Cow<'_, str> {
    path.file_name()
        .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
}

fn lossy(path: &Path) -> Cow<'_, str> {
    path.to_string_lossy()
}

fn owned_lossy(path: &Path) -> String {
    lossy(path).into_owned()
}

#[derive(Serialize)]
struct JsonRecord<'a> {
    file_path: Cow<'a, str>,
    file_size: u64,
    file_modified: Option<String>,
    architecture: &'a str,
    image_base: String,
    entry_point: String,
    timestamp: String,
    subsystem: &'a str,
    is_dll: bool,
    local_pdb: JsonLocalPdb<'a>,
    remote_pdb: JsonRemotePdb<'a>,
    /// Present only with `--download`.
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<JsonDownload<'a>>,
    /// Present only with `--output`.
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<JsonOutput<'a>>,
}

#[derive(Serialize)]
struct JsonLocalPdb<'a> {
    available: bool,
    path: Option<Cow<'a, str>>,
    /// Whether the PDB belongs to this build; `null` when that could not be determined.
    matches: Option<bool>,
}

#[derive(Serialize)]
struct JsonRemotePdb<'a> {
    has_info: bool,
    /// `null` when the server was not asked or gave no usable answer.
    available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    info: Option<JsonPdbInfo<'a>>,
}

#[derive(Serialize)]
struct JsonPdbInfo<'a> {
    file_name: &'a str,
    guid: Option<String>,
    age: u32,
    signature: String,
    url: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonDownload<'a> {
    status: &'static str,
    path: Option<Cow<'a, str>>,
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    binary_copied: Option<Cow<'a, str>>,
    pdb_copied: Option<Cow<'a, str>>,
    pdb_downloaded: Option<Cow<'a, str>>,
}

impl<'a> JsonRecord<'a> {
    fn new(task: &'a Task, outcome: &'a Outcome) -> Self {
        let entry = &task.entry;
        let image = &entry.image;
        let has_local_pdb = outcome.has_local_pdb(entry);
        let modified = entry.modified.and_then(UtcTime::from_system_time);

        Self {
            file_path: lossy(&entry.path),
            file_size: entry.len,
            file_modified: modified.map(|time| time.rfc3339()),
            architecture: image.architecture(),
            image_base: format!("0x{:X}", image.image_base),
            entry_point: format!("0x{:X}", image.entry_point),
            timestamp: UtcTime::from_unix(i64::from(image.timestamp)).rfc3339(),
            subsystem: image.subsystem_name(),
            is_dll: image.is_dll(),
            local_pdb: JsonLocalPdb {
                available: has_local_pdb,
                path: has_local_pdb.then(|| lossy(&entry.pdb_path)),
                matches: match (&outcome.download, entry.local_pdb) {
                    (Some(Download::Saved { .. }), _) => Some(true),
                    (_, Some(PdbMatch::Matches)) => Some(true),
                    (_, Some(PdbMatch::Differs)) => Some(false),
                    (_, Some(PdbMatch::Unverified) | None) => None,
                },
            },
            remote_pdb: JsonRemotePdb {
                has_info: image.codeview.is_some(),
                available: match outcome.remote {
                    Remote::Available => Some(true),
                    Remote::Missing => Some(false),
                    Remote::Unchecked | Remote::Failed(_) => None,
                },
                error: match &outcome.remote {
                    Remote::Failed(reason) => Some(reason.as_str()),
                    _ => None,
                },
                info: image.codeview.as_ref().map(|codeview| JsonPdbInfo {
                    file_name: codeview.pdb_file_name(),
                    guid: match &codeview.id {
                        PdbId::Guid(guid) => Some(guid.to_string()),
                        PdbId::Timestamp(_) => None,
                    },
                    age: codeview.age,
                    signature: codeview.symbol_key(),
                    url: task.url.as_deref(),
                }),
            },
            download: outcome.download.as_ref().map(|download| {
                let (status, bytes, error) = match download {
                    Download::Saved { bytes } => ("downloaded", Some(*bytes), None),
                    Download::Kept => ("exists", None, None),
                    Download::NotOnServer => ("not_found", None, None),
                    Download::NoDebugInfo => ("no_debug_info", None, None),
                    Download::Yielded { .. } => ("name_conflict", None, None),
                    Download::Failed(reason) => ("failed", None, Some(reason.as_str())),
                };
                JsonDownload {
                    status,
                    path: bytes.map(|_| lossy(&entry.pdb_path)),
                    bytes,
                    error,
                }
            }),
            output: outcome.collected.as_ref().map(|collected| JsonOutput {
                binary_copied: collected.binary.done().map(lossy),
                pdb_copied: collected.pdb_copy.done().map(lossy),
                pdb_downloaded: collected.pdb_download.done().map(lossy),
            }),
        }
    }
}

#[derive(Serialize)]
struct Manifest<'a> {
    files: &'a [ManifestEntry],
    count: usize,
}

#[derive(Serialize)]
struct ManifestEntry {
    binary: String,
    binary_copied: Option<String>,
    pdb_copied: Option<String>,
    pdb_downloaded: Option<String>,
}

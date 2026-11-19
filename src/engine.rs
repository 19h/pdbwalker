//! Decides what to do for each binary, then does it.
//!
//! Planning is sequential and deterministic: it settles every file name up
//! front, so the parallel execution phase never has two workers writing to
//! the same path. Execution is where all network traffic happens.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::scan::{Entry, PdbMatch};
use crate::symsrv::{self, Lookup, SymbolServer};

/// A binary together with everything planned for it.
#[derive(Debug)]
pub struct Task {
    pub entry: Entry,
    /// Symbol server URL of the binary's PDB, if it references one.
    pub url: Option<String>,
    in_place: InPlace,
    collect: Option<Collect>,
}

/// Plan for `--download`, which stores `foo.pdb` next to `foo.exe`.
#[derive(Debug, PartialEq, Eq)]
enum InPlace {
    NotRequested,
    NoDebugInfo,
    /// A PDB is already there and is not to be replaced.
    Keep,
    /// Another binary in the same directory maps to the same PDB name and takes precedence.
    Yield {
        to: PathBuf,
    },
    Fetch,
}

/// Plan for `--output`, which gathers files in one directory.
#[derive(Debug)]
struct Collect {
    binary: Option<Slot>,
    pdb: Option<(Slot, PdbSource)>,
}

#[derive(Debug)]
enum PdbSource {
    /// Copy the PDB sitting next to the binary.
    Local,
    /// Download it from the symbol server.
    Server,
}

/// A destination in the output directory.
#[derive(Debug)]
enum Slot {
    Free(PathBuf),
    /// An earlier binary of this run already uses this name.
    Taken(PathBuf),
}

/// What happened to one binary.
#[derive(Debug)]
pub struct Outcome {
    /// Whether the binary passed the filters that depend on the server's answer.
    pub listed: bool,
    pub remote: Remote,
    /// Result of `--download`; `None` if it was not requested.
    pub download: Option<Download>,
    /// Result of `--output`; `None` if it was not requested.
    pub collected: Option<Collected>,
}

/// Whether the symbol server has the binary's PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    Unchecked,
    Available,
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Download {
    Saved {
        bytes: u64,
    },
    /// A PDB was already in place and was left alone.
    Kept,
    NotOnServer,
    NoDebugInfo,
    /// The PDB name belongs to another binary in the same directory.
    Yielded {
        to: PathBuf,
    },
    Failed(String),
}

#[derive(Debug)]
pub struct Collected {
    pub binary: Transfer,
    pub pdb_copy: Transfer,
    pub pdb_download: Transfer,
}

/// Fate of one file destined for the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transfer {
    NotPlanned,
    Done(PathBuf),
    /// The destination already exists and `--force` was not given.
    Exists(PathBuf),
    /// Another binary of this run already produced a file of that name.
    NameTaken(PathBuf),
    NotOnServer,
    Failed(String),
}

impl Transfer {
    /// The path of the file, if it was written by this run.
    pub fn done(&self) -> Option<&Path> {
        match self {
            Self::Done(path) => Some(path),
            _ => None,
        }
    }
}

impl Collected {
    /// Every transfer with a label describing it.
    pub fn transfers(&self) -> [(&'static str, &Transfer); 3] {
        [
            ("Binary copy", &self.binary),
            ("PDB copy", &self.pdb_copy),
            ("PDB download", &self.pdb_download),
        ]
    }
}

impl Outcome {
    /// Whether the binary has a PDB next to it now that the run is over.
    pub fn has_local_pdb(&self, entry: &Entry) -> bool {
        entry.local_pdb.is_some() || matches!(self.download, Some(Download::Saved { .. }))
    }

    /// Messages for everything that went wrong with this binary.
    pub fn failures(&self) -> Vec<String> {
        let mut failures = Vec::new();
        // A failed download already explains a failed lookup.
        match (&self.download, &self.remote) {
            (Some(Download::Failed(reason)), _) => {
                failures.push(format!("download failed: {reason}"));
            }
            (_, Remote::Failed(reason)) => {
                failures.push(format!("symbol server lookup failed: {reason}"));
            }
            _ => {}
        }
        let transfers = self.collected.iter().flat_map(Collected::transfers);
        for (_, transfer) in transfers {
            if let Transfer::Failed(reason) = transfer {
                failures.push(reason.clone());
            }
        }
        failures
    }
}

pub struct Engine<'a> {
    cli: &'a Cli,
    server_base: &'a str,
    server: Option<SymbolServer>,
}

impl<'a> Engine<'a> {
    /// `server` must be present whenever the options involve the network.
    pub fn new(cli: &'a Cli, server_base: &'a str, server: Option<SymbolServer>) -> Self {
        debug_assert_eq!(server.is_some(), cli.uses_network());
        Self {
            cli,
            server_base,
            server,
        }
    }

    /// Applies the local filters and plans the work for every remaining binary.
    pub fn plan(&self, entries: Vec<Entry>) -> Vec<Task> {
        let entries: Vec<Entry> = entries
            .into_iter()
            .filter(|entry| self.selects(entry))
            .collect();

        let in_place = self.plan_in_place(&entries);
        let mut taken = HashSet::new();
        entries
            .into_iter()
            .zip(in_place)
            .map(|(entry, in_place)| {
                let url = entry
                    .image
                    .codeview
                    .as_ref()
                    .map(|codeview| symsrv::pdb_url(self.server_base, codeview));
                let collect = self.plan_collect(&entry, &in_place, &mut taken);
                Task {
                    entry,
                    url,
                    in_place,
                    collect,
                }
            })
            .collect()
    }

    fn selects(&self, entry: &Entry) -> bool {
        let needs_debug_info = self.cli.remote_only || self.cli.search;
        (!self.cli.local_only || entry.local_pdb.is_some())
            && (!needs_debug_info || entry.image.codeview.is_some())
    }

    /// Settles which binary may write each `<stem>.pdb`.
    ///
    /// `foo.exe` and `foo.dll` in one directory both map to `foo.pdb`. The
    /// name goes to the binary a PDB next to it already matches, else to the
    /// one whose debug record names exactly that file, else to the first one.
    fn plan_in_place(&self, entries: &[Entry]) -> Vec<InPlace> {
        if !self.cli.download {
            return entries.iter().map(|_| InPlace::NotRequested).collect();
        }

        let claim_strength = |entry: &Entry| {
            let codeview = entry.image.codeview.as_ref()?;
            let names_this_file = entry.pdb_path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .eq_ignore_ascii_case(codeview.pdb_file_name())
            });
            Some(match entry.local_pdb {
                Some(PdbMatch::Matches) => 0,
                _ if names_this_file => 1,
                _ => 2,
            })
        };

        let mut owners: HashMap<String, (u8, usize)> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(strength) = claim_strength(entry) {
                owners
                    .entry(path_key(&entry.pdb_path))
                    .and_modify(|owner| {
                        if strength < owner.0 {
                            *owner = (strength, index);
                        }
                    })
                    .or_insert((strength, index));
            }
        }

        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                if entry.image.codeview.is_none() {
                    return InPlace::NoDebugInfo;
                }
                match owners[&path_key(&entry.pdb_path)] {
                    (_, owner) if owner != index => InPlace::Yield {
                        to: entries[owner].path.clone(),
                    },
                    _ => match entry.local_pdb {
                        Some(PdbMatch::Matches) => InPlace::Keep,
                        Some(_) if !self.cli.force => InPlace::Keep,
                        _ => InPlace::Fetch,
                    },
                }
            })
            .collect()
    }

    fn plan_collect(
        &self,
        entry: &Entry,
        in_place: &InPlace,
        taken: &mut HashSet<String>,
    ) -> Option<Collect> {
        let dir = self.cli.output_dir.as_deref()?;
        let mut slot = |name: &OsStr| {
            let dest = dir.join(name);
            if taken.insert(path_key(&dest)) {
                Slot::Free(dest)
            } else {
                Slot::Taken(dest)
            }
        };

        let binary = entry
            .path
            .file_name()
            .filter(|_| self.cli.copy_binaries)
            .map(&mut slot);

        // A PDB next to the binary (present now, or about to be downloaded
        // there) is copied; otherwise it can be fetched under its own name.
        let has_local_source = entry.has_usable_pdb() || *in_place == InPlace::Fetch;
        let pdb = if has_local_source {
            entry
                .pdb_path
                .file_name()
                .map(|name| (slot(name), PdbSource::Local))
        } else if self.cli.download_remote
            && let Some(codeview) = &entry.image.codeview
        {
            let name = sanitize_file_name(codeview.pdb_file_name());
            Some((slot(OsStr::new(&name)), PdbSource::Server))
        } else {
            None
        };

        Some(Collect { binary, pdb })
    }

    /// Carries out the plan for one binary. Safe to call from many threads.
    pub fn execute(&self, task: &Task) -> Outcome {
        let entry = &task.entry;
        let mut remote = Remote::Unchecked;

        let download = match &task.in_place {
            InPlace::NotRequested => None,
            InPlace::NoDebugInfo => Some(Download::NoDebugInfo),
            InPlace::Keep => Some(Download::Kept),
            InPlace::Yield { to } => Some(Download::Yielded { to: to.clone() }),
            InPlace::Fetch => Some(match self.fetch(task, &entry.pdb_path, &mut remote) {
                Lookup::Found(bytes) => Download::Saved { bytes },
                Lookup::Missing => Download::NotOnServer,
                Lookup::Failed(reason) => Download::Failed(reason),
            }),
        };

        // Downloading into the output directory doubles as the availability check.
        let pdb_download = match &task.collect {
            Some(Collect {
                pdb: Some((slot, PdbSource::Server)),
                ..
            }) => self.transfer(slot, |dest| match self.fetch(task, dest, &mut remote) {
                Lookup::Found(_) => Transfer::Done(dest.to_owned()),
                Lookup::Missing => Transfer::NotOnServer,
                Lookup::Failed(reason) => Transfer::Failed(format!("download failed: {reason}")),
            }),
            _ => Transfer::NotPlanned,
        };

        if self.cli.probes_server()
            && remote == Remote::Unchecked
            && let (Some(server), Some(url)) = (&self.server, &task.url)
        {
            remote = match server.probe(url) {
                Lookup::Found(()) => Remote::Available,
                Lookup::Missing => Remote::Missing,
                Lookup::Failed(reason) => Remote::Failed(reason),
            };
        }

        let listed = !self.cli.requires_available() || remote == Remote::Available;

        let collected = task.collect.as_ref().map(|collect| {
            let mut collected = Collected {
                binary: Transfer::NotPlanned,
                pdb_copy: Transfer::NotPlanned,
                pdb_download,
            };
            if !listed {
                return collected;
            }
            if let Some(slot) = &collect.binary {
                collected.binary = self.transfer(slot, |dest| copy(&entry.path, dest));
            }
            let saved = matches!(download, Some(Download::Saved { .. }));
            if let Some((slot, PdbSource::Local)) = &collect.pdb
                && (saved || entry.has_usable_pdb())
            {
                collected.pdb_copy = self.transfer(slot, |dest| copy(&entry.pdb_path, dest));
            }
            collected
        });

        Outcome {
            listed,
            remote,
            download,
            collected,
        }
    }

    /// Downloads the task's PDB to `dest`, recording what that says about availability.
    fn fetch(&self, task: &Task, dest: &Path, remote: &mut Remote) -> Lookup<u64> {
        let (Some(server), Some(url)) = (&self.server, &task.url) else {
            return Lookup::Failed("no symbol server URL for this binary".to_owned());
        };
        let lookup = server.download(url, dest);
        *remote = match &lookup {
            Lookup::Found(_) => Remote::Available,
            Lookup::Missing => Remote::Missing,
            // The file may well exist: writing it could be what failed.
            Lookup::Failed(reason) => Remote::Failed(reason.clone()),
        };
        lookup
    }

    /// Runs `write` for a free slot unless the destination must be left alone.
    fn transfer(&self, slot: &Slot, write: impl FnOnce(&Path) -> Transfer) -> Transfer {
        match slot {
            Slot::Taken(dest) => Transfer::NameTaken(dest.clone()),
            Slot::Free(dest) if !self.cli.force && dest.exists() => Transfer::Exists(dest.clone()),
            Slot::Free(dest) => write(dest),
        }
    }
}

fn copy(source: &Path, dest: &Path) -> Transfer {
    // Copying a file onto itself would truncate it.
    let same_file = matches!(
        (fs::canonicalize(source), fs::canonicalize(dest)),
        (Ok(source), Ok(dest)) if source == dest
    );
    if same_file {
        return Transfer::Exists(dest.to_owned());
    }
    match fs::copy(source, dest) {
        Ok(_) => Transfer::Done(dest.to_owned()),
        Err(err) => Transfer::Failed(format!(
            "failed to copy {} to {}: {err}",
            source.display(),
            dest.display()
        )),
    }
}

/// Key under which two paths count as the same file. Case is folded because
/// PE files usually live on case-insensitive file systems.
fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// Makes a name taken from a binary's debug record safe to create on any platform.
fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::pe::{CodeView, Guid, PdbId, PeImage};

    fn entry(path: &str, pdb_name: Option<&str>, local_pdb: Option<PdbMatch>) -> Entry {
        let path = PathBuf::from(path);
        Entry {
            pdb_path: path.with_extension("pdb"),
            path,
            len: 0,
            modified: None,
            image: PeImage {
                machine: 0x8664,
                characteristics: 0,
                timestamp: 0,
                image_base: 0,
                entry_point: 0,
                subsystem: 3,
                codeview: pdb_name.map(|name| CodeView {
                    id: PdbId::Guid(Guid([1; 16])),
                    age: 1,
                    pdb_path: format!(r"c:\build\{name}"),
                }),
            },
            local_pdb,
        }
    }

    fn plan(args: &[&str], entries: Vec<Entry>) -> Vec<Task> {
        let args = ["pdbwalker"].iter().chain(args).copied().chain(["."]);
        let cli = Cli::try_parse_from(args).unwrap();
        let server = cli.uses_network().then(|| SymbolServer::new().unwrap());
        Engine::new(&cli, "http://symbols.test", server).plan(entries)
    }

    fn in_place(tasks: &[Task]) -> Vec<&InPlace> {
        tasks.iter().map(|task| &task.in_place).collect()
    }

    #[test]
    fn plans_nothing_without_download() {
        let tasks = plan(&[], vec![entry("a.exe", Some("a.pdb"), None)]);
        assert_eq!(in_place(&tasks), [&InPlace::NotRequested]);
        assert!(tasks[0].collect.is_none());
        assert_eq!(
            tasks[0].url.as_deref(),
            Some("http://symbols.test/a.pdb/010101010101010101010101010101011/a.pdb")
        );
    }

    #[test]
    fn download_fetches_missing_pdbs_and_keeps_existing_ones() {
        let entries = || {
            vec![
                entry("missing.exe", Some("missing.pdb"), None),
                entry("good.dll", Some("good.pdb"), Some(PdbMatch::Matches)),
                entry("stale.dll", Some("stale.pdb"), Some(PdbMatch::Differs)),
                entry("odd.dll", Some("odd.pdb"), Some(PdbMatch::Unverified)),
                entry("bare.exe", None, None),
            ]
        };
        assert_eq!(
            in_place(&plan(&["--download"], entries())),
            [
                &InPlace::Fetch,
                &InPlace::Keep,
                &InPlace::Keep,
                &InPlace::Keep,
                &InPlace::NoDebugInfo
            ]
        );
        // --force replaces what does not verifiably match, and nothing else.
        assert_eq!(
            in_place(&plan(&["--download", "--force"], entries())),
            [
                &InPlace::Fetch,
                &InPlace::Keep,
                &InPlace::Fetch,
                &InPlace::Fetch,
                &InPlace::NoDebugInfo
            ]
        );
    }

    #[test]
    fn shared_pdb_name_goes_to_the_binary_that_names_it() {
        // A .NET app: the host executable is built from apphost.pdb, the
        // managed assembly from app.pdb. Both map to app.pdb.
        let tasks = plan(
            &["--download"],
            vec![
                entry("bin/App.exe", Some("apphost.pdb"), None),
                entry("bin/app.dll", Some("app.pdb"), None),
            ],
        );
        assert_eq!(
            in_place(&tasks),
            [
                &InPlace::Yield {
                    to: PathBuf::from("bin/app.dll")
                },
                &InPlace::Fetch
            ]
        );
    }

    #[test]
    fn shared_pdb_name_prefers_a_verified_local_match_then_scan_order() {
        let tasks = plan(
            &["--download", "--force"],
            vec![
                entry("x.dll", Some("x.pdb"), Some(PdbMatch::Differs)),
                entry("x.exe", Some("other.pdb"), Some(PdbMatch::Matches)),
            ],
        );
        assert_eq!(
            in_place(&tasks),
            [
                &InPlace::Yield {
                    to: PathBuf::from("x.exe")
                },
                &InPlace::Keep
            ]
        );

        let tasks = plan(
            &["--download"],
            vec![
                entry("y.dll", Some("one.pdb"), None),
                entry("y.exe", Some("two.pdb"), None),
                entry("y.sys", None, None),
            ],
        );
        assert_eq!(
            in_place(&tasks),
            [
                &InPlace::Fetch,
                &InPlace::Yield {
                    to: PathBuf::from("y.dll")
                },
                &InPlace::NoDebugInfo
            ]
        );
    }

    #[test]
    fn local_filters_apply_before_planning() {
        let entries = || {
            vec![
                entry("a.exe", Some("a.pdb"), Some(PdbMatch::Matches)),
                entry("b.exe", Some("b.pdb"), None),
                entry("c.exe", None, None),
            ]
        };
        let paths = |tasks: &[Task]| -> Vec<String> {
            tasks
                .iter()
                .map(|task| task.entry.path.display().to_string())
                .collect()
        };
        let with_debug_info = ["a.exe", "b.exe"];
        assert_eq!(paths(&plan(&["--local-only"], entries())), ["a.exe"]);
        assert_eq!(paths(&plan(&["--remote-only"], entries())), with_debug_info);
        assert_eq!(paths(&plan(&["--search"], entries())), with_debug_info);
    }

    #[test]
    fn a_pdb_from_another_build_is_not_collected() {
        let stale = || vec![entry("a.dll", Some("real.pdb"), Some(PdbMatch::Differs))];

        // Without a download there is nothing trustworthy to put in the output directory.
        let tasks = plan(&["-o", "out"], stale());
        assert!(tasks[0].collect.as_ref().unwrap().pdb.is_none());

        // With one, the right PDB comes from the server under its own name.
        let tasks = plan(&["-o", "out", "--download-remote"], stale());
        assert!(matches!(
            &tasks[0].collect.as_ref().unwrap().pdb,
            Some((Slot::Free(p), PdbSource::Server)) if p == Path::new("out/real.pdb")
        ));
    }

    #[test]
    fn output_directory_names_are_handed_out_once() {
        let tasks = plan(
            &["-o", "out", "--copy-binaries", "--download-remote"],
            vec![
                entry("one/lib.dll", Some("lib.pdb"), Some(PdbMatch::Matches)),
                entry("two/LIB.dll", Some("lib.pdb"), None),
                entry("two/tool.exe", Some(r"evil:name?.pdb"), None),
            ],
        );
        let collect: Vec<_> = tasks.iter().map(|t| t.collect.as_ref().unwrap()).collect();

        assert!(matches!(&collect[0].binary, Some(Slot::Free(p)) if p == Path::new("out/lib.dll")));
        assert!(matches!(
            &collect[0].pdb,
            Some((Slot::Free(p), PdbSource::Local)) if p == Path::new("out/lib.pdb")
        ));
        assert!(matches!(&collect[1].binary, Some(Slot::Taken(_))));
        assert!(matches!(
            &collect[1].pdb,
            Some((Slot::Taken(_), PdbSource::Server))
        ));
        assert!(matches!(
            &collect[2].pdb,
            Some((Slot::Free(p), PdbSource::Server)) if p == Path::new("out/evil_name_.pdb")
        ));
    }
}

//! Finding PE files on disk and gathering what can be learned without a network.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::SystemTime;

use walkdir::WalkDir;

use crate::cli::Cli;
use crate::pdb;
use crate::pe::{CodeView, PeImage};
use crate::pool::{self, Sink};
use crate::term::Progress;

/// A PE file found on disk.
#[derive(Debug)]
pub struct Entry {
    pub path: PathBuf,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub image: PeImage,
    /// Where this binary's PDB lives when it sits next to it: `foo.exe` -> `foo.pdb`.
    pub pdb_path: PathBuf,
    /// State of the file at `pdb_path`, if there is one.
    pub local_pdb: Option<PdbMatch>,
}

impl Entry {
    /// Whether a PDB sits next to the binary that is not known to belong to
    /// a different build.
    pub fn has_usable_pdb(&self) -> bool {
        matches!(
            self.local_pdb,
            Some(PdbMatch::Matches | PdbMatch::Unverified)
        )
    }
}

/// How a PDB found next to a binary relates to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbMatch {
    /// The PDB carries the GUID the binary asks for.
    Matches,
    /// The PDB belongs to a different build.
    Differs,
    /// The binary names no PDB, or the PDB's format could not be read.
    Unverified,
}

/// Problems met while scanning. Only `errors` affect the exit status.
#[derive(Debug, Default)]
pub struct Diagnostics {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Walks the requested paths and returns every file worth inspecting, in a stable order.
pub fn discover(cli: &Cli, diagnostics: &mut Diagnostics) -> Vec<PathBuf> {
    let extensions: Vec<&str> = cli
        .extensions
        .iter()
        .map(|extension| extension.trim().trim_start_matches('.'))
        .filter(|extension| !extension.is_empty())
        .collect();
    let wanted = |path: &Path| {
        cli.all_files
            || path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extensions
                        .iter()
                        .any(|wanted| wanted.eq_ignore_ascii_case(extension))
                })
    };

    let mut files = Vec::new();
    for root in &cli.paths {
        let mut walker = WalkDir::new(root)
            .follow_links(cli.follow_symlinks)
            .sort_by_file_name();
        if let Some(depth) = cli.max_depth {
            walker = walker.max_depth(depth);
        }
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                // Failing to read a path the user named is an error; trouble
                // further down the tree is only worth a warning.
                Err(err) if err.depth() == 0 => {
                    let reason = err
                        .io_error()
                        .map_or_else(|| err.to_string(), io::Error::to_string);
                    diagnostics
                        .errors
                        .push(format!("{}: {reason}", root.display()));
                    continue;
                }
                Err(err) => {
                    diagnostics.warnings.push(err.to_string());
                    continue;
                }
            };
            // Paths given on the command line are inspected whatever they are called.
            if entry.depth() > 0 && !wanted(entry.path()) {
                continue;
            }
            // Only regular files are opened: reading a FIFO or device could block forever.
            let file_type = entry.file_type();
            if file_type.is_file() || (file_type.is_symlink() && entry.path().is_file()) {
                files.push(entry.into_path());
            }
        }
    }
    files
}

/// Parses every candidate in parallel, keeping those that are PE images.
pub fn inspect_all(candidates: &[PathBuf], diagnostics: &mut Diagnostics) -> Vec<Entry> {
    /// A PE image, a file that is something else, or a warning.
    type Inspected = Result<Option<Entry>, String>;

    struct Collector<'a> {
        entries: Vec<Entry>,
        diagnostics: &'a mut Diagnostics,
        progress: Progress,
    }

    impl Sink<Inspected> for Collector<'_> {
        fn progress(&mut self, finished: usize) {
            self.progress.set(finished);
        }

        fn accept(&mut self, _index: usize, result: Inspected) -> io::Result<()> {
            match result {
                Ok(Some(entry)) => self.entries.push(entry),
                Ok(None) => {}
                Err(warning) => self.diagnostics.warnings.push(warning),
            }
            Ok(())
        }
    }

    let mut collector = Collector {
        entries: Vec::new(),
        diagnostics,
        progress: Progress::new("Scanning files", candidates.len()),
    };
    let threads = thread::available_parallelism().map_or(4, usize::from);
    let inspect_one =
        |path: &PathBuf| inspect(path).map_err(|err| format!("{}: {err}", path.display()));
    pool::run_ordered(candidates, threads, inspect_one, &mut collector)
        .expect("collecting entries cannot fail");
    collector.entries
}

/// Reads the PE headers of `path`; `Ok(None)` means it is not a PE image.
fn inspect(path: &Path) -> io::Result<Option<Entry>> {
    let mut file = File::open(path)?;
    let Some(image) = PeImage::parse(&mut file)? else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    let pdb_path = path.with_extension("pdb");
    let local_pdb = check_local_pdb(&pdb_path, image.codeview.as_ref());

    Ok(Some(Entry {
        path: path.to_owned(),
        len: metadata.len(),
        modified: metadata.modified().ok(),
        image,
        pdb_path,
        local_pdb,
    }))
}

/// Looks for a PDB at `pdb_path` and compares its identity with the binary's.
fn check_local_pdb(pdb_path: &Path, codeview: Option<&CodeView>) -> Option<PdbMatch> {
    let mut file = File::open(pdb_path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let verdict = match (codeview, pdb::read_id(&mut file)) {
        (Some(codeview), Ok(Some(id))) if id == codeview.id => PdbMatch::Matches,
        (Some(_), Ok(Some(_))) => PdbMatch::Differs,
        _ => PdbMatch::Unverified,
    };
    Some(verdict)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;

    use super::*;
    use crate::support::{self, PeSpec};

    const GUID: [u8; 16] = *b"fedcba9876543210";

    fn cli(args: &[&str], root: &Path) -> Cli {
        let root = root.to_str().unwrap();
        Cli::try_parse_from(["pdbwalker"].iter().chain(args).copied().chain([root])).unwrap()
    }

    fn names(files: &[PathBuf]) -> Vec<&str> {
        files
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap())
            .collect()
    }

    fn files_of(entries: &[Entry]) -> Vec<PathBuf> {
        entries.iter().map(|entry| entry.path.clone()).collect()
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let image = support::pe_image(&PeSpec {
            pdb: Some((GUID, 1, r"c:\src\app.pdb")),
            ..PeSpec::default()
        });
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("app.exe"), &image).unwrap();
        fs::write(dir.path().join("sub/driver.SYS"), &image).unwrap();
        fs::write(dir.path().join("sub/renamed.bin"), &image).unwrap();
        fs::write(dir.path().join("notes.txt"), "not a binary").unwrap();
        fs::write(dir.path().join("fake.dll"), "MZ but not really").unwrap();
        dir
    }

    #[test]
    fn discovers_by_extension_in_sorted_order() {
        let dir = tree();
        let mut diagnostics = Diagnostics::default();
        let files = discover(&cli(&[], dir.path()), &mut diagnostics);
        assert_eq!(names(&files), ["app.exe", "fake.dll", "driver.SYS"]);
        assert!(diagnostics.errors.is_empty());
    }

    #[test]
    fn honours_depth_extension_and_all_files_options() {
        let dir = tree();
        let mut diagnostics = Diagnostics::default();

        let files = discover(&cli(&["--max-depth", "1"], dir.path()), &mut diagnostics);
        assert_eq!(names(&files), ["app.exe", "fake.dll"]);

        let files = discover(&cli(&["--ext", ".bin,sys"], dir.path()), &mut diagnostics);
        assert_eq!(names(&files), ["driver.SYS", "renamed.bin"]);

        let files = discover(&cli(&["--all-files"], dir.path()), &mut diagnostics);
        assert_eq!(files.len(), 5);
    }

    #[test]
    fn explicit_files_bypass_the_extension_filter() {
        let dir = tree();
        let mut diagnostics = Diagnostics::default();
        let target = dir.path().join("sub/renamed.bin");
        let files = discover(&cli(&[], &target), &mut diagnostics);
        assert_eq!(files, [target]);
    }

    #[test]
    fn missing_roots_are_errors() {
        let dir = tree();
        let mut diagnostics = Diagnostics::default();
        let files = discover(&cli(&[], &dir.path().join("nope")), &mut diagnostics);
        assert!(files.is_empty());
        assert_eq!(diagnostics.errors.len(), 1);
    }

    #[test]
    fn inspection_keeps_only_real_images_and_classifies_local_pdbs() {
        let dir = tree();
        let other_build = support::msf_pdb([7; 16], 1);
        fs::write(dir.path().join("app.pdb"), support::msf_pdb(GUID, 1)).unwrap();
        fs::write(dir.path().join("sub/driver.pdb"), other_build).unwrap();
        fs::write(dir.path().join("sub/renamed.pdb"), "garbage").unwrap();

        let mut diagnostics = Diagnostics::default();
        let files = discover(&cli(&["--all-files"], dir.path()), &mut diagnostics);
        let entries = inspect_all(&files, &mut diagnostics);

        let local_pdbs: Vec<_> = entries.iter().map(|entry| entry.local_pdb).collect();
        assert_eq!(
            names(&files_of(&entries)),
            ["app.exe", "driver.SYS", "renamed.bin"]
        );
        assert_eq!(
            local_pdbs,
            [
                Some(PdbMatch::Matches),
                Some(PdbMatch::Differs),
                Some(PdbMatch::Unverified),
            ]
        );
        assert_eq!(entries[0].pdb_path, dir.path().join("app.pdb"));
        assert!(diagnostics.warnings.is_empty());
    }
}

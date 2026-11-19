//! Command-line interface definition.

use std::path::PathBuf;

use clap::Parser;

/// Microsoft's public symbol server.
pub const DEFAULT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Extensions that are scanned unless `--ext` or `--all-files` says otherwise.
const DEFAULT_EXTENSIONS: &str = "exe,dll,sys,drv,ocx,cpl,scr,efi,ax,acm,pyd,node";

const EXAMPLES: &str = "\
Examples:
  pdbwalker C:\\Windows\\System32            List PE files and their debug info
  pdbwalker --search C:\\Windows\\System32   List PE files whose PDB is on the symbol server
  pdbwalker --search --download ./bin       ...and save each one next to its binary
  pdbwalker --download foo.exe              Fetch foo.pdb next to foo.exe";

#[derive(Debug, Parser)]
#[command(version, about, after_help = EXAMPLES, max_term_width = 100)]
pub struct Cli {
    /// Directories or PE files to scan
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,

    /// Show detailed information about each binary
    #[arg(short, long)]
    pub verbose: bool,

    /// Print one JSON object per binary (JSON Lines) instead of text
    #[arg(long)]
    pub json: bool,

    /// Maximum recursion depth (default: unlimited)
    #[arg(long, value_name = "N", help_heading = "Scanning")]
    pub max_depth: Option<usize>,

    /// Follow symbolic links
    #[arg(long, help_heading = "Scanning")]
    pub follow_symlinks: bool,

    /// File extensions to treat as PE binaries
    #[arg(
        short,
        long = "ext",
        value_name = "EXT",
        value_delimiter = ',',
        default_value = DEFAULT_EXTENSIONS,
        help_heading = "Scanning"
    )]
    pub extensions: Vec<String>,

    /// Probe every file for a PE header, whatever its extension
    #[arg(short, long, help_heading = "Scanning")]
    pub all_files: bool,

    /// Only show binaries that have a PDB next to them
    #[arg(long, help_heading = "Filters")]
    pub local_only: bool,

    /// Only show binaries that reference a PDB (with --check-remote: one the server has)
    #[arg(long, help_heading = "Filters")]
    pub remote_only: bool,

    /// Search the symbol server: only show binaries whose PDB it provides
    #[arg(short, long, help_heading = "Symbol server")]
    pub search: bool,

    /// Download PDBs next to their binaries (foo.exe -> foo.pdb) when the server has them
    #[arg(short, long, help_heading = "Symbol server")]
    pub download: bool,

    /// Ask the symbol server whether each PDB exists
    #[arg(long, help_heading = "Symbol server")]
    pub check_remote: bool,

    /// Symbol server to query
    #[arg(
        long,
        value_name = "URL",
        default_value = DEFAULT_SYMBOL_SERVER,
        help_heading = "Symbol server"
    )]
    pub symbol_server: String,

    /// Number of parallel symbol server requests
    #[arg(
        short,
        long,
        value_name = "N",
        default_value_t = 16,
        value_parser = clap::value_parser!(u16).range(1..=256),
        help_heading = "Symbol server"
    )]
    pub jobs: u16,

    /// Collect PDB files into this directory and write a manifest.json
    #[arg(
        short,
        long = "output",
        value_name = "DIR",
        help_heading = "Output directory"
    )]
    pub output_dir: Option<PathBuf>,

    /// Also copy the binaries into the output directory
    #[arg(long, requires = "output_dir", help_heading = "Output directory")]
    pub copy_binaries: bool,

    /// Download PDBs that are not available locally into the output directory
    #[arg(long, requires = "output_dir", help_heading = "Output directory")]
    pub download_remote: bool,

    /// Overwrite existing files, including local PDBs that do not match their binary
    #[arg(short, long)]
    pub force: bool,
}

impl Cli {
    /// Whether the run should ask the server about PDBs it does not download.
    pub fn probes_server(&self) -> bool {
        self.check_remote || self.search
    }

    /// Whether only binaries with a server-confirmed PDB are reported.
    pub fn requires_available(&self) -> bool {
        self.search || (self.remote_only && self.check_remote)
    }

    /// Whether any part of the run talks to the symbol server.
    pub fn uses_network(&self) -> bool {
        self.probes_server() || self.download || self.download_remote
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn output_only_flags_require_output_dir() {
        assert!(Cli::try_parse_from(["pdbwalker", "--copy-binaries", "."]).is_err());
        assert!(Cli::try_parse_from(["pdbwalker", "--download-remote", "."]).is_err());
        assert!(Cli::try_parse_from(["pdbwalker", "--download-remote", "-o", "out", "."]).is_ok());
    }

    #[test]
    fn search_implies_a_server_probe() {
        let cli = Cli::try_parse_from(["pdbwalker", "-s", "."]).unwrap();
        assert!(cli.probes_server() && cli.requires_available() && cli.uses_network());

        let cli = Cli::try_parse_from(["pdbwalker", "--remote-only", "."]).unwrap();
        assert!(!cli.uses_network() && !cli.requires_available());
    }
}

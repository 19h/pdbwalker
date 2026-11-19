//! pdbwalker scans directories for PE binaries, reports on their debug
//! symbols and fetches matching PDB files from a symbol server.

mod cli;
mod engine;
mod pdb;
mod pe;
mod pool;
mod report;
mod scan;
mod symsrv;
mod term;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

use std::fs;
use std::io::{self, BufWriter, IsTerminal};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cli::Cli;
use crate::engine::Engine;
use crate::report::Reporter;
use crate::scan::Diagnostics;
use crate::symsrv::SymbolServer;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        // Whoever was reading our output went away (`pdbwalker ... | head`); not an error.
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pdbwalker: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the scan; `Ok(false)` means it completed but some operations failed.
fn run(cli: &Cli) -> Result<bool> {
    let server_base = symsrv::normalize_base(&cli.symbol_server)?;
    let server = cli.uses_network().then(SymbolServer::new).transpose()?;
    if let Some(dir) = &cli.output_dir {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create output directory {}", dir.display()))?;
    }

    let mut diagnostics = Diagnostics::default();
    let candidates = scan::discover(cli, &mut diagnostics);
    let entries = scan::inspect_all(&candidates, &mut diagnostics);
    for error in &diagnostics.errors {
        eprintln!("pdbwalker: error: {error}");
    }
    for warning in &diagnostics.warnings {
        eprintln!("pdbwalker: warning: {warning}");
    }

    let scanned = entries.len();
    let engine = Engine::new(cli, server_base, server);
    let tasks = engine.plan(entries);

    let stdout = io::stdout();
    let interactive = stdout.is_terminal();
    let out = BufWriter::new(anstream::AutoStream::auto(stdout.lock()));
    let mut reporter = Reporter::new(cli, &tasks, scanned, out, interactive);
    pool::run_ordered(
        &tasks,
        usize::from(cli.jobs),
        |task| engine.execute(task),
        &mut reporter,
    )?;
    let totals = reporter.finish()?;

    Ok(diagnostics.errors.is_empty() && totals.failures == 0)
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|err| err.kind() == io::ErrorKind::BrokenPipe)
}

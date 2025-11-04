use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use clap::Parser;
use walkdir::WalkDir;
use reqwest::blocking::Client;

mod formatter;
mod pdb_info;
mod pdb_downloader;

use formatter::{colors_from_env, format_size, print_header, render_kv_block, Colors};
use pdb_info::{BinaryInfo, check_remote_pdb_exists};
use pdb_downloader::{DownloadConfig, process_binary};

/// Scans directories for PE binaries and checks for local and remote debug symbols (PDB files)
#[derive(Parser, Debug)]
#[command(name = "pdbwalker", version = "0.1.0")]
#[command(about = "PE binary scanner with PDB symbol file detection and download capabilities")]
struct Cli {
    /// Directory to scan for PE binaries
    #[arg(value_name = "DIRECTORY", required = true)]
    directory: PathBuf,

    /// Show detailed information about each binary
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Only show binaries with local PDB files
    #[arg(long = "local-only")]
    local_only: bool,

    /// Only show binaries with remote PDB files available
    #[arg(long = "remote-only")]
    remote_only: bool,

    /// Check if remote PDB files exist (requires network requests)
    #[arg(long = "check-remote")]
    check_remote: bool,

    /// Copy binaries and PDB files to output directory
    #[arg(short = 'o', long = "output", value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// Copy binaries in addition to PDB files (requires --output)
    #[arg(long = "copy-binaries")]
    copy_binaries: bool,

    /// Download remote PDB files (requires --output)
    #[arg(long = "download-remote")]
    download_remote: bool,

    /// Overwrite existing files in output directory
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Output results as JSON
    #[arg(long = "json")]
    json: bool,

    /// Maximum recursion depth (default: unlimited)
    #[arg(long = "max-depth", value_name = "N")]
    max_depth: Option<usize>,

    /// Follow symbolic links
    #[arg(long = "follow-symlinks")]
    follow_symlinks: bool,
}

#[derive(Debug)]
struct ScanResult {
    binary: BinaryInfo,
    remote_available: Option<bool>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Validate output options
    if (cli.copy_binaries || cli.download_remote) && cli.output_dir.is_none() {
        anyhow::bail!("--copy-binaries and --download-remote require --output to be specified");
    }

    let colors = colors_from_env();
    let client = Client::new();

    if cli.verbose && !cli.json {
        print_header("PDB Walker - PE Binary Scanner", &colors);
        println!("{}Scanning directory: {}{}",
            colors.dim(), cli.directory.display(), colors.reset());
        if cli.check_remote {
            println!("{}Checking remote symbol availability...{}",
                colors.dim(), colors.reset());
        }
        println!();
    }

    // Scan for binaries
    let mut results = Vec::new();
    
    let mut walker = WalkDir::new(&cli.directory);
    
    if let Some(depth) = cli.max_depth {
        walker = walker.max_depth(depth);
    }
    
    if cli.follow_symlinks {
        walker = walker.follow_links(true);
    }

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if ext_str == "exe" || ext_str == "dll" {
                if let Some(binary_info) = BinaryInfo::from_file(path) {
                    // Apply filters
                    if cli.local_only && !binary_info.has_local_pdb() {
                        continue;
                    }
                    if cli.remote_only && !binary_info.has_remote_pdb() {
                        continue;
                    }

                    let remote_available = if cli.check_remote {
                        binary_info.pdb_info.as_ref().map(|info| {
                            check_remote_pdb_exists(&client, &info.url)
                        })
                    } else {
                        None
                    };

                    // Additional filter for remote-only with check
                    if cli.remote_only && cli.check_remote && remote_available == Some(false) {
                        continue;
                    }

                    results.push(ScanResult {
                        binary: binary_info,
                        remote_available,
                    });
                }
            }
        }
    }

    if cli.json {
        output_json(&results)?;
    } else {
        display_results(&results, &cli, &colors);
    }

    // Download/copy files if requested
    if let Some(ref output_dir) = cli.output_dir {
        let download_config = DownloadConfig {
            output_dir: output_dir.clone(),
            copy_binaries: cli.copy_binaries,
            download_remote: cli.download_remote,
            overwrite: cli.force,
        };

        let mut download_results = Vec::new();

        if !cli.json {
            println!();
            print_header("Copying/Downloading Files", &colors);
        }

        for result in &results {
            let pdb_url = result.binary.pdb_info.as_ref().map(|info| info.url.as_str());
            let local_pdb = result.binary.local_pdb_path.as_deref();
            
            let binary_path = Path::new(&result.binary.file_path);
            
            match process_binary(
                binary_path,
                pdb_url,
                local_pdb,
                &download_config,
                &client,
            ) {
                Ok(dl_result) => {
                    if !cli.json && cli.verbose {
                        if let Some(ref path) = dl_result.binary_copied {
                            println!("   {}✓{} Copied binary: {}{}{}",
                                colors.bright_green(), colors.reset(),
                                colors.bright_cyan(), path.display(), colors.reset());
                        }
                        if let Some(ref path) = dl_result.pdb_copied {
                            println!("   {}✓{} Copied PDB:    {}{}{}",
                                colors.bright_green(), colors.reset(),
                                colors.bright_cyan(), path.display(), colors.reset());
                        }
                        if let Some(ref path) = dl_result.pdb_downloaded {
                            println!("   {}✓{} Downloaded PDB: {}{}{}",
                                colors.bright_green(), colors.reset(),
                                colors.bright_cyan(), path.display(), colors.reset());
                        }
                    }
                    download_results.push((binary_path.to_path_buf(), dl_result));
                }
                Err(e) => {
                    if !cli.json {
                        eprintln!("   {}✗{} Error processing {}: {}",
                            colors.red(), colors.reset(),
                            binary_path.display(), e);
                    }
                }
            }
        }

        // Create manifest
        if !download_results.is_empty() {
            pdb_downloader::create_manifest(output_dir, &download_results)
                .context("Failed to create manifest")?;
            
            if !cli.json && cli.verbose {
                println!();
                println!("   {}✓{} Created manifest: {}{}{}",
                    colors.bright_green(), colors.reset(),
                    colors.bright_cyan(),
                    output_dir.join("manifest.json").display(),
                    colors.reset());
            }
        }
    }

    Ok(())
}

fn display_results(results: &[ScanResult], cli: &Cli, colors: &Colors) {
    if results.is_empty() {
        println!("{}No binaries found matching criteria.{}", colors.dim(), colors.reset());
        return;
    }

    println!("{}{}Found {} PE binarie(s){}",
        colors.bold(), colors.bright_cyan(), results.len(), colors.reset());
    println!();

    for (idx, result) in results.iter().enumerate() {
        display_binary_info(idx + 1, result, cli.verbose, colors);
        println!();
    }

    // Summary
    let local_count = results.iter().filter(|r| r.binary.has_local_pdb()).count();
    let remote_count = results.iter().filter(|r| r.binary.has_remote_pdb()).count();
    let remote_available = results.iter()
        .filter(|r| r.remote_available == Some(true))
        .count();

    println!("{}{}{}", colors.cyan(), "─".repeat(60), colors.reset());
    println!("{}{}Summary{}", colors.bold(), colors.bright_cyan(), colors.reset());
    println!();
    println!("   {}Total binaries:{} {}{}{}", 
        colors.bold(), colors.reset(),
        colors.bright_cyan(), results.len(), colors.reset());
    println!("   {}With local PDB:{} {}{}{}", 
        colors.bold(), colors.reset(),
        colors.bright_green(), local_count, colors.reset());
    println!("   {}With PDB info:{} {}{}{}", 
        colors.bold(), colors.reset(),
        colors.bright_cyan(), remote_count, colors.reset());
    
    if cli.check_remote {
        println!("   {}Remote available:{} {}{}{}", 
            colors.bold(), colors.reset(),
            colors.bright_yellow(), remote_available, colors.reset());
    }
}

fn display_binary_info(index: usize, result: &ScanResult, verbose: bool, colors: &Colors) {
    let binary = &result.binary;
    
    // Header
    let status_symbol = if binary.has_local_pdb() {
        format!("{}●{}", colors.bright_green(), colors.reset())
    } else if result.remote_available == Some(true) {
        format!("{}●{}", colors.bright_yellow(), colors.reset())
    } else if binary.has_remote_pdb() {
        format!("{}●{}", colors.yellow(), colors.reset())
    } else {
        format!("{}○{}", colors.dim(), colors.reset())
    };

    let bin_type = if binary.is_dll { "DLL" } else { "EXE" };
    
    println!("{} {}{}Binary #{}{} {}({}){}", 
        status_symbol,
        colors.bold(), colors.bright_cyan(),
        index,
        colors.reset(),
        colors.dim(),
        bin_type,
        colors.reset());

    // Basic info
    let mut pairs = vec![
        ("Path", binary.file_path.clone()),
        ("Size", format_size(binary.file_size)),
        ("Architecture", binary.architecture.clone()),
    ];

    if let Some(modified) = binary.file_modified {
        pairs.push(("Modified", modified.format("%Y-%m-%d %H:%M:%S UTC").to_string()));
    }

    render_kv_block(&mut String::new(), &pairs, 3, colors);
    for (key, value) in pairs {
        println!("   {}{}{}{}: {}{}{}",
            colors.bold(), colors.cyan(), key, colors.reset(),
            colors.bright_cyan(), value, colors.reset());
    }

    // PE details (verbose)
    if verbose {
        println!();
        println!("   {}PE Details:{}", colors.dim(), colors.reset());
        println!("      {}Image Base:{} {}0x{:X}{}",
            colors.cyan(), colors.reset(),
            colors.bright_cyan(), binary.image_base, colors.reset());
        println!("      {}Entry Point:{} {}0x{:X}{}",
            colors.cyan(), colors.reset(),
            colors.bright_cyan(), binary.entry_point, colors.reset());
        println!("      {}Subsystem:{} {}{}{}",
            colors.cyan(), colors.reset(),
            colors.bright_cyan(), binary.subsystem, colors.reset());
        
        if let Some(timestamp) = binary.timestamp {
            println!("      {}Timestamp:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(),
                timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                colors.reset());
        }
    }

    // PDB status
    println!();
    if let Some(ref local_pdb) = binary.local_pdb_path {
        println!("   {}{}Local PDB:{} {}✓ Found{}",
            colors.bold(), colors.green(), colors.reset(),
            colors.bright_green(), colors.reset());
        if verbose {
            println!("      {}Path:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), local_pdb, colors.reset());
        }
    } else {
        println!("   {}{}Local PDB:{} {}✗ Not found{}",
            colors.bold(), colors.dim(), colors.reset(),
            colors.dim(), colors.reset());
    }

    if let Some(ref pdb_info) = binary.pdb_info {
        let status = match result.remote_available {
            Some(true) => format!("{}✓ Available{}", colors.bright_green(), colors.reset()),
            Some(false) => format!("{}✗ Not available{}", colors.red(), colors.reset()),
            None => format!("{}? Not checked{}", colors.dim(), colors.reset()),
        };
        
        println!("   {}{}Remote PDB:{} {}{}",
            colors.bold(), colors.yellow(), colors.reset(),
            colors.bright_yellow(), status);
        
        if verbose {
            println!("      {}File:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), pdb_info.pdb_file_name, colors.reset());
            println!("      {}GUID:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), pdb_info.guid, colors.reset());
            println!("      {}Age:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), pdb_info.age, colors.reset());
            println!("      {}Signature:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), pdb_info.signature, colors.reset());
            println!("      {}URL:{} {}{}{}",
                colors.cyan(), colors.reset(),
                colors.bright_cyan(), pdb_info.url, colors.reset());
        }
    } else {
        println!("   {}{}Remote PDB:{} {}✗ No debug info{}",
            colors.bold(), colors.dim(), colors.reset(),
            colors.dim(), colors.reset());
    }
}

fn output_json(results: &[ScanResult]) -> Result<()> {
    use serde_json::json;

    for result in results {
        let binary = &result.binary;
        
        let json_output = json!({
            "file_path": binary.file_path,
            "file_size": binary.file_size,
            "file_modified": binary.file_modified.map(|dt| dt.to_rfc3339()),
            "architecture": binary.architecture,
            "image_base": format!("0x{:X}", binary.image_base),
            "entry_point": format!("0x{:X}", binary.entry_point),
            "timestamp": binary.timestamp.map(|dt| dt.to_rfc3339()),
            "subsystem": binary.subsystem,
            "is_dll": binary.is_dll,
            "local_pdb": {
                "available": binary.has_local_pdb(),
                "path": binary.local_pdb_path,
            },
            "remote_pdb": {
                "has_info": binary.has_remote_pdb(),
                "available": result.remote_available,
                "info": binary.pdb_info.as_ref().map(|info| json!({
                    "file_name": info.pdb_file_name,
                    "guid": info.guid,
                    "age": info.age,
                    "signature": info.signature,
                    "url": info.url,
                })),
            },
        });

        println!("{}", serde_json::to_string(&json_output)?);
    }

    Ok(())
}

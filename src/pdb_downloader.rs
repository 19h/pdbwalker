use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use reqwest::blocking::Client;

pub struct DownloadConfig {
    pub output_dir: PathBuf,
    pub copy_binaries: bool,
    pub download_remote: bool,
    pub overwrite: bool,
}

#[derive(Debug)]
pub struct DownloadResult {
    pub binary_copied: Option<PathBuf>,
    pub pdb_copied: Option<PathBuf>,
    pub pdb_downloaded: Option<PathBuf>,
}

impl DownloadResult {
    pub fn new() -> Self {
        DownloadResult {
            binary_copied: None,
            pdb_copied: None,
            pdb_downloaded: None,
        }
    }
}

pub fn process_binary(
    binary_path: &Path,
    pdb_url: Option<&str>,
    local_pdb_path: Option<&str>,
    config: &DownloadConfig,
    client: &Client,
) -> Result<DownloadResult> {
    let mut result = DownloadResult::new();
    
    // Create output directory if it doesn't exist
    fs::create_dir_all(&config.output_dir)
        .context("Failed to create output directory")?;

    let binary_name = binary_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid binary file name")?;

    // Copy binary if requested
    if config.copy_binaries {
        let dest_path = config.output_dir.join(binary_name);
        if !dest_path.exists() || config.overwrite {
            fs::copy(binary_path, &dest_path)
                .with_context(|| format!("Failed to copy binary to {:?}", dest_path))?;
            result.binary_copied = Some(dest_path);
        }
    }

    // Copy local PDB if it exists
    if let Some(local_pdb) = local_pdb_path {
        let local_pdb_path = Path::new(local_pdb);
        if local_pdb_path.exists() {
            let pdb_name = local_pdb_path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid PDB file name")?;
            let dest_path = config.output_dir.join(pdb_name);
            
            if !dest_path.exists() || config.overwrite {
                fs::copy(local_pdb_path, &dest_path)
                    .with_context(|| format!("Failed to copy PDB to {:?}", dest_path))?;
                result.pdb_copied = Some(dest_path);
            }
        }
    }

    // Download remote PDB if requested and local doesn't exist
    if config.download_remote && result.pdb_copied.is_none() {
        if let Some(url) = pdb_url {
            if let Some(pdb_name) = extract_pdb_name_from_url(url) {
                let dest_path = config.output_dir.join(pdb_name);
                
                if !dest_path.exists() || config.overwrite {
                    match download_pdb(client, url, &dest_path) {
                        Ok(_) => result.pdb_downloaded = Some(dest_path),
                        Err(e) => {
                            eprintln!("Warning: Failed to download PDB from {}: {}", url, e);
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

fn extract_pdb_name_from_url(url: &str) -> Option<&str> {
    url.rsplit('/').next()
}

fn download_pdb(client: &Client, url: &str, dest_path: &Path) -> Result<()> {
    let response = client
        .get(url)
        .send()
        .context("Failed to send download request")?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed with status: {}", response.status());
    }

    let bytes = response
        .bytes()
        .context("Failed to read response bytes")?;

    fs::write(dest_path, bytes)
        .with_context(|| format!("Failed to write PDB file to {:?}", dest_path))?;

    Ok(())
}

pub fn create_manifest(
    output_dir: &Path,
    results: &[(PathBuf, DownloadResult)],
) -> Result<()> {
    use serde_json::json;
    
    let manifest = results
        .iter()
        .map(|(binary, result)| {
            json!({
                "binary": binary.to_string_lossy(),
                "binary_copied": result.binary_copied.as_ref().map(|p| p.to_string_lossy()),
                "pdb_copied": result.pdb_copied.as_ref().map(|p| p.to_string_lossy()),
                "pdb_downloaded": result.pdb_downloaded.as_ref().map(|p| p.to_string_lossy()),
            })
        })
        .collect::<Vec<_>>();

    let manifest_path = output_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&json!({
        "files": manifest,
        "count": manifest.len(),
    }))?;

    fs::write(&manifest_path, manifest_json)
        .with_context(|| format!("Failed to write manifest to {:?}", manifest_path))?;

    Ok(())
}


use std::path::Path;
use exe::pe::VecPE;
use exe::headers::{ImageDebugDirectory, ImageDirectoryEntry, ImageDebugType};
use exe::{Buffer, PE, Arch};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct PdbInfo {
    pub pdb_file_name: String,
    pub guid: String,
    pub age: u32,
    pub signature: String,  // Combined GUID + Age for symbol server lookup
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub file_path: String,
    pub file_size: u64,
    pub file_modified: Option<DateTime<Utc>>,
    pub architecture: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub subsystem: String,
    pub is_dll: bool,
    pub pdb_info: Option<PdbInfo>,
    pub local_pdb_path: Option<String>,
}

impl BinaryInfo {
    pub fn from_file(path: &Path) -> Option<Self> {
        let metadata = path.metadata().ok()?;
        let file_size = metadata.len();
        
        let file_modified = metadata.modified()
            .ok()
            .and_then(|t| {
                let duration = t.duration_since(std::time::UNIX_EPOCH).ok()?;
                DateTime::from_timestamp(duration.as_secs() as i64, 0)
            });

        let pe_file = VecPE::from_disk_file(path).ok()?;
        
        // Get architecture
        let architecture = match pe_file.get_arch() {
            Ok(Arch::X86) => "x86",
            Ok(Arch::X64) => "x64",
            _ => "Unknown",
        }.to_string();

        // Get image base
        let image_base = pe_file.get_image_base().unwrap_or(0);
        
        // Get entry point
        let entry_point = pe_file.get_entrypoint().map(|ep| ep.0 as u64).unwrap_or(0);

        // Get timestamp and subsystem
        let (timestamp, subsystem) = if let Ok(nt64) = pe_file.get_nt_headers_64() {
            let ts = DateTime::from_timestamp(nt64.file_header.time_date_stamp as i64, 0);
            let sub = match nt64.optional_header.subsystem {
                    1 => "Native",
                    2 => "Windows GUI",
                    3 => "Windows CUI",
                    5 => "OS/2 CUI",
                    7 => "POSIX CUI",
                    9 => "Windows CE GUI",
                    10 => "EFI Application",
                    11 => "EFI Boot Service Driver",
                    12 => "EFI Runtime Driver",
                    13 => "EFI ROM",
                    14 => "Xbox",
                    16 => "Windows Boot Application",
                    _ => "Unknown",
                }.to_string();
            (ts, sub)
        } else if let Ok(nt32) = pe_file.get_nt_headers_32() {
            let ts = DateTime::from_timestamp(nt32.file_header.time_date_stamp as i64, 0);
            let sub = match nt32.optional_header.subsystem {
                    1 => "Native",
                    2 => "Windows GUI",
                    3 => "Windows CUI",
                    5 => "OS/2 CUI",
                    7 => "POSIX CUI",
                    9 => "Windows CE GUI",
                    10 => "EFI Application",
                    11 => "EFI Boot Service Driver",
                    12 => "EFI Runtime Driver",
                    13 => "EFI ROM",
                    14 => "Xbox",
                    16 => "Windows Boot Application",
                    _ => "Unknown",
                }.to_string();
            (ts, sub)
        } else {
            (None, "Unknown".to_string())
        };

        // Check if DLL
        let is_dll = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase() == "dll")
            .unwrap_or(false);

        // Extract PDB info
        let pdb_info = extract_pdb_info(&pe_file);
        
        // Check for local PDB
        let local_pdb_path = if path.with_extension("pdb").exists() {
            Some(path.with_extension("pdb").to_string_lossy().to_string())
        } else {
            None
        };

        Some(BinaryInfo {
            file_path: path.to_string_lossy().to_string(),
            file_size,
            file_modified,
            architecture,
            image_base,
            entry_point,
            timestamp,
            subsystem,
            is_dll,
            pdb_info,
            local_pdb_path,
        })
    }

    pub fn has_local_pdb(&self) -> bool {
        self.local_pdb_path.is_some()
    }

    pub fn has_remote_pdb(&self) -> bool {
        self.pdb_info.is_some()
    }
}

fn extract_pdb_info(pe_file: &VecPE) -> Option<PdbInfo> {
    const SYMBOLS_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
    
    let debug_data_dir = pe_file.get_data_directory(ImageDirectoryEntry::Debug).ok()?;
    if debug_data_dir.size == 0 {
        return None;
    }

    let offset_obj = pe_file.rva_to_offset(debug_data_dir.virtual_address).ok()?;
    let offset: usize = offset_obj.into();
    let size = debug_data_dir.size as usize;

    let raw_debug_data = pe_file.get(offset..offset + size)?;
    let entry_size = std::mem::size_of::<ImageDebugDirectory>();
    if entry_size == 0 {
        return None;
    }
    let num_entries = raw_debug_data.len() / entry_size;

    let debug_entries: &[ImageDebugDirectory] = unsafe {
        std::slice::from_raw_parts(
            raw_debug_data.as_ptr() as *const ImageDebugDirectory,
            num_entries,
        )
    };

    for entry in debug_entries {
        if entry.type_ == ImageDebugType::CodeView as u32 {
            let cv_offset: usize = entry.pointer_to_raw_data.into();
            let cv_size: usize = entry.size_of_data as usize;

            let cv_data = pe_file.get(cv_offset..(cv_offset + cv_size))?;
            if cv_data.len() < 24 || &cv_data[0..4] != b"RSDS" {
                continue;
            }

            let guid_bytes = &cv_data[4..20];
            let age = u32::from_le_bytes(cv_data[20..24].try_into().unwrap());
            
            let pdb_path_bytes = &cv_data[24..];
            if let Some(nul_pos) = pdb_path_bytes.iter().position(|&b| b == 0) {
                if let Ok(pdb_full_path) = std::str::from_utf8(&pdb_path_bytes[..nul_pos]) {
                    let pdb_file_name = Path::new(pdb_full_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default()
                        .to_string();

                    let data1 = u32::from_le_bytes(guid_bytes[0..4].try_into().unwrap());
                    let data2 = u16::from_le_bytes(guid_bytes[4..6].try_into().unwrap());
                    let data3 = u16::from_le_bytes(guid_bytes[6..8].try_into().unwrap());
                    let data4 = &guid_bytes[8..16];

                    let guid_string = format!(
                        "{:08X}{:04X}{:04X}{}",
                        data1, data2, data3,
                        data4.iter().map(|b| format!("{:02X}", b)).collect::<String>()
                    );

                    let guid_formatted = format!(
                        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}}}",
                        data1, data2, data3,
                        data4[0], data4[1],
                        data4[2..].iter().map(|b| format!("{:02X}", b)).collect::<String>()
                    );

                    let signature = format!("{}{:x}", guid_string, age);

                    let url = format!(
                        "{}/{}/{}/{}",
                        SYMBOLS_SERVER, pdb_file_name, signature, pdb_file_name
                    );

                    return Some(PdbInfo {
                        pdb_file_name,
                        guid: guid_formatted,
                        age,
                        signature,
                        url,
                    });
                }
            }
        }
    }

    None
}

pub fn check_remote_pdb_exists(client: &reqwest::blocking::Client, url: &str) -> bool {
    client.head(url)
        .send()
        .map(|resp| resp.status() == reqwest::StatusCode::OK)
        .unwrap_or(false)
}


//! Builders for tiny but structurally valid PE and PDB files.
//!
//! Shared by the unit tests (through `#[path]`) and the integration tests.
#![allow(dead_code)]

/// File offset of the debug directory in images built by [`pe_image`].
pub const DEBUG_DIRECTORY_OFFSET: usize = 0x200;

const SECTION_RVA: u32 = 0x1000;
const DEBUG_ENTRY_LEN: u32 = 28;

pub struct PeSpec {
    pub pe32_plus: bool,
    pub dll: bool,
    /// GUID, age and PDB path of the CodeView record; `None` omits the debug directory.
    pub pdb: Option<([u8; 16], u32, &'static str)>,
}

impl Default for PeSpec {
    fn default() -> Self {
        Self {
            pe32_plus: true,
            dll: false,
            pdb: None,
        }
    }
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    put(bytes, at, &value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    put(bytes, at, &value.to_le_bytes());
}

/// Builds a one-section PE image whose section holds the debug directory.
pub fn pe_image(spec: &PeSpec) -> Vec<u8> {
    let mut image = vec![0u8; 0x400];
    let nt = 0x40;
    let optional = nt + 24;
    // Machine, optional header magic and length, offset of the data directories.
    let (machine, magic, optional_len, directories): (u16, u16, u16, usize) = if spec.pe32_plus {
        (0x8664, 0x20b, 0xf0, optional + 112)
    } else {
        (0x014c, 0x10b, 0xe0, optional + 96)
    };
    let characteristics = if spec.dll { 0x2022 } else { 0x0022 };
    let section = optional + usize::from(optional_len);

    // DOS header
    put(&mut image, 0, b"MZ");
    put_u32(&mut image, 0x3c, nt as u32);

    // NT signature and COFF header
    put(&mut image, nt, b"PE\0\0");
    put_u16(&mut image, nt + 4, machine);
    put_u16(&mut image, nt + 6, 1);
    put_u32(&mut image, nt + 8, 0x5f00_0000);
    put_u16(&mut image, nt + 20, optional_len);
    put_u16(&mut image, nt + 22, characteristics);

    // Optional header
    put_u16(&mut image, optional, magic);
    put_u32(&mut image, optional + 16, 0x1234);
    if spec.pe32_plus {
        put(&mut image, optional + 24, &0x1_4000_0000u64.to_le_bytes());
    } else {
        put_u32(&mut image, optional + 28, 0x40_0000);
    }
    put_u32(&mut image, optional + 32, 0x1000);
    put_u32(&mut image, optional + 36, 0x200);
    put_u32(&mut image, optional + 56, 0x2000);
    put_u32(&mut image, optional + 60, 0x200);
    put_u16(&mut image, optional + 68, 3);
    put_u32(&mut image, directories - 4, 16);

    // Section header
    put(&mut image, section, b".rdata");
    put_u32(&mut image, section + 8, 0x200);
    put_u32(&mut image, section + 12, SECTION_RVA);
    put_u32(&mut image, section + 16, 0x200);
    put_u32(&mut image, section + 20, DEBUG_DIRECTORY_OFFSET as u32);

    if let Some((guid, age, path)) = spec.pdb {
        let mut record = b"RSDS".to_vec();
        record.extend_from_slice(&guid);
        record.extend_from_slice(&age.to_le_bytes());
        record.extend_from_slice(path.as_bytes());
        record.push(0);

        put_u32(&mut image, directories + 6 * 8, SECTION_RVA);
        put_u32(&mut image, directories + 6 * 8 + 4, DEBUG_ENTRY_LEN);

        let entry = DEBUG_DIRECTORY_OFFSET;
        put_u32(&mut image, entry + 12, 2);
        put_u32(&mut image, entry + 16, record.len() as u32);
        put_u32(&mut image, entry + 20, SECTION_RVA + DEBUG_ENTRY_LEN);
        put_u32(&mut image, entry + 24, entry as u32 + DEBUG_ENTRY_LEN);
        put(&mut image, entry + DEBUG_ENTRY_LEN as usize, &record);
    }
    image
}

/// Builds a minimal MSF 7.00 container whose PDB info stream carries `guid` and `age`.
pub fn msf_pdb(guid: [u8; 16], age: u32) -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut pdb = vec![0u8; 6 * BLOCK];

    // Superblock: the directory is 24 bytes long and its block list lives in block 3.
    put(&mut pdb, 0, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    put_u32(&mut pdb, 0x20, BLOCK as u32);
    put_u32(&mut pdb, 0x24, 1);
    put_u32(&mut pdb, 0x28, 6);
    put_u32(&mut pdb, 0x2c, 24);
    put_u32(&mut pdb, 0x34, 3);

    // Block map: the directory occupies block 4.
    put_u32(&mut pdb, 3 * BLOCK, 4);

    // Directory: stream 0 spans blocks 1-2, stream 1 (PDB info) is block 5.
    let directory = [2u32, 600, 28, 1, 2, 5];
    for (index, value) in directory.into_iter().enumerate() {
        put_u32(&mut pdb, 4 * BLOCK + index * 4, value);
    }

    // PDB info stream: version, signature, age, GUID.
    put_u32(&mut pdb, 5 * BLOCK, 20_000_404);
    put_u32(&mut pdb, 5 * BLOCK + 4, 0x5f00_0000);
    put_u32(&mut pdb, 5 * BLOCK + 8, age);
    put(&mut pdb, 5 * BLOCK + 12, &guid);
    pdb
}

/// Builds the metadata root of a portable PDB whose `#Pdb` stream starts with `guid`.
pub fn portable_pdb(guid: [u8; 16]) -> Vec<u8> {
    let mut pdb = b"BSJB".to_vec();
    pdb.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0]);
    pdb.extend_from_slice(&12u32.to_le_bytes());
    pdb.extend_from_slice(b"PDB v1.0\0\0\0\0");
    pdb.extend_from_slice(&[0, 0, 2, 0]);
    // Stream headers: a decoy first, then `#Pdb`.
    for (offset, name) in [(96u32, &b"#Strings\0\0\0\0"[..]), (72, b"#Pdb\0\0\0\0")] {
        pdb.extend_from_slice(&offset.to_le_bytes());
        pdb.extend_from_slice(&20u32.to_le_bytes());
        pdb.extend_from_slice(name);
    }
    assert_eq!(pdb.len(), 68);
    pdb.resize(72, 0);
    pdb.extend_from_slice(&guid);
    pdb.extend_from_slice(&0x5f00_0000u32.to_le_bytes());
    pdb.resize(128, 0);
    pdb
}

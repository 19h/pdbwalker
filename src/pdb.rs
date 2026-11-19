//! Just enough PDB parsing to tell which build a symbol file belongs to.

use std::io::{self, Read, Seek, SeekFrom};

use crate::pe::{Guid, PdbId};

const MSF7_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const MSF2_MAGIC: &[u8; 44] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";
const PORTABLE_MAGIC: &[u8; 4] = b"BSJB";

/// Number of leading bytes [`has_pdb_magic`] needs to recognise every format.
pub const MAGIC_LEN: usize = MSF2_MAGIC.len();

const MSF7_SUPERBLOCK_LEN: usize = 0x38;
/// Size of the PDB info stream up to and including the GUID.
const PDB_INFO_LEN: usize = 28;
/// Index of the PDB info stream in the MSF stream directory.
const PDB_INFO_STREAM: u32 = 1;
const NIL_STREAM_LEN: u32 = u32::MAX;
const PORTABLE_HEAD_LEN: u64 = 4096;

/// Whether `prefix` starts like a native (MSF) or portable PDB.
pub fn has_pdb_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(MSF7_MAGIC)
        || prefix.starts_with(MSF2_MAGIC)
        || prefix.starts_with(PORTABLE_MAGIC)
}

/// Reads the identity of a PDB file.
///
/// Returns `Ok(None)` for formats whose identity is not understood (such as
/// PDB 2.0) and for files that are truncated or not PDBs at all.
pub fn read_id<R: Read + Seek>(reader: &mut R) -> io::Result<Option<PdbId>> {
    let mut superblock = [0u8; MSF7_SUPERBLOCK_LEN];
    if !read_exact_at(reader, 0, &mut superblock)? {
        return Ok(None);
    }
    let guid = if superblock.starts_with(MSF7_MAGIC) {
        read_msf7_guid(reader, &superblock)?
    } else if superblock.starts_with(PORTABLE_MAGIC) {
        read_portable_guid(reader)?
    } else {
        None
    };
    Ok(guid.map(|guid| PdbId::Guid(Guid(guid))))
}

/// Locates the PDB info stream through the MSF stream directory and reads its GUID.
fn read_msf7_guid<R: Read + Seek>(
    reader: &mut R,
    superblock: &[u8; MSF7_SUPERBLOCK_LEN],
) -> io::Result<Option<[u8; 16]>> {
    let field = |at: usize| u64::from(le_u32(&superblock[at..]));
    let (block_len, directory_len, block_map) = (field(0x20), field(0x2c), field(0x34));
    if !(512..=1 << 20).contains(&block_len) || !block_len.is_power_of_two() {
        return Ok(None);
    }

    // The directory is itself scattered over blocks; this reads the u32 at a
    // logical directory offset by going through the block map.
    let directory_u32 = |reader: &mut R, offset: u64| -> io::Result<Option<u32>> {
        if offset + 4 > directory_len {
            return Ok(None);
        }
        let mut word = [0u8; 4];
        let map_entry = block_map * block_len + offset / block_len * 4;
        if !read_exact_at(reader, map_entry, &mut word)? {
            return Ok(None);
        }
        let position = u64::from(u32::from_le_bytes(word)) * block_len + offset % block_len;
        Ok(read_exact_at(reader, position, &mut word)?.then(|| u32::from_le_bytes(word)))
    };

    // Directory layout: stream count, one length per stream, then every
    // stream's block numbers back to back.
    let Some(stream_count) = directory_u32(reader, 0)? else {
        return Ok(None);
    };
    if stream_count <= PDB_INFO_STREAM {
        return Ok(None);
    }
    let mut preceding_blocks = 0;
    for stream in 0..PDB_INFO_STREAM {
        match directory_u32(reader, 4 + 4 * u64::from(stream))? {
            Some(NIL_STREAM_LEN) => {}
            Some(len) => preceding_blocks += u64::from(len).div_ceil(block_len),
            None => return Ok(None),
        }
    }
    match directory_u32(reader, 4 + 4 * u64::from(PDB_INFO_STREAM))? {
        Some(len) if len != NIL_STREAM_LEN && len as usize >= PDB_INFO_LEN => {}
        _ => return Ok(None),
    }
    let blocks_at = 4 + 4 * u64::from(stream_count);
    let Some(first_block) = directory_u32(reader, blocks_at + 4 * preceding_blocks)? else {
        return Ok(None);
    };

    // Version, signature and age precede the GUID.
    let mut info = [0u8; PDB_INFO_LEN];
    if !read_exact_at(reader, u64::from(first_block) * block_len, &mut info)? {
        return Ok(None);
    }
    Ok(info.last_chunk().copied())
}

/// Reads the GUID that opens the `#Pdb` stream of a portable PDB.
fn read_portable_guid<R: Read + Seek>(reader: &mut R) -> io::Result<Option<[u8; 16]>> {
    reader.seek(SeekFrom::Start(0))?;
    let mut head = Vec::new();
    reader.take(PORTABLE_HEAD_LEN).read_to_end(&mut head)?;

    let Some(offset) = portable_pdb_stream_offset(&head) else {
        return Ok(None);
    };
    let mut guid = [0u8; 16];
    Ok(read_exact_at(reader, u64::from(offset), &mut guid)?.then_some(guid))
}

/// Walks the stream headers of an ECMA-335 metadata root looking for `#Pdb`.
fn portable_pdb_stream_offset(head: &[u8]) -> Option<u32> {
    let version_len = le_u32(head.get(12..16)?) as usize;
    if version_len > 256 {
        return None;
    }
    let mut cursor = 16 + version_len;
    let stream_count = u16::from_le_bytes(*head.get(cursor + 2..)?.first_chunk()?);
    cursor += 4;

    for _ in 0..stream_count {
        let offset = le_u32(head.get(cursor..cursor + 4)?);
        let name = head.get(cursor + 8..)?;
        let name_len = name.iter().position(|&byte| byte == 0)?;
        if &name[..name_len] == b"#Pdb" {
            return Some(offset);
        }
        // Names are NUL-terminated and padded to a four-byte boundary.
        cursor += 8 + (name_len + 4) / 4 * 4;
    }
    None
}

/// Fills `buf` from `offset`; returns `false` if the file ends first.
fn read_exact_at<R: Read + Seek>(reader: &mut R, offset: u64, buf: &mut [u8]) -> io::Result<bool> {
    reader.seek(SeekFrom::Start(offset))?;
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(err),
    }
}

/// Decodes the little-endian `u32` at the start of `bytes`.
fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(*bytes.first_chunk().expect("at least four bytes"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::support;

    const GUID: [u8; 16] = *b"0123456789abcdef";

    fn id_of(bytes: &[u8]) -> Option<PdbId> {
        read_id(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn reads_guid_from_msf() {
        let pdb = support::msf_pdb(GUID, 3);
        assert!(has_pdb_magic(&pdb));
        assert_eq!(id_of(&pdb), Some(PdbId::Guid(Guid(GUID))));
    }

    #[test]
    fn reads_guid_from_portable_pdb() {
        let pdb = support::portable_pdb(GUID);
        assert!(has_pdb_magic(&pdb));
        assert_eq!(id_of(&pdb), Some(PdbId::Guid(Guid(GUID))));
    }

    #[test]
    fn unknown_or_damaged_files_have_no_id() {
        assert_eq!(id_of(b""), None);
        assert_eq!(id_of(&[0u8; 4096]), None);
        assert!(!has_pdb_magic(b"MSCF\0\0\0\0"));

        let mut pdb2 = MSF2_MAGIC.to_vec();
        pdb2.resize(4096, 0);
        assert!(has_pdb_magic(&pdb2));
        assert_eq!(id_of(&pdb2), None);
    }

    #[test]
    fn truncated_files_never_panic() {
        for pdb in [support::msf_pdb(GUID, 1), support::portable_pdb(GUID)] {
            for len in 0..pdb.len() {
                let _ = id_of(&pdb[..len]);
            }
        }
    }

    #[test]
    fn corrupt_block_numbers_are_tolerated() {
        let mut pdb = support::msf_pdb(GUID, 1);
        // Point the block map far outside the file.
        pdb[0x34..0x38].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(id_of(&pdb), None);
    }
}

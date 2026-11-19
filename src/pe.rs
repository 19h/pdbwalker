//! A minimal reader for the parts of the PE/COFF format pdbwalker needs.
//!
//! Only the headers, the section table and the debug directory are read, so
//! inspecting an image costs a handful of small reads no matter how large the
//! file is. Every offset taken from the file is bounds-checked; malformed
//! input yields `Ok(None)` rather than an error or a panic.

use std::borrow::Cow;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

/// How much of the file is read up front; covers the headers of virtually every image.
const HEAD_LEN: usize = 4096;
const DOS_HEADER_LEN: usize = 0x40;
const NT_SIGNATURE_AND_COFF_LEN: usize = 24;
const SECTION_HEADER_LEN: usize = 40;
const DEBUG_ENTRY_LEN: usize = 28;

const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const IMAGE_FILE_DLL: u16 = 0x2000;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

/// Caps that keep hostile headers from triggering large reads.
const MAX_DEBUG_ENTRIES: usize = 64;
const MAX_CODEVIEW_LEN: usize = 4096;

/// The header fields of a PE image, plus its CodeView debug record if present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub machine: u16,
    pub characteristics: u16,
    /// `TimeDateStamp` of the COFF header (seconds since the Unix epoch).
    pub timestamp: u32,
    pub image_base: u64,
    /// Entry point as a relative virtual address.
    pub entry_point: u32,
    pub subsystem: u16,
    pub codeview: Option<CodeView>,
}

impl PeImage {
    /// Parses a PE image, returning `Ok(None)` if `reader` does not hold one.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> io::Result<Option<Self>> {
        let mut source = Source::new(reader)?;

        let Some(nt_offset) = nt_headers_offset(&source.head) else {
            return Ok(None);
        };
        let Some(coff) = source
            .read(nt_offset, NT_SIGNATURE_AND_COFF_LEN)?
            .and_then(|bytes| CoffHeader::parse(&bytes))
        else {
            return Ok(None);
        };
        let optional_offset = nt_offset + NT_SIGNATURE_AND_COFF_LEN as u64;
        let Some(optional) = source
            .read(optional_offset, usize::from(coff.optional_header_len))?
            .and_then(|bytes| OptionalHeader::parse(&bytes))
        else {
            return Ok(None);
        };

        let codeview = match optional.debug_directory {
            Some(directory) => {
                let sections_offset = optional_offset + u64::from(coff.optional_header_len);
                let sections_len = usize::from(coff.section_count) * SECTION_HEADER_LEN;
                let sections = source
                    .read(sections_offset, sections_len)?
                    .map(|bytes| parse_sections(&bytes))
                    .unwrap_or_default();
                let layout = Layout {
                    sections,
                    headers_len: optional.headers_len,
                };
                find_codeview(&mut source, &layout, directory)?
            }
            None => None,
        };

        Ok(Some(Self {
            machine: coff.machine,
            characteristics: coff.characteristics,
            timestamp: coff.timestamp,
            image_base: optional.image_base,
            entry_point: optional.entry_point,
            subsystem: optional.subsystem,
            codeview,
        }))
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    /// Short label for the kind of image.
    pub fn kind(&self) -> &'static str {
        if self.is_dll() { "DLL" } else { "EXE" }
    }

    pub fn architecture(&self) -> &'static str {
        match self.machine {
            0x014c => "x86",
            0x8664 => "x64",
            0xaa64 => "ARM64",
            0x01c0 | 0x01c2 | 0x01c4 => "ARM",
            0x0200 => "IA64",
            0x0ebc => "EBC",
            0x5032 => "RISCV32",
            0x5064 => "RISCV64",
            0x6264 => "LoongArch64",
            _ => "Unknown",
        }
    }

    pub fn subsystem_name(&self) -> &'static str {
        match self.subsystem {
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
        }
    }
}

/// A CodeView record: the link from an image to the PDB it was built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView {
    pub id: PdbId,
    pub age: u32,
    /// PDB path as recorded by the linker, usually an absolute build-machine path.
    pub pdb_path: String,
}

impl CodeView {
    fn parse(data: &[u8]) -> Option<Self> {
        let (id, age, path) = match data.first_chunk::<4>()? {
            b"RSDS" => {
                let guid = Guid(array_at(data, 4)?);
                (PdbId::Guid(guid), u32_at(data, 20)?, data.get(24..)?)
            }
            // NB10 layout: signature, offset, timestamp, age, path.
            b"NB10" => (
                PdbId::Timestamp(u32_at(data, 8)?),
                u32_at(data, 12)?,
                data.get(16..)?,
            ),
            _ => return None,
        };
        let path = path.split(|&byte| byte == 0).next()?;
        let record = Self {
            id,
            age,
            pdb_path: String::from_utf8_lossy(path).into_owned(),
        };
        // A record without a usable file name cannot be looked up anywhere.
        (!matches!(record.pdb_file_name(), "" | "." | "..")).then_some(record)
    }

    /// File name of the PDB, without the build-machine directory.
    pub fn pdb_file_name(&self) -> &str {
        self.pdb_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.pdb_path)
    }

    /// The identifier symbol servers index this PDB under.
    pub fn symbol_key(&self) -> String {
        match &self.id {
            PdbId::Guid(guid) => format!("{guid:X}{:X}", self.age),
            PdbId::Timestamp(timestamp) => format!("{timestamp:08X}{:X}", self.age),
        }
    }
}

/// What identifies a particular build of a PDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbId {
    /// PDB 7.0 (`RSDS`), used by every toolchain since Visual Studio .NET.
    Guid(Guid),
    /// PDB 2.0 (`NB10`), used by Visual C++ 6 and earlier.
    Timestamp(u32),
}

/// A GUID in its on-disk (mixed-endian) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    fn fields(&self) -> (u32, u16, u16, &[u8]) {
        let b = &self.0;
        (
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            &b[8..],
        )
    }
}

/// Registry format: `{01234567-89AB-CDEF-0123-456789ABCDEF}`.
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (data1, data2, data3, data4) = self.fields();
        write!(f, "{{{data1:08X}-{data2:04X}-{data3:04X}-")?;
        for (index, byte) in data4.iter().enumerate() {
            if index == 2 {
                f.write_str("-")?;
            }
            write!(f, "{byte:02X}")?;
        }
        f.write_str("}")
    }
}

/// Symbol server format: 32 hex digits without punctuation.
impl fmt::UpperHex for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (data1, data2, data3, data4) = self.fields();
        write!(f, "{data1:08X}{data2:04X}{data3:04X}")?;
        data4.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
    }
}

/// Random access to a file with its first [`HEAD_LEN`] bytes cached.
struct Source<'r, R> {
    reader: &'r mut R,
    head: Vec<u8>,
}

impl<'r, R: Read + Seek> Source<'r, R> {
    fn new(reader: &'r mut R) -> io::Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let mut head = Vec::with_capacity(HEAD_LEN);
        reader.take(HEAD_LEN as u64).read_to_end(&mut head)?;
        Ok(Self { reader, head })
    }

    /// Returns `len` bytes at `offset`, or `None` if the file ends before that.
    fn read(&mut self, offset: u64, len: usize) -> io::Result<Option<Cow<'_, [u8]>>> {
        let cached = usize::try_from(offset)
            .ok()
            .and_then(|start| self.head.get(start..start.checked_add(len)?));
        if let Some(bytes) = cached {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        let mut bytes = vec![0; len];
        self.reader.seek(SeekFrom::Start(offset))?;
        match self.reader.read_exact(&mut bytes) {
            Ok(()) => Ok(Some(Cow::Owned(bytes))),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(err) => Err(err),
        }
    }
}

struct CoffHeader {
    machine: u16,
    section_count: u16,
    timestamp: u32,
    optional_header_len: u16,
    characteristics: u16,
}

impl CoffHeader {
    /// Parses the `PE\0\0` signature and the COFF file header that follows it.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if !bytes.starts_with(b"PE\0\0") {
            return None;
        }
        Some(Self {
            machine: u16_at(bytes, 4)?,
            section_count: u16_at(bytes, 6)?,
            timestamp: u32_at(bytes, 8)?,
            optional_header_len: u16_at(bytes, 20)?,
            characteristics: u16_at(bytes, 22)?,
        })
    }
}

#[derive(Clone, Copy)]
struct DataDirectory {
    rva: u32,
    len: u32,
}

struct OptionalHeader {
    entry_point: u32,
    image_base: u64,
    headers_len: u32,
    subsystem: u16,
    debug_directory: Option<DataDirectory>,
}

impl OptionalHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let (image_base, directories_at) = match u16_at(bytes, 0)? {
            PE32_MAGIC => (u64::from(u32_at(bytes, 28)?), 96),
            PE32_PLUS_MAGIC => (u64_at(bytes, 24)?, 112),
            _ => return None,
        };
        let directory_count = u32_at(bytes, directories_at - 4)? as usize;
        let debug_at = directories_at + DEBUG_DIRECTORY_INDEX * 8;
        // A truncated directory table just means "no debug directory".
        let debug_directory = (directory_count > DEBUG_DIRECTORY_INDEX)
            .then(|| {
                Some(DataDirectory {
                    rva: u32_at(bytes, debug_at)?,
                    len: u32_at(bytes, debug_at + 4)?,
                })
            })
            .flatten()
            .filter(|directory| directory.rva != 0 && directory.len != 0);

        Some(Self {
            entry_point: u32_at(bytes, 16)?,
            image_base,
            headers_len: u32_at(bytes, 60)?,
            subsystem: u16_at(bytes, 68)?,
            debug_directory,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Section {
    virtual_address: u32,
    raw_offset: u32,
    raw_len: u32,
}

/// What is needed to translate relative virtual addresses into file offsets.
struct Layout {
    sections: Vec<Section>,
    headers_len: u32,
}

impl Layout {
    fn file_offset(&self, rva: u32) -> Option<u64> {
        let in_section = self.sections.iter().find_map(|section| {
            let delta = rva.checked_sub(section.virtual_address)?;
            (delta < section.raw_len).then(|| u64::from(section.raw_offset) + u64::from(delta))
        });
        // The headers are mapped at RVA 0, so addresses inside them are file offsets.
        in_section.or_else(|| (rva < self.headers_len).then_some(u64::from(rva)))
    }
}

fn nt_headers_offset(head: &[u8]) -> Option<u64> {
    (head.len() >= DOS_HEADER_LEN && head.starts_with(b"MZ"))
        .then(|| u32_at(head, 0x3c).map(u64::from))
        .flatten()
}

fn parse_sections(bytes: &[u8]) -> Vec<Section> {
    bytes
        .as_chunks::<SECTION_HEADER_LEN>()
        .0
        .iter()
        .filter_map(|header| {
            Some(Section {
                virtual_address: u32_at(header, 12)?,
                raw_len: u32_at(header, 16)?,
                raw_offset: u32_at(header, 20)?,
            })
        })
        .collect()
}

/// Walks the debug directory and returns the first well-formed CodeView record.
fn find_codeview<R: Read + Seek>(
    source: &mut Source<'_, R>,
    layout: &Layout,
    directory: DataDirectory,
) -> io::Result<Option<CodeView>> {
    let Some(offset) = layout.file_offset(directory.rva) else {
        return Ok(None);
    };
    let len = (directory.len as usize).min(MAX_DEBUG_ENTRIES * DEBUG_ENTRY_LEN);
    let Some(entries) = source.read(offset, len)?.map(Cow::into_owned) else {
        return Ok(None);
    };

    for entry in entries.as_chunks::<DEBUG_ENTRY_LEN>().0 {
        // IMAGE_DEBUG_DIRECTORY: Type at 12, SizeOfData at 16, AddressOfRawData
        // (an RVA) at 20 and PointerToRawData (a file offset) at 24.
        let field = |at| u32_at(entry, at).unwrap_or(0);
        if field(12) != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let data_offset = match field(24) {
            0 => layout.file_offset(field(20)),
            pointer => Some(u64::from(pointer)),
        };
        let Some(data_offset) = data_offset else {
            continue;
        };
        let data_len = (field(16) as usize).min(MAX_CODEVIEW_LEN);
        let record = source
            .read(data_offset, data_len)?
            .and_then(|data| CodeView::parse(&data));
        if record.is_some() {
            return Ok(record);
        }
    }
    Ok(None)
}

/// The `N` bytes at offset `at`, if `bytes` is long enough.
fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..)?.first_chunk().copied()
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    array_at(bytes, at).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    array_at(bytes, at).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    array_at(bytes, at).map(u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::support::{self, PeSpec};

    const GUID: [u8; 16] = [
        0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];

    fn parse(bytes: &[u8]) -> Option<PeImage> {
        PeImage::parse(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn guid_formats() {
        let guid = Guid(GUID);
        assert_eq!(guid.to_string(), "{01234567-89AB-CDEF-0123-456789ABCDEF}");
        assert_eq!(format!("{guid:X}"), "0123456789ABCDEF0123456789ABCDEF");
    }

    #[test]
    fn parses_pe32_plus_with_rsds() {
        let image = parse(&support::pe_image(&PeSpec {
            pdb: Some((GUID, 0x1b, r"D:\build\obj\amd64\ntkrnlmp.pdb")),
            ..PeSpec::default()
        }))
        .unwrap();

        assert_eq!(image.architecture(), "x64");
        assert_eq!(image.kind(), "EXE");
        assert_eq!(image.image_base, 0x1_4000_0000);
        assert_eq!(image.entry_point, 0x1234);
        assert_eq!(image.timestamp, 0x5f00_0000);
        assert_eq!(image.subsystem_name(), "Windows CUI");

        let codeview = image.codeview.unwrap();
        assert_eq!(codeview.id, PdbId::Guid(Guid(GUID)));
        assert_eq!(codeview.age, 0x1b);
        assert_eq!(codeview.pdb_file_name(), "ntkrnlmp.pdb");
        assert_eq!(codeview.symbol_key(), "0123456789ABCDEF0123456789ABCDEF1B");
    }

    #[test]
    fn parses_pe32_dll() {
        let image = parse(&support::pe_image(&PeSpec {
            pe32_plus: false,
            dll: true,
            pdb: Some((GUID, 1, "plain.pdb")),
        }))
        .unwrap();

        assert_eq!(image.architecture(), "x86");
        assert_eq!(image.kind(), "DLL");
        assert_eq!(image.image_base, 0x40_0000);
        assert_eq!(image.codeview.unwrap().pdb_file_name(), "plain.pdb");
    }

    #[test]
    fn image_without_debug_directory_has_no_codeview() {
        let image = parse(&support::pe_image(&PeSpec::default())).unwrap();
        assert_eq!(image.codeview, None);
    }

    #[test]
    fn resolves_codeview_through_rva_when_file_pointer_is_missing() {
        let mut bytes = support::pe_image(&PeSpec {
            pdb: Some((GUID, 1, "a.pdb")),
            ..PeSpec::default()
        });
        // Zero PointerToRawData of the only debug entry.
        let entry = support::DEBUG_DIRECTORY_OFFSET;
        bytes[entry + 24..entry + 28].fill(0);
        assert!(parse(&bytes).unwrap().codeview.is_some());
    }

    #[test]
    fn parses_nb10_records() {
        let mut record = b"NB10".to_vec();
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&0x3b7d_8410u32.to_le_bytes());
        record.extend_from_slice(&2u32.to_le_bytes());
        record.extend_from_slice(b"c:\\old\\thing.pdb\0");

        let codeview = CodeView::parse(&record).unwrap();
        assert_eq!(codeview.id, PdbId::Timestamp(0x3b7d_8410));
        assert_eq!(codeview.symbol_key(), "3B7D84102");
        assert_eq!(codeview.pdb_file_name(), "thing.pdb");
    }

    #[test]
    fn rejects_codeview_without_a_file_name() {
        for path in ["", "C:\\dir\\", ".."] {
            let mut record = b"RSDS".to_vec();
            record.extend_from_slice(&GUID);
            record.extend_from_slice(&1u32.to_le_bytes());
            record.extend_from_slice(path.as_bytes());
            record.push(0);
            assert_eq!(CodeView::parse(&record), None, "{path:?}");
        }
    }

    #[test]
    fn rejects_non_pe_input() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"MZ"), None);
        assert_eq!(parse(&[0x7f, b'E', b'L', b'F'].repeat(64)), None);

        // A DOS executable whose e_lfanew points past the end of the file.
        let mut dos = vec![0u8; 0x80];
        dos[..2].copy_from_slice(b"MZ");
        dos[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert_eq!(parse(&dos), None);
    }

    #[test]
    fn truncated_images_never_panic() {
        let bytes = support::pe_image(&PeSpec {
            pdb: Some((GUID, 1, "a.pdb")),
            ..PeSpec::default()
        });
        for len in 0..bytes.len() {
            let _ = parse(&bytes[..len]);
        }
    }

    #[test]
    fn reads_headers_beyond_the_cached_prefix() {
        let small = support::pe_image(&PeSpec {
            pdb: Some((GUID, 1, "far.pdb")),
            ..PeSpec::default()
        });
        // Push everything after the DOS header out past HEAD_LEN.
        let shift = 2 * HEAD_LEN;
        let mut bytes = small[..DOS_HEADER_LEN].to_vec();
        bytes.resize(DOS_HEADER_LEN + shift, 0);
        bytes.extend_from_slice(&small[DOS_HEADER_LEN..]);
        let nt = u32_at(&small, 0x3c).unwrap() + shift as u32;
        bytes[0x3c..0x40].copy_from_slice(&nt.to_le_bytes());

        let image = parse(&bytes).unwrap();
        assert_eq!(image.architecture(), "x64");
        // The debug data's file pointer was not relocated, so only the headers are expected.
        assert_eq!(image.entry_point, 0x1234);
    }
}

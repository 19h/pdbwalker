<h1 align="center">pdbwalker</h1>

<h5 align="center">Advanced PE binary scanner with PDB debug symbol detection and download capabilities</h5>

<div align="center">
  <a href="https://crates.io/crates/pdbwalker">
    crates.io
  </a>
  —
  <a href="https://github.com/19h/pdbwalker">
    Github
  </a>
</div>

<br />

`pdbwalker` is a command-line utility that recursively scans directories for Windows PE executables (`.exe` and `.dll` files) and provides detailed information about their debug symbols (PDB files). It parses PE debug directories to extract CodeView information (GUID, age, and PDB filename), checks for local PDB files, and optionally queries Microsoft's public symbol server to determine if symbols can be downloaded.

## Features

### Core Capabilities
*   **🎨 Colorful, Structured Output:** Beautiful CLI interface with color-coded status indicators and organized information display
*   **📊 Detailed Binary Information:** Displays architecture, file size, timestamps, subsystem, entry points, and more
*   **🔍 Dual PDB Detection:** Checks for both local PDB files and remote availability on Microsoft's symbol server
*   **📦 Download & Copy:** Copy binaries and their PDB files to an output directory, or download missing PDBs from remote servers
*   **🎯 Smart Filtering:** Filter results by local-only or remote-only availability
*   **📄 Multiple Output Formats:** Human-readable colorful output, JSON for scripting, and manifest generation
*   **⚡ Efficient Scanning:** Fast directory traversal with configurable depth and symlink following
*   **🔧 PE Format Support:** Handles both 32-bit and 64-bit PE files

## Installation

```shell
cargo install pdbwalker
```

Or build from source:

```shell
git clone https://github.com/19h/pdbwalker
cd pdbwalker
cargo build --release
```

## Usage

### Basic Usage

```shell
# Scan a directory (shows all PE files with PDB info)
pdbwalker C:\Windows\System32

# Verbose output with detailed PE information
pdbwalker -v C:\Windows\System32

# Check remote PDB availability (requires network)
pdbwalker --check-remote C:\Windows\System32

# Filter to show only files with local PDBs
pdbwalker --local-only C:\MyProject\bin\Release

# Filter to show only files with remote PDB info
pdbwalker --remote-only C:\Windows\System32
```

### Advanced Usage

```shell
# Download remote PDBs to output directory
pdbwalker --check-remote --download-remote -o ./symbols C:\Windows\System32

# Copy binaries AND download their PDBs
pdbwalker --check-remote --copy-binaries --download-remote -o ./analysis C:\Program Files\MyApp

# JSON output for scripting
pdbwalker --json C:\Windows\System32 > results.json

# Limit recursion depth
pdbwalker --max-depth 2 C:\Windows

# Follow symbolic links
pdbwalker --follow-symlinks C:\MyLinkedDirs
```

## Example Output

### Standard Output

```
PDB Walker - PE Binary Scanner
==============================
Scanning directory: C:\Windows\System32

Found 3 PE binarie(s)

● Binary #1 (DLL)
   Path: C:\Windows\System32\kernel32.dll
   Size: 1.05 MB
   Architecture: x64
   Modified: 2024-03-15 14:32:10 UTC

   Local PDB: ✓ Found
      Path: C:\Windows\System32\kernel32.pdb

   Remote PDB: ? Not checked

● Binary #2 (DLL)
   Path: C:\Windows\System32\ntdll.dll
   Size: 2.10 MB
   Architecture: x64
   Modified: 2024-03-15 14:32:10 UTC

   Local PDB: ✗ Not found

   Remote PDB: ✓ Available
      File: ntdll.pdb
      GUID: {1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D}
      Age: 1
      Signature: 1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D1
      URL: https://msdl.microsoft.com/download/symbols/ntdll.pdb/...

────────────────────────────────────────────────────────────
Summary

   Total binaries: 3
   With local PDB: 1
   With PDB info: 2
   Remote available: 1
```

### Verbose Mode

Add `-v` or `--verbose` to see additional PE details:
- Image base address
- Entry point address
- PE subsystem type
- Build timestamp
- Complete PDB URLs

### JSON Output

```shell
pdbwalker --json C:\Windows\System32
```

```json
{
  "file_path": "C:\\Windows\\System32\\kernel32.dll",
  "file_size": 1048576,
  "file_modified": "2024-03-15T14:32:10Z",
  "architecture": "x64",
  "image_base": "0x180000000",
  "entry_point": "0x1000",
  "timestamp": "2024-03-15T14:30:00Z",
  "subsystem": "Windows GUI",
  "is_dll": true,
  "local_pdb": {
    "available": true,
    "path": "C:\\Windows\\System32\\kernel32.pdb"
  },
  "remote_pdb": {
    "has_info": true,
    "available": true,
    "info": {
      "file_name": "kernel32.pdb",
      "guid": "{1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D}",
      "age": 1,
      "signature": "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D1",
      "url": "https://msdl.microsoft.com/download/symbols/kernel32.pdb/..."
    }
  }
}
```

## Command-Line Options

```
PE binary scanner with PDB symbol file detection and download capabilities

Usage: pdbwalker [OPTIONS] <DIRECTORY>

Arguments:
  <DIRECTORY>  Directory to scan for PE binaries

Options:
  -v, --verbose          Show detailed information about each binary
      --local-only       Only show binaries with local PDB files
      --remote-only      Only show binaries with remote PDB files available
      --check-remote     Check if remote PDB files exist (requires network requests)
  -o, --output <DIR>     Copy binaries and PDB files to output directory
      --copy-binaries    Copy binaries in addition to PDB files (requires --output)
      --download-remote  Download remote PDB files (requires --output)
  -f, --force            Overwrite existing files in output directory
      --json             Output results as JSON
      --max-depth <N>    Maximum recursion depth (default: unlimited)
      --follow-symlinks  Follow symbolic links
  -h, --help             Print help
  -V, --version          Print version
```

## Use Cases

### Reverse Engineering
```shell
# Find which system DLLs have public symbols
pdbwalker --check-remote --remote-only C:\Windows\System32 > available_symbols.txt

# Download all available symbols for analysis
pdbwalker --check-remote --download-remote -o ./symbols C:\Windows\System32
```

### Debugging Third-Party Software
```shell
# Check if debugging symbols are available for an application
pdbwalker --check-remote "C:\Program Files\SomeApp"

# Download symbols for offline debugging
pdbwalker --check-remote --download-remote -o ./app_symbols "C:\Program Files\SomeApp"
```

### Security Research
```shell
# Identify which drivers have symbols (useful for kernel debugging)
pdbwalker --check-remote --remote-only C:\Windows\System32\drivers

# Create a local symbol cache with binaries
pdbwalker --check-remote --copy-binaries --download-remote -o ./research C:\Windows\System32
```

### Build Verification
```shell
# Verify that your build output has matching PDB files
pdbwalker --local-only C:\MyProject\bin\Release

# Verbose check of all PE details
pdbwalker -v --local-only C:\MyProject\bin\Release
```

### Malware Analysis
```shell
# Copy suspicious binaries and try to download their symbols
pdbwalker --check-remote --copy-binaries --download-remote -o ./malware_analysis C:\Suspicious\Path

# Export all binary information as JSON for further analysis
pdbwalker --check-remote --json C:\Suspicious\Path > malware_info.json
```

## Technical Background

### Windows Program Database (PDB) Files

PDB files contain debug information for Windows executables, including:
*   Symbol names (functions, variables)
*   Type information
*   Source file line mappings
*   Call stack unwinding data

These files are essential for debugging, profiling, and reverse engineering Windows applications.

### PE Debug Directory Structure

Windows PE files contain an optional Debug Directory that stores debug information. The most common format is **CodeView**, specifically the `RSDS` signature format introduced with Visual Studio .NET.

**CodeView RSDS Structure:**
```
+0x00: "RSDS" signature (4 bytes)
+0x04: GUID (16 bytes) - unique identifier for the PDB
+0x14: Age (4 bytes) - incremental counter for PDB updates
+0x18: PDB path (null-terminated UTF-8 string)
```

### Microsoft Symbol Server Protocol

Microsoft hosts public symbols for Windows system files at `https://msdl.microsoft.com/download/symbols`.

**URL Format:**
```
https://msdl.microsoft.com/download/symbols/<filename>/<GUID><Age>/<filename>
```

**Example:**
```
https://msdl.microsoft.com/download/symbols/ntdll.pdb/1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D1/ntdll.pdb
```

Where:
*   `<filename>` is the PDB filename extracted from the PE debug directory
*   `<GUID>` is the 32-character hex GUID (no hyphens) with the age appended as lowercase hex
*   The GUID is formatted as: `{Data1:08X}{Data2:04X}{Data3:04X}{Data4[0..8]:02X}`

### Detection Logic

**Local PDB Check:**
1. For each `.exe` or `.dll`, check if a `.pdb` with the same base name exists in the same directory
2. Report as "✓ Found" if present

**Remote PDB Check:**
1. Parse the PE file to locate the Debug Directory (IMAGE_DIRECTORY_ENTRY_DEBUG)
2. Iterate through debug directory entries to find `IMAGE_DEBUG_TYPE_CODEVIEW`
3. Extract the CodeView record if it has an `RSDS` signature
4. Parse the GUID (16 bytes), age (4 bytes), and PDB filename
5. Construct the symbol server URL using the format above
6. If `--check-remote` is specified, send an HTTP HEAD request to verify the file exists (status 200 OK)
7. Report availability status

**Download Logic:**
1. When `--output` and `--download-remote` are specified, download PDB files that aren't available locally
2. Optionally copy binaries with `--copy-binaries`
3. Create a `manifest.json` file documenting all copied/downloaded files

## Performance

`pdbwalker` is optimized for speed:
*   Uses `walkdir` for efficient recursive directory traversal
*   HTTP HEAD requests (not GET) minimize network transfer during checks
*   Skips remote checks unless explicitly requested
*   Parses PE files in-memory without external tools
*   Downloads only when requested

**Typical performance:**
*   Local checks: Milliseconds per file (filesystem metadata only)
*   Remote checks: Limited by network latency (typically 50-200ms per HEAD request)
*   Downloads: Limited by network bandwidth
*   Large directories: Scans hundreds of files per second (local checks)

## Color Support

Colors are automatically enabled when outputting to a terminal. To disable colors:

```shell
NO_COLOR=1 pdbwalker C:\Windows\System32
```

Or redirect output to a file (colors are automatically disabled):

```shell
pdbwalker C:\Windows\System32 > output.txt
```

## Output Files

When using `--output` to copy/download files, the following structure is created:

```
output_directory/
├── binary1.exe
├── binary1.pdb
├── binary2.dll
├── binary2.pdb
└── manifest.json
```

The `manifest.json` contains metadata about all processed files:

```json
{
  "files": [
    {
      "binary": "C:\\Windows\\System32\\kernel32.dll",
      "binary_copied": "output_directory/kernel32.dll",
      "pdb_copied": "output_directory/kernel32.pdb",
      "pdb_downloaded": null
    }
  ],
  "count": 1
}
```

## Notes

*   Only Windows PE executables (`.exe` and `.dll`) are scanned; other file types are ignored.
*   Network requests to Microsoft's symbol server require internet connectivity. Firewalls or corporate proxies may block access.
*   The tool does not verify the integrity of local PDB files; it only checks for their existence.
*   Some files may fail to parse if they are corrupted, packed, or use non-standard PE structures.
*   Downloaded PDB files may be compressed (cabinet format). Use tools like `symchk` or `expand` to decompress if needed.

## License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

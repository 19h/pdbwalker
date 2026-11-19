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

`pdbwalker` is a command-line utility that scans directories for Windows PE binaries (`.exe`, `.dll`, `.sys`, ...) and reports on their debug symbols (PDB files). It reads the CodeView record of each binary (GUID, age and PDB file name), checks for a matching PDB next to it, can search a symbol server for the binaries whose symbols are published, and can download those PDBs right next to the binaries they belong to.

## Features

*   **Symbol server search:** `--search` lists exactly the binaries whose PDB Microsoft's public symbol server (or any compatible server) provides.
*   **In-place downloads:** `--download` saves each available PDB next to its binary, named after it: `foo.exe` -> `foo.pdb`.
*   **Verified local PDBs:** a PDB found next to a binary is opened and its GUID compared with the binary's, so a stale PDB from another build is reported instead of silently trusted.
*   **Fast:** only the PE headers and the debug directory are read, files are inspected in parallel, and symbol server requests run concurrently. Binaries that share a PDB cost a single request.
*   **Safe writes:** downloads go to a temporary file and are renamed into place once complete and confirmed to be a PDB. Existing files are never overwritten without `--force`.
*   **Scriptable:** JSON Lines output, a manifest for collected files, meaningful exit codes.
*   **PE32 and PE32+**, any architecture; classic (MSF) and portable PDBs.

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

```shell
# List PE files and what is known about their symbols locally
pdbwalker C:\Windows\System32

# Search the symbol server: list only binaries whose PDB is available there
pdbwalker --search C:\Windows\System32

# ...and download each of those PDBs next to its binary (ntdll.dll -> ntdll.pdb)
pdbwalker --search --download C:\Windows\System32

# Fetch the PDB for a single file
pdbwalker --download foo.exe

# Show every binary, with a note on whether the server has its PDB
pdbwalker --check-remote "C:\Program Files\SomeApp"

# Detailed PE and CodeView information
pdbwalker -v C:\MyProject\bin\Release

# Only binaries that already have a PDB next to them
pdbwalker --local-only C:\MyProject\bin\Release
```

Several paths can be given, and a path may be a single file. Directories are scanned for the extensions listed under `--ext`; use `--all-files` to probe every file for a PE header instead.

### Collecting files in one directory

```shell
# Gather PDBs (local ones are copied, missing ones downloaded) in ./symbols
pdbwalker --download-remote -o ./symbols C:\Windows\System32

# The same, together with the binaries
pdbwalker --copy-binaries --download-remote -o ./analysis "C:\Program Files\MyApp"
```

PDBs downloaded into an output directory keep the name their binary refers to (for example `ntkrnlmp.pdb` for `ntoskrnl.exe`). A PDB next to a binary is copied unless it is known to come from a different build. A `manifest.json` records what was copied or downloaded:

```json
{
  "files": [
    {
      "binary": "C:\\Windows\\System32\\kernel32.dll",
      "binary_copied": "analysis\\kernel32.dll",
      "pdb_copied": null,
      "pdb_downloaded": "analysis\\kernel32.pdb"
    }
  ],
  "count": 1
}
```

## Example Output

```
$ pdbwalker --search --download ./bin
● ./bin/msvcp110.dll  x64   DLL  downloaded msvcp110.pdb (707.00 KB)
● ./bin/msvcr110.dll  x64   DLL  downloaded msvcr110.pdb (747.00 KB)

────────────────────────────────────────────────────────────
Summary

   PE binaries:      2 (of 6 scanned)
   With PDB info:    2
   With local PDB:   2
   On symbol server: 2
   PDBs downloaded:  2
```

Each line starts with a status marker: green when the binary has a PDB next to it, bright yellow when the server has one, yellow when the binary references a PDB whose availability is unknown, and a hollow circle when it carries no debug information.

With `-v` every binary gets a block instead of a line:

```
● ./bin/msvcp110.dll (DLL)
   Size:          630.50 KB
   Architecture:  x64
   Modified:      2026-11-19 02:30:43 UTC
   Image base:    0x180000000
   Entry point:   0x4B93C
   Subsystem:     Windows GUI
   Timestamp:     2012-07-26 19:52:59 UTC
   Debug info:    msvcp110.amd64.pdb
   GUID:          {DBE4BA10-CFCA-424D-AFE4-901CEE1AE0A5}
   Age:           1
   Signature:     DBE4BA10CFCA424DAFE4901CEE1AE0A51
   URL:           https://msdl.microsoft.com/download/symbols/msvcp110.amd64.pdb/DBE4BA10CFCA424DAFE4901CEE1AE0A51/msvcp110.amd64.pdb
   Local PDB:     ./bin/msvcp110.pdb (matches)
   Symbol server: available
```

### JSON Output

`--json` prints one object per binary, one per line (shown here pretty-printed):

```json
{
  "file_path": "./bin/msvcr110.dll",
  "file_size": 813056,
  "file_modified": "2026-11-19T02:30:43+00:00",
  "architecture": "x64",
  "image_base": "0x180000000",
  "entry_point": "0x230FC",
  "timestamp": "2012-07-26T19:52:55+00:00",
  "subsystem": "Windows GUI",
  "is_dll": true,
  "local_pdb": {
    "available": true,
    "path": "./bin/msvcr110.pdb",
    "matches": true
  },
  "remote_pdb": {
    "has_info": true,
    "available": true,
    "info": {
      "file_name": "msvcr110.amd64.pdb",
      "guid": "{D44838F1-45BC-4995-A4EF-8CD875379C72}",
      "age": 1,
      "signature": "D44838F145BC4995A4EF8CD875379C721",
      "url": "https://msdl.microsoft.com/download/symbols/msvcr110.amd64.pdb/D44838F145BC4995A4EF8CD875379C721/msvcr110.amd64.pdb"
    }
  },
  "download": {
    "status": "downloaded",
    "path": "./bin/msvcr110.pdb",
    "bytes": 764928
  }
}
```

*   `local_pdb.matches` is `true` or `false` when the PDB's identity could be compared with the binary's, `null` otherwise.
*   `remote_pdb.available` is `null` when the server was not asked; `remote_pdb.error` appears when asking failed.
*   `download` is present with `--download`. Its `status` is one of `downloaded`, `exists`, `not_found`, `no_debug_info`, `name_conflict` or `failed` (with an `error`).
*   `output` is present with `--output` and lists `binary_copied`, `pdb_copied` and `pdb_downloaded`.

## Command-Line Options

```
Usage: pdbwalker [OPTIONS] <PATH>...

Arguments:
  <PATH>...  Directories or PE files to scan

Options:
  -v, --verbose  Show detailed information about each binary
      --json     Print one JSON object per binary (JSON Lines) instead of text
  -f, --force    Overwrite existing files, including local PDBs that do not match their binary
  -h, --help     Print help
  -V, --version  Print version

Scanning:
      --max-depth <N>    Maximum recursion depth (default: unlimited)
      --follow-symlinks  Follow symbolic links
  -e, --ext <EXT>        File extensions to treat as PE binaries
                         [default: exe,dll,sys,drv,ocx,cpl,scr,efi,ax,acm,pyd,node]
  -a, --all-files        Probe every file for a PE header, whatever its extension

Filters:
      --local-only   Only show binaries that have a PDB next to them
      --remote-only  Only show binaries that reference a PDB (with --check-remote: one the
                     server has)

Symbol server:
  -s, --search               Search the symbol server: only show binaries whose PDB it provides
  -d, --download             Download PDBs next to their binaries (foo.exe -> foo.pdb) when the
                             server has them
      --check-remote         Ask the symbol server whether each PDB exists
      --symbol-server <URL>  Symbol server to query
                             [default: https://msdl.microsoft.com/download/symbols]
  -j, --jobs <N>             Number of parallel symbol server requests [default: 16]

Output directory:
  -o, --output <DIR>     Collect PDB files into this directory and write a manifest.json
      --copy-binaries    Also copy the binaries into the output directory
      --download-remote  Download PDBs that are not available locally into the output directory
```

Filters select the binaries that are shown and acted upon: `--search --download` downloads exactly what it lists.

### Exit status

| Code | Meaning |
|------|---------|
| 0 | The scan completed. A PDB that the server does not have is not an error. |
| 1 | A path could not be read, or a lookup, download or copy failed. |
| 2 | Invalid command line. |

## How downloads behave

*   **Naming.** `--download` names the PDB after the binary: `foo.exe` -> `foo.pdb`, in the same directory, whatever name the binary's debug record uses.
*   **Existing PDBs are kept.** If `foo.pdb` already exists it is left alone, and reported as matching, from a different build, or not verifiable. `--force` replaces PDBs that do not verifiably match; a matching PDB is never downloaded again.
*   **Name clashes.** `foo.exe` and `foo.dll` in one directory both map to `foo.pdb`. The name goes to the binary that an existing `foo.pdb` matches, otherwise to the one whose debug record actually names `foo.pdb`, otherwise to the first one. The other binary is reported with `name_conflict`; `--output` with `--download-remote` fetches its PDB under its own name.
*   **Atomic.** Data is written to `.foo.pdb.<pid>.part` and renamed to `foo.pdb` only when the transfer is complete and the content is a PDB. An interrupted run can leave `.part` files behind, never a truncated `foo.pdb`.
*   **Retries.** Connection failures, timeouts and temporary server errors (408, 429, 500, 502, 503, 504) are retried twice before the binary is reported as failed.

## Technical Background

### PE Debug Directory

A PE image can carry a debug directory. Its CodeView entry links the image to the PDB produced by the same build:

```
+0x00: "RSDS" signature (4 bytes)
+0x04: GUID (16 bytes) - identifies the build
+0x14: Age (4 bytes)   - incremented each time the PDB is rewritten
+0x18: PDB path (null-terminated string)
```

pdbwalker also understands the older `NB10` record (PDB 2.0), which carries a timestamp instead of a GUID.

### Symbol Server Protocol

Symbol servers publish PDBs under a path derived from that record:

```
<server>/<pdb name>/<GUID><age>/<pdb name>
```

For example:

```
https://msdl.microsoft.com/download/symbols/ntdll.pdb/1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D1/ntdll.pdb
```

The GUID is written as 32 hexadecimal digits without punctuation, followed by the age in hexadecimal. Microsoft's server answers with a redirect to the file when it has it and with `404` when it does not. `--search` and `--check-remote` send `HEAD` requests; `--download` sends a single `GET` per PDB, which doubles as the availability check.

### Matching local PDBs

A PDB next to a binary is only as good as its GUID. pdbwalker reads the GUID from the PDB info stream of MSF 7.00 files and from the `#Pdb` stream of portable PDBs and compares it with the binary's CodeView record. PDB 2.0 files and binaries without a CodeView record cannot be compared and are reported as "not verified".

## Notes

*   Files that are not valid PE images are skipped silently, whatever their extension.
*   Colours are used when writing to a terminal and disabled when output is redirected or `NO_COLOR` is set. A progress line is shown on stderr while it is a terminal.
*   Requests go through the system proxy configuration and the usual `HTTPS_PROXY` / `NO_PROXY` environment variables.
*   Compressed symbol files (`.pd_`, served by some private symbol servers) are not supported; such responses are rejected rather than saved under a `.pdb` name.

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

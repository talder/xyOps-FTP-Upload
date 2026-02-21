<p align="center"><img src="https://raw.githubusercontent.com/xyOps-tools/xyOps-FTP-Upload/refs/heads/main/logo.svg" height="108" alt="xyOps FTP Upload Logo"/></p>
<h1 align="center">xyOps FTP Upload</h1>

# xyOps FTP Upload Event Plugin

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/xyOps-tools/xyOps-FTP-Upload/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

Upload files to remote servers via **FTP**, **FTPS** (Explicit & Implicit TLS), or **SFTP** (SSH). This is an **event plugin** — use it as a step in an xyOps workflow to upload generated reports, exports, backups, or any file to a remote server. As an event plugin, it receives files and data from the previous workflow step automatically.

**Key Features:**
- 3 protocols: FTP, FTPS (Explicit/Implicit), SFTP
- 4 file sources: local files/folders, raw text content, previous job output data, previous job files
- 6 secrets in the xyOps Secret Vault (all overridable via parameters)
- Auto-install of Posh-SSH module on first SFTP use
- Recursive folder upload with automatic remote directory creation
- Configurable file-exists behaviour (overwrite, skip, error)
- Comprehensive error handling with categorised diagnostics
- Structured output data for downstream job chaining

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Secrets Configuration](#secrets-configuration)
- [Protocols](#protocols)
  - [FTP — Plain File Transfer](#ftp--plain-file-transfer)
  - [FTPS — FTP over TLS/SSL](#ftps--ftp-over-tlsssl)
  - [SFTP — SSH File Transfer](#sftp--ssh-file-transfer)
- [Parameters Reference](#parameters-reference)
- [File Sources](#file-sources)
  - [Local File or Folder](#local-file-or-folder)
  - [Raw Text Content](#raw-text-content)
  - [Previous Job Output Data](#previous-job-output-data)
  - [Previous Job Files](#previous-job-files)
- [Examples & Use Cases](#examples--use-cases)
  - [Example 1 — Upload a Single File via FTP](#example-1--upload-a-single-file-via-ftp)
  - [Example 2 — Upload a Folder via SFTP with SSH Key](#example-2--upload-a-folder-via-sftp-with-ssh-key)
  - [Example 3 — Upload Generated Report from Previous Job](#example-3--upload-generated-report-from-previous-job)
  - [Example 4 — Upload CSV Content Directly](#example-4--upload-csv-content-directly)
  - [Example 5 — FTPS Explicit with Skip-if-Exists](#example-5--ftps-explicit-with-skip-if-exists)
  - [Example 6 — FTPS Implicit (Legacy Servers)](#example-6--ftps-implicit-legacy-servers)
  - [Example 7 — Upload Multiple Files with Glob Pattern](#example-7--upload-multiple-files-with-glob-pattern)
  - [Example 8 — Chaining: NetBox Export → FTP Upload](#example-8--chaining-netbox-export--ftp-upload)
  - [Example 9 — Backup Config to SFTP with Timestamp](#example-9--backup-config-to-sftp-with-timestamp)
  - [Example 10 — Upload to Vendor SFTP with Encrypted Key](#example-10--upload-to-vendor-sftp-with-encrypted-key)
  - [Example 11 — Upload Previous Job Files (Dynamic Filenames)](#example-11--upload-previous-job-files-dynamic-filenames)
- [File Exists Behaviour](#file-exists-behaviour)
- [Remote Directory Creation](#remote-directory-creation)
- [Passive Mode](#passive-mode)
- [Error Handling](#error-handling)
- [Output Data Reference](#output-data-reference)
- [Downstream Chaining](#downstream-chaining)
- [Dependencies](#dependencies)
- [Testing Locally](#testing-locally)
- [License](#license)
- [Version History](#version-history)

---

## Quick Start

1. Install the plugin in xyOps (copy to plugins directory or install from Marketplace)
2. Configure secrets in the Secret Vault (see [Secrets Configuration](#secrets-configuration))
3. Create a workflow and add a step that produces files/data (e.g., NetBox DCIM, IPAM export)
4. Add **FTP Upload** as the next event plugin step in the workflow
5. Select protocol, set remote path, choose file source
6. Run the workflow

---

## Installation

### From xyOps Marketplace

1. Navigate to xyOps Marketplace
2. Search for "FTP Upload"
3. Click Install

### Manual Installation

```bash
cd /opt/xyops/plugins
git clone https://github.com/xyOps-tools/xyOps-FTP-Upload.git
```

---

## Secrets Configuration

Configure the following secrets in the **xyOps Secret Vault**. All secrets are optional — parameters always override secrets when provided.

| Secret Name | Description | Used By |
|-------------|-------------|---------|
| `FTP_HOST` | Server hostname or IP address | All protocols |
| `FTP_PORT` | Server port number | All protocols |
| `FTP_USERNAME` | Login username | All protocols |
| `FTP_PASSWORD` | Login password | All protocols |
| `FTP_SSH_KEY_PATH` | Path to SSH private key file | SFTP only |
| `FTP_SSH_KEY_PASSPHRASE` | Passphrase for encrypted SSH key | SFTP only |

**Priority:** Parameter value → Secret vault → Error if required

**Example:** If you set `FTP_HOST = ftp.company.com` in the vault and leave the Host parameter empty, the plugin uses `ftp.company.com`. If you then enter `ftp2.company.com` in the Host parameter, the parameter wins.

---

## Protocols

### FTP — Plain File Transfer

| Property | Value |
|----------|-------|
| Default Port | 21 |
| Encryption | None (plain text) |
| Backend | .NET `System.Net.FtpWebRequest` |
| Auth | Username + Password |

Standard FTP with no encryption. Use only on trusted networks or for non-sensitive data.

**When to use:**
- Internal transfers on isolated networks
- Legacy systems that don't support TLS
- Testing and development

### FTPS — FTP over TLS/SSL

FTPS adds TLS encryption to the FTP protocol. Two modes are available:

#### Explicit FTPS (Recommended)

| Property | Value |
|----------|-------|
| Default Port | 21 |
| Encryption | STARTTLS upgrade on port 21 |
| Backend | .NET `System.Net.FtpWebRequest` with `EnableSsl` |
| Auth | Username + Password |

The client connects on port 21 (plain text), then sends `AUTH TLS` to upgrade the connection to TLS. This is the modern, recommended approach.

**When to use:**
- Most modern FTP servers with TLS support
- Servers that support both plain FTP and FTPS on port 21
- When the server administrator has enabled STARTTLS

#### Implicit FTPS (Legacy)

| Property | Value |
|----------|-------|
| Default Port | 990 |
| Encryption | Direct TLS on connect |
| Backend | Custom `TcpClient` + `SslStream` implementation |
| Auth | Username + Password |

The client connects directly with TLS — no plain text phase. This is a legacy approach (RFC 4217 deprecated it), but some older servers require it.

**When to use:**
- Older servers that only support Implicit FTPS on port 990
- Banking/financial systems with legacy FTPS infrastructure
- When Explicit FTPS fails and the server admin confirms Implicit mode

### SFTP — SSH File Transfer

| Property | Value |
|----------|-------|
| Default Port | 22 |
| Encryption | SSH tunnel (full session encryption) |
| Backend | [Posh-SSH](https://github.com/darkoperator/Posh-SSH) module (auto-installed) |
| Auth | Password or SSH key (RSA, ED25519, ECDSA, DSA) |

SFTP runs over SSH — it is **not** related to FTP/FTPS. It provides strong encryption and is the most secure option.

**When to use:**
- Any server with SSH access (Linux/Unix servers)
- Secure file transfers to cloud infrastructure
- When SSH key authentication is required
- Vendor/partner file exchanges

**Supported key types:** RSA, ED25519, ECDSA, DSA

**Auto-install:** If the Posh-SSH module is not installed, the plugin automatically installs it on first SFTP use (`Install-Module -Name Posh-SSH -Scope CurrentUser`). No manual setup required.

---

## Parameters Reference

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| **Protocol** | Select | FTP | No | `FTP`, `FTPS`, or `SFTP` |
| **Host** | Text | — | Yes* | Server hostname or IP. Overrides `FTP_HOST` secret. |
| **Port** | Text | Auto | No | Server port. Auto-detects: 21 (FTP/FTPS Explicit), 990 (FTPS Implicit), 22 (SFTP). Overrides `FTP_PORT` secret. |
| **Username** | Text | — | Yes* | Login username. Overrides `FTP_USERNAME` secret. |
| **Password** | Text | — | Cond. | Login password. Required for FTP/FTPS and SFTP password auth. Overrides `FTP_PASSWORD` secret. |
| **FTPS Mode** | Select | Explicit | No | `Explicit` (STARTTLS, port 21) or `Implicit` (direct TLS, port 990). Only for FTPS. |
| **SSH Key Path** | Text | — | No | Path to SSH private key file. SFTP only. Overrides `FTP_SSH_KEY_PATH` secret. |
| **SSH Key Passphrase** | Text | — | No | Passphrase for encrypted SSH key. SFTP only. Overrides `FTP_SSH_KEY_PASSPHRASE` secret. |
| **Remote Path** | Text | — | Yes | Destination directory on the remote server (e.g., `/uploads/reports`). |
| **File Source** | Select | Local | No | `Local file or folder`, `Raw text content`, `Previous job output data`, or `Previous job files`. |
| **Local Path** | Text | — | Cond. | File, folder, or glob pattern to upload. Required when File Source is Local. |
| **Content** | Code | — | Cond. | Raw text content to upload. Required when File Source is Raw text content. |
| **Content File Name** | Text | upload.txt | No | Filename for raw content upload. |
| **Data Path** | Text | — | Cond. | Dot-notation path to content in previous job output. Required when File Source is Previous job output data. |
| **Data File Name** | Text | upload.txt | No | Filename for content from previous job data. |
| **Create Remote Dirs** | Checkbox | ✓ | No | Auto-create remote directories if they don't exist. |
| **If File Exists** | Select | Overwrite | No | `Overwrite`, `Skip`, or `Error`. |
| **Passive Mode** | Checkbox | ✓ | No | Use passive mode for FTP/FTPS. Recommended for firewalls/NAT. |

\* Required via parameter or secret vault.

---

## File Sources

### Local File or Folder

Upload files from the local filesystem. Supports three modes:

**Single file:**
```
/tmp/reports/quarterly-report.pdf
```

**Entire folder (recursive):**
```
/tmp/exports/
```
All files in the folder (and subfolders) are uploaded, preserving the directory structure on the remote server.

**Glob pattern (multiple files):**
```
/tmp/exports/*.csv
/var/log/app-*.log
```

### Raw Text Content

Upload text content directly as a file. Useful for:
- Uploading generated configuration files
- Uploading JSON/CSV/XML data without saving to disk first
- Uploading small text snippets

Set **Content File Name** to specify the remote filename (e.g., `config.json`, `report.csv`).

### Previous Job Output Data

Upload content from a previous job's structured output data. Use **Data Path** (dot-notation) to navigate the output structure. The data is saved as a file with the specified **Data File Name**.

| Previous Job Output | Data Path | Resolved Value |
|---------------------|-----------|----------------|
| `{ "data": { "report": "CSV content here" } }` | `data.report` | `CSV content here` |
| `{ "data": { "export": { "csv": "..." } } }` | `data.export.csv` | `...` |
| `{ "data": { "items": [...] } }` | `data.items` | JSON array (serialized) |

### Previous Job Files

Upload **actual files** generated by the previous workflow step. This is the key feature for workflows where the previous step creates files with dynamic/timestamped filenames (e.g., `netbox_tags_20260221_090501.csv`).

**How it works:**
1. The previous workflow step writes files to its working directory and declares them to xyOps via `Write-XY @{ files = $files }`
2. xyOps automatically pre-downloads those files into this plugin's working directory (CWD)
3. File metadata is passed via `input.files` in the STDIN JSON
4. This plugin reads `input.files`, finds each file in the CWD, and uploads them

**No configuration needed** — just select "Previous job files" as the File Source. No Data Path, no filename to guess. All files from the previous job are uploaded automatically.

**Example `input.files` structure (provided by xyOps):**
```json
"input": {
  "data": {},
  "files": [
    {
      "id": "fmktcdzp1skybhk9",
      "date": 1769321584,
      "filename": "netbox_tags_20260221_090501.csv",
      "size": 12450,
      "username": "admin"
    },
    {
      "id": "fmktcdzpasm25ncs",
      "date": 1769321584,
      "filename": "netbox_tags_20260221_090501.md",
      "size": 8230,
      "username": "admin"
    }
  ]
}
```

**When to use `jobfiles` vs `jobdata`:**

| Scenario | File Source | Why |
|----------|------------|-----|
| Previous job outputs a string/JSON value you want saved as a file | `jobdata` | You need to extract a data field and give it a filename |
| Previous job creates actual files (CSV, MD, PDF, etc.) with dynamic names | `jobfiles` | Files are already on disk — just upload them as-is |

---

## Examples & Use Cases

### Example 1 — Upload a Single File via FTP

Upload a backup file to an internal FTP server.

| Parameter | Value |
|-----------|-------|
| Protocol | FTP — Plain FTP |
| Host | `ftp.internal.company.com` |
| Username | `backupuser` |
| Password | `(from secret vault)` |
| Remote Path | `/backups/daily` |
| File Source | Local file or folder |
| Local Path | `/opt/backups/db-backup-2026-02-21.sql.gz` |

**Result:** Uploads `db-backup-2026-02-21.sql.gz` to `ftp.internal.company.com:/backups/daily/db-backup-2026-02-21.sql.gz`

---

### Example 2 — Upload a Folder via SFTP with SSH Key

Upload an entire export folder to a Linux server using SSH key authentication.

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `sftp.datacenter.com` |
| Port | `2222` |
| Username | `deploy` |
| SSH Key Path | `/home/xyops/.ssh/id_ed25519` |
| Remote Path | `/data/imports/2026-02` |
| File Source | Local file or folder |
| Local Path | `/tmp/exports/network-audit/` |
| Create Remote Dirs | ✓ |

**Result:** All files in `/tmp/exports/network-audit/` are uploaded recursively to `/data/imports/2026-02/` on the SFTP server, preserving subdirectory structure. Missing remote directories are created automatically.

**Folder structure preserved:**
```
Local:                                    Remote:
/tmp/exports/network-audit/               /data/imports/2026-02/
├── switches.csv           ──────────►    ├── switches.csv
├── routers.csv            ──────────►    ├── routers.csv
└── diagrams/                             └── diagrams/
    └── topology.png       ──────────►        └── topology.png
```

---

### Example 3 — Upload Generated Report from Previous Job

Chain a NetBox DCIM export job with an FTP upload. The DCIM plugin exports device data, and this action uploads the result.

**Previous job output (NetBox DCIM — List Devices):**
```json
{
  "data": {
    "tool": "listDevices",
    "count": 42,
    "csv": "Name,Role,Site,Status\nswitch-01,Access Switch,DC-East,Active\nrouter-01,Core Router,DC-West,Active\n..."
  }
}
```

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `(from FTP_HOST secret)` |
| Username | `(from FTP_USERNAME secret)` |
| Remote Path | `/reports/netbox` |
| File Source | Previous job output |
| Data Path | `data.csv` |
| Data File Name | `devices-export.csv` |

**Result:** The CSV content from the previous job is uploaded as `devices-export.csv` to `/reports/netbox/` on the SFTP server.

---

### Example 4 — Upload CSV Content Directly

Upload hand-crafted CSV data without saving to a local file first.

| Parameter | Value |
|-----------|-------|
| Protocol | FTPS — FTP over TLS/SSL |
| FTPS Mode | Explicit — STARTTLS on port 21 |
| Host | `secure-ftp.vendor.com` |
| Username | `partner_upload` |
| Password | `(from secret vault)` |
| Remote Path | `/incoming/orders` |
| File Source | Raw text content |
| Content | `OrderID,Product,Qty\n1001,Widget-A,50\n1002,Widget-B,30` |
| Content File Name | `order-batch-2026-02-21.csv` |

**Result:** Creates `order-batch-2026-02-21.csv` on the FTPS server containing the CSV data.

---

### Example 5 — FTPS Explicit with Skip-if-Exists

Upload log files but skip any that already exist on the server (idempotent).

| Parameter | Value |
|-----------|-------|
| Protocol | FTPS — FTP over TLS/SSL |
| FTPS Mode | Explicit — STARTTLS on port 21 |
| Host | `logs.company.com` |
| Username | `logshipper` |
| Password | `(from secret vault)` |
| Remote Path | `/logs/application` |
| File Source | Local file or folder |
| Local Path | `/var/log/myapp/*.log` |
| If File Exists | Skip |
| Passive Mode | ✓ |

**Result:** Uploads all `.log` files from `/var/log/myapp/`. If a file with the same name already exists on the server, it is skipped (not overwritten). Progress output shows which files were uploaded and which were skipped.

---

### Example 6 — FTPS Implicit (Legacy Servers)

Connect to a legacy banking FTPS server that only supports Implicit TLS on port 990.

| Parameter | Value |
|-----------|-------|
| Protocol | FTPS — FTP over TLS/SSL |
| FTPS Mode | Implicit — Direct TLS on port 990 |
| Host | `ftps.bank-legacy.com` |
| Port | `990` |
| Username | `transfer_agent` |
| Password | `(from secret vault)` |
| Remote Path | `/secure/uploads` |
| File Source | Local file or folder |
| Local Path | `/opt/reports/financial-statement.pdf` |
| If File Exists | Error |

**Result:** Uploads the PDF via FTPS Implicit (direct TLS handshake on port 990). If the file already exists, the job fails with a clear error message instead of silently overwriting.

---

### Example 7 — Upload Multiple Files with Glob Pattern

Upload all CSV and JSON export files from a directory.

| Parameter | Value |
|-----------|-------|
| Protocol | FTP — Plain FTP |
| Host | `ftp.warehouse.local` |
| Username | `inventory` |
| Remote Path | `/imports/daily` |
| File Source | Local file or folder |
| Local Path | `/tmp/exports/*.csv` |
| Create Remote Dirs | ✓ |
| If File Exists | Overwrite |

**Output table:**
```
┌───┬──────────────────────┬──────────────┬──────────┐
│ # │ File                 │ Size         │ Status   │
├───┼──────────────────────┼──────────────┼──────────┤
│ 1 │ switches.csv         │ 12,450 bytes │ Uploaded │
│ 2 │ routers.csv          │  8,230 bytes │ Uploaded │
│ 3 │ vlans.csv            │  3,100 bytes │ Uploaded │
│ 4 │ ip-ranges.csv        │ 15,780 bytes │ Uploaded │
└───┴──────────────────────┴──────────────┴──────────┘
4 uploaded, 0 skipped, 39,560 bytes total
```

---

### Example 8 — Chaining: NetBox Export → FTP Upload

A complete workflow: NetBox DCIM exports a device list, then the FTP Upload step sends it to a documentation server.

**Workflow Configuration:**
1. **Step 1:** xyOps NetBox DCIM → Tool: "List Devices" → Filter: Site = "DC-East"
2. **Step 2:** xyOps FTP Upload → File Source: "Previous job output"

| Parameter | Value |
|------------------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `docs.company.com` |
| Username | `automation` |
| SSH Key Path | `/opt/xyops/keys/automation_ed25519` |
| Remote Path | `/var/www/reports/network` |
| File Source | Previous job output |
| Data Path | `data.csv` |
| Data File Name | `dc-east-devices.csv` |
| Create Remote Dirs | ✓ |

**Result:** The NetBox DCIM step generates a CSV of all devices at DC-East. The FTP Upload step takes that CSV content and uploads it as `dc-east-devices.csv` to the documentation web server.

---

### Example 9 — Backup Config to SFTP with Timestamp

Upload a network device configuration backup with a timestamped filename.

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `backup.noc.com` |
| Username | `netbackup` |
| Password | `(from FTP_PASSWORD secret)` |
| Remote Path | `/backups/network/configs` |
| File Source | Local file or folder |
| Local Path | `/opt/backups/running-config.txt` |
| Create Remote Dirs | ✓ |
| If File Exists | Overwrite |

---

### Example 10 — Upload to Vendor SFTP with Encrypted Key

Upload compliance reports to a vendor's SFTP server using an encrypted ED25519 key.

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `sftp.vendor-portal.com` |
| Port | `2222` |
| Username | `company_uploads` |
| SSH Key Path | `/opt/xyops/keys/vendor_ed25519` |
| SSH Key Passphrase | `(from FTP_SSH_KEY_PASSPHRASE secret)` |
| Remote Path | `/incoming/compliance/2026` |
| File Source | Local file or folder |
| Local Path | `/opt/reports/compliance/` |
| Create Remote Dirs | ✓ |
| If File Exists | Error |

**Result:** All files in the compliance report folder are uploaded via SFTP using an encrypted ED25519 key. The passphrase is securely read from the xyOps Secret Vault. If any file already exists on the vendor server, the job fails to prevent accidental overwrites.

---

### Example 11 — Upload Previous Job Files (Dynamic Filenames)

Upload files generated by a previous event plugin. This is ideal for workflows where the event plugin creates files with timestamped or dynamic filenames that you cannot predict in advance.

**Workflow:**
1. **Step 1:** xyOps NetBox DCIM → Tool: "Export Tags" → Outputs: `netbox_tags_20260221_143022.csv`, `netbox_tags_20260221_143022.md`
2. **Step 2:** xyOps FTP Upload → File Source: "Previous job files"

The DCIM event plugin writes files to its working directory and emits them to xyOps:
```powershell
# Inside the DCIM event plugin:
$files = @("netbox_tags_20260221_143022.csv", "netbox_tags_20260221_143022.md")
Write-XY @{ files = $files }
```

xyOps pre-downloads those files into the FTP Upload plugin's CWD. The plugin reads `input.files` to discover them.

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `docs.company.com` |
| Username | `automation` |
| SSH Key Path | `/opt/xyops/keys/automation_ed25519` |
| Remote Path | `/reports/netbox/exports` |
| File Source | Previous job files |
| Create Remote Dirs | ✓ |
| If File Exists | Overwrite |

**Result:** Both `netbox_tags_20260221_143022.csv` and `netbox_tags_20260221_143022.md` are uploaded to `/reports/netbox/exports/` on the SFTP server. You don't need to know or specify the dynamic filenames — the plugin discovers them automatically from the previous job's output.

**Output table:**
```
┌───┬──────────────────────────────────────────┬──────────────┬──────────┐
│ # │ File                                     │ Size         │ Status   │
├───┼──────────────────────────────────────────┼──────────────┼──────────┤
│ 1 │ netbox_tags_20260221_143022.csv           │ 12,450 bytes │ Uploaded │
│ 2 │ netbox_tags_20260221_143022.md            │  8,230 bytes │ Uploaded │
└───┴──────────────────────────────────────────┴──────────────┴──────────┘
2 uploaded, 0 skipped, 20,680 bytes total
```

---

## File Exists Behaviour

| Option | Behaviour |
|--------|-----------|
| **Overwrite** (default) | Replace the existing remote file with the new upload |
| **Skip** | Leave the existing file untouched, continue with next file |
| **Error** | Fail the entire job immediately if any file already exists |

The **Skip** option is useful for idempotent uploads — you can safely re-run a job without overwriting previously uploaded files. The upload results table shows which files were uploaded and which were skipped.

---

## Remote Directory Creation

When **Create Remote Directories** is enabled (default), the plugin recursively creates all missing directories in the remote path before uploading files.

**Example:** Remote path `/reports/2026/Q1/network` — if `/reports` exists but `2026`, `Q1`, and `network` do not, the plugin creates them all.

This also applies to subdirectories within folder uploads. If you upload a local folder with subfolders, the remote directory structure is recreated automatically.

---

## Passive Mode

**Passive mode** (default: enabled) is recommended for most setups. In passive mode, the client initiates all connections, which works with firewalls and NAT.

| Mode | Data Connection | Firewall Friendly |
|------|----------------|-------------------|
| **Passive** (default) | Client connects to server on a dynamic port | Yes |
| **Active** | Server connects back to client on a dynamic port | No (requires open inbound ports) |

Passive mode only applies to FTP and FTPS. SFTP runs entirely over a single SSH connection and does not use passive/active modes.

---

## Error Handling

The plugin provides **comprehensive, categorised error handling**. When an error occurs, a detailed diagnostics table is displayed:

| Property | Example Value |
|----------|---------------|
| **Category** | `Connection — DNS Resolution` |
| **Phase** | `Connection` |
| **Protocol** | `SFTP` |
| **Details** | `No such host is known (sftp.example.invalid)` |
| **Suggestion** | `Verify the hostname is correct and DNS is reachable` |

### Error Categories

| Category | Phase | Common Causes |
|----------|-------|---------------|
| **Connection — DNS Resolution** | Connection | Typo in hostname, DNS server unreachable |
| **Connection — Refused** | Connection | Server not running, wrong port, firewall blocking |
| **Connection — Timeout** | Connection | Network issues, firewall dropping packets |
| **Connection — Unreachable** | Connection | No route to host, VPN not connected |
| **Authentication — Failed** | Authentication | Wrong username/password, account locked |
| **Authentication — SSH Key Error** | Authentication | Key file not found, wrong format, permissions |
| **Authentication — Key Passphrase** | Authentication | Wrong passphrase for encrypted key |
| **Permission — Access Denied** | Permission | No write permission on remote directory |
| **Permission — Path Not Found** | Permission | Remote directory doesn't exist (enable Create Remote Dirs) |
| **Transfer — Disk Full** | Transfer | Remote server out of disk space, quota exceeded |
| **Transfer — Failed** | Transfer | Connection dropped during upload, server error |
| **Protocol — TLS/SSL Error** | Protocol | Certificate issues, TLS version mismatch |
| **Protocol — STARTTLS Failed** | Protocol | Server doesn't support Explicit FTPS |

---

## Output Data Reference

All uploads produce structured output data accessible to downstream jobs via `data.*` paths.

**Output structure:**
```json
{
  "tool": "ftpUpload",
  "success": true,
  "protocol": "sftp",
  "host": "sftp.example.com",
  "port": 22,
  "remotePath": "/uploads/reports",
  "files": [
    {
      "name": "report.csv",
      "remotePath": "/uploads/reports/report.csv",
      "size": 12450,
      "status": "uploaded"
    },
    {
      "name": "summary.txt",
      "remotePath": "/uploads/reports/summary.txt",
      "size": 1024,
      "status": "skipped"
    }
  ],
  "totalFiles": 1,
  "totalSize": 12450,
  "skippedFiles": 1,
  "timestamp": "2026-02-21T14:30:00.0000000Z"
}
```

**Key output fields:**

| Data Path | Type | Description |
|-----------|------|-------------|
| `data.tool` | String | Always `ftpUpload` |
| `data.success` | Boolean | `true` if upload completed |
| `data.protocol` | String | Protocol used (`ftp`, `ftps`, `sftp`) |
| `data.host` | String | Server hostname |
| `data.port` | Number | Server port |
| `data.remotePath` | String | Remote directory path |
| `data.files` | Array | Details of each file processed |
| `data.files[].name` | String | Filename |
| `data.files[].remotePath` | String | Full remote path of the file |
| `data.files[].size` | Number | File size in bytes |
| `data.files[].status` | String | `uploaded` or `skipped` |
| `data.totalFiles` | Number | Count of successfully uploaded files |
| `data.totalSize` | Number | Total bytes uploaded |
| `data.skippedFiles` | Number | Count of skipped files |
| `data.timestamp` | String | ISO 8601 UTC timestamp |

---

## Downstream Chaining

The output data can be consumed by a subsequent step in a workflow. For example, you could chain:

1. **Step 1:** NetBox DCIM → Export devices as CSV
2. **Step 2:** FTP Upload → Upload CSV to documentation server
3. **Next job** could read `data.files[0].remotePath` to confirm the upload location

Or use the output to trigger notifications:
- `data.totalFiles` — number of files uploaded
- `data.skippedFiles` — number of files skipped
- `data.success` — overall success/failure

---

## Dependencies

| Dependency | Required For | Installation |
|------------|-------------|-------------|
| [PowerShell 7.0+](https://github.com/PowerShell/PowerShell) | All protocols | Manual (pre-requisite) |
| [Posh-SSH](https://github.com/darkoperator/Posh-SSH) (v3.2.7+) | SFTP only | **Auto-installed** on first SFTP use |
| .NET `System.Net.FtpWebRequest` | FTP / FTPS Explicit | Built-in (part of .NET runtime) |
| .NET `System.Net.Sockets.TcpClient` | FTPS Implicit | Built-in (part of .NET runtime) |

**Posh-SSH auto-installation:** When you first run an SFTP upload, the plugin checks if `Posh-SSH` is installed. If not, it automatically runs `Install-Module -Name Posh-SSH -Scope CurrentUser -Force`. This is a one-time operation. Subsequent runs skip the installation check.

**Posh-SSH features used:**
- `New-SFTPSession` — establish SSH connection (password or key auth)
- `Set-SFTPItem` — upload files
- `Test-SFTPPath` — check if remote path exists
- `New-SFTPItem` — create remote directories
- `Get-SFTPItem` — check file existence and size
- `Remove-SFTPSession` — clean up connections

---

## Testing Locally

You can test the plugin locally by piping a JSON job object to the script:

```bash
pwsh -NoProfile -ExecutionPolicy Bypass -File ./ftp.ps1 < job.json
```

**Example `job.json` for FTP upload:**
```json
{
  "params": {
    "protocol": "ftp",
    "host": "localhost",
    "port": "21",
    "username": "testuser",
    "password": "testpass",
    "remotePath": "/uploads",
    "fileSource": "content",
    "content": "Hello, World!",
    "contentFileName": "test.txt",
    "createRemoteDirs": true,
    "ifFileExists": "overwrite",
    "passiveMode": true
  }
}
```

**Example `job.json` for SFTP upload with SSH key:**
```json
{
  "params": {
    "protocol": "sftp",
    "host": "192.168.1.100",
    "port": "22",
    "username": "deploy",
    "sshKeyPath": "/home/user/.ssh/id_ed25519",
    "remotePath": "/data/uploads",
    "fileSource": "local",
    "localPath": "/tmp/exports/report.csv",
    "createRemoteDirs": true,
    "ifFileExists": "overwrite"
  }
}
```

**Example `job.json` for previous job data:**
```json
{
  "params": {
    "protocol": "sftp",
    "host": "sftp.example.com",
    "username": "automation",
    "password": "secret",
    "remotePath": "/reports",
    "fileSource": "jobdata",
    "dataPath": "data.csv",
    "dataFileName": "export.csv"
  },
  "input": {
    "data": {
      "csv": "Name,Status\nDevice-1,Active\nDevice-2,Offline"
    }
  }
}
```

**Example `job.json` for previous job files (dynamic filenames):**
```json
{
  "params": {
    "protocol": "sftp",
    "host": "sftp.example.com",
    "username": "automation",
    "password": "secret",
    "remotePath": "/reports/exports",
    "fileSource": "jobfiles",
    "createRemoteDirs": true,
    "ifFileExists": "overwrite"
  },
  "cwd": "/opt/xyops/satellite/temp/jobs/jmi11fqevei",
  "input": {
    "data": {},
    "files": [
      {
        "id": "fmktcdzp1skybhk9",
        "date": 1769321584,
        "filename": "netbox_tags_20260221_143022.csv",
        "size": 12450,
        "username": "admin"
      },
      {
        "id": "fmktcdzpasm25ncs",
        "date": 1769321584,
        "filename": "netbox_tags_20260221_143022.md",
        "size": 8230,
        "username": "admin"
      }
    ]
  }
}
```

---

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.

---

## Author

**Tim Alderweireldt**
- Plugin: xyOps FTP Upload
- Year: 2026

---

## Version History

### v1.2.0 (2026-02-21)
- **Changed plugin type** from `action` to `event` — now runs as a workflow step with full access to files from previous steps
- Simplified STDIN handling for event plugin wire protocol (`cwd` and `input` at top level)
- Removed action-plugin workarounds for inaccessible temp directories

### v1.1.0 (2026-02-21)
- **New file source:** `Previous job files` — upload actual files generated by the previous event plugin
- Supports dynamic/timestamped filenames from upstream jobs (e.g., `netbox_tags_20260221_143022.csv`)
- Files are discovered automatically from `input.files` metadata
- Now **4 file sources** total

### v1.0.0 (2026-02-21)
- Initial release
- **3 protocols:** FTP (plain), FTPS (Explicit + Implicit TLS), SFTP (SSH)
- **3 file sources:** local file/folder, raw text content, previous job output
- **6 secrets** in xyOps Secret Vault with parameter override
- Posh-SSH auto-installation for SFTP
- Recursive folder upload with directory structure preservation
- Remote directory auto-creation
- Configurable file-exists behaviour (overwrite / skip / error)
- Passive mode support for FTP/FTPS
- Comprehensive error handling with 13 error categories
- Structured output data for downstream job chaining
- 18 configurable parameters
- Cross-platform: Linux, Windows, macOS

---

**Need help?** Open an issue on GitHub or contact the author.

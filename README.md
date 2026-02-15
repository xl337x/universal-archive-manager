# Universal Archive Manager (UAM)

Universal Archive Manager (UAM) is a Bash-based command-line tool for extracting, creating, analyzing, testing, repairing, and managing a wide range of archive formats through a single unified interface. It automatically detects file types using both extensions and magic bytes, even if files are renamed.

---

## Installation

```bash
chmod +x universal-archive-manager.sh
sudo cp universal-archive-manager.sh /usr/local/bin/uam
```

Verify:

```bash
uam -v
```

---

## Usage

```bash
uam [OPTIONS] [ARGUMENTS]
```

UAM performs one operation at a time using flags described below.

---

## Operations

### Extract (`-x, --extract`)

Extracts an archive to the current directory or a specified output directory.

```bash
uam -x archive.zip
uam -x archive.tar.gz /tmp/output
```

Encrypted archives are detected automatically. You can supply the password interactively or using:

```bash
UAM_PASSWORD=secret uam -x enc.zip /out
```

---

### Create (`-c, --create`)

Creates a new archive in the specified format.

```bash
uam -c tar.gz backup.tar.gz ./data
uam -c zip archive.zip file1 dir1/
uam -c 7z archive.7z file1 file2
```

Behavior can be customized using environment variables (compression level, threads, exclusions, encryption, splitting, checksum generation).

---

### List (`-l, --list`)

Displays archive contents without extracting.

```bash
uam -l archive.zip
```

---

### Test (`-t, --test`)

Checks archive integrity without extracting files.

```bash
uam -t suspicious.rar
```

---

### Repair (`-r, --repair`)

Attempts to repair corrupted archives and recover accessible data.

```bash
uam -r corrupted.zip /tmp/repaired
```

---

### Batch Extract (`-b, --batch`)

Extracts multiple archives into a single directory.

```bash
uam -b /tmp/output *.zip *.tar.gz *.7z
```

---

### Forensic Info (`-i, --info`)

Performs structural and metadata analysis on an archive. Useful for investigation or validation.

```bash
uam -i suspicious_archive.zip
```

---

### Password Crack Guide (`-p, --password-crack`)

Generates a structured guide for attempting password recovery using external tools. It does not perform cracking itself.

```bash
uam -p encrypted.zip > crack_plan.txt
```

---

### Dependencies (`--deps`)

Shows or installs required backend tools used for handling various formats.

---

## Supported Formats

### Extraction

Supports most common compressed files, tar variants, standard archives (zip, 7z, rar), Linux packages (rpm, deb), application bundles (apk, ipa, jar), disk images (iso, dmg, vhd), and special formats such as cpio, squashfs, zpaq, and self-extracting executables.

### Creation

Supports creating tar (and compressed tar), zip, 7z, gz, cpio, and ar archives.

---

## Environment Variables

| Variable                | Purpose                                    |
| ----------------------- | ------------------------------------------ |
| `UAM_PASSWORD`          | Password for extracting encrypted archives |
| `UAM_CREATE_PASSWORD`   | Password for creating encrypted archives   |
| `UAM_COMPRESSION_LEVEL` | Compression level (1–9, format dependent)  |
| `UAM_THREADS`           | Number of threads for compression          |
| `UAM_EXCLUDE`           | Comma-separated exclusion patterns         |
| `UAM_SPLIT_SIZE`        | Split archive into parts (e.g., 100m, 1g)  |
| `UAM_CHECKSUM`          | Set to 1 to generate checksum              |
| `UAM_LOG_FILE`          | Log file path                              |
| `UAM_DEBUG`             | Enable debug output                        |
| `UAM_FORCE_UNSAFE`      | Disable path traversal protection          |

---

## Security and Behavior

* Format auto-detection using extension and magic bytes
* Automatic detection of encrypted archives
* Path traversal protection enabled by default
* Clean interruption handling (Ctrl+C)
* Partial recovery support for damaged archives

---

## Version

Universal Archive Manager (UAM) v2.0.0

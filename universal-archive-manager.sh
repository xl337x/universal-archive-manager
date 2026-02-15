#!/usr/bin/env bash
# ==============================================================================
# Universal Archive Manager (UAM)
# Version: 2.0.0
# A comprehensive archive management tool for penetration testers and sysadmins.
# Supports extraction, creation, integrity testing, listing, forensic analysis,
# corruption detection/repair, and password-protected archive handling for
# virtually every archive format in existence.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- Global Configuration ---
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly TMPDIR_BASE="${TMPDIR:-/tmp}"
readonly LOG_FILE="${UAM_LOG_FILE:-}"
readonly MAX_PATH_DEPTH=50  # Path traversal protection

# --- Color Codes (disabled if not a terminal) ---
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; RESET=''
fi

# --- Trap Handlers ---
cleanup() {
    local exit_code=$?
    if [[ -n "${UAM_TMPDIR:-}" && -d "${UAM_TMPDIR}" ]]; then
        rm -rf "${UAM_TMPDIR}" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT

handle_sigint() {
    msg_warn "Operation interrupted by user (SIGINT)."
    exit 130
}
trap handle_sigint INT

handle_sigterm() {
    msg_warn "Operation terminated (SIGTERM)."
    exit 143
}
trap handle_sigterm TERM

# --- Messaging Functions ---
msg_info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
msg_ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
msg_warn()  { echo -e "${YELLOW}[WARN]${RESET} $*" >&2; }
msg_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
msg_fatal() { echo -e "${RED}[FATAL]${RESET} $*" >&2; exit 1; }
msg_debug() { [[ "${UAM_DEBUG:-0}" == "1" ]] && echo -e "${CYAN}[DEBUG]${RESET} $*" >&2 || true; }

log_msg() {
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
    fi
}

# --- Utility Functions ---

# Check if a command exists
has_cmd() { command -v "$1" &>/dev/null; }

# Get file size in human-readable format
human_size() {
    local size=$1
    if (( size >= 1073741824 )); then
        printf "%.2f GB" "$(echo "scale=2; $size / 1073741824" | bc 2>/dev/null || echo "$((size / 1073741824))")"
    elif (( size >= 1048576 )); then
        printf "%.2f MB" "$(echo "scale=2; $size / 1048576" | bc 2>/dev/null || echo "$((size / 1048576))")"
    elif (( size >= 1024 )); then
        printf "%.2f KB" "$(echo "scale=2; $size / 1024" | bc 2>/dev/null || echo "$((size / 1024))")"
    else
        printf "%d B" "$size"
    fi
}

# Safely get file size across platforms
get_file_size() {
    local file="$1"
    if stat --version &>/dev/null 2>&1; then
        stat -c%s "$file" 2>/dev/null || echo 0
    else
        stat -f%z "$file" 2>/dev/null || echo 0
    fi
}

# Check available disk space (in bytes) for a given path
get_available_space() {
    local path="$1"
    df -P "$path" 2>/dev/null | awk 'NR==2 {print $4 * 1024}' || echo 0
}

# Validate output path for path traversal attacks
validate_path_safety() {
    local archive="$1"
    local tool="$2"
    local unsafe=0

    case "$tool" in
        tar)
            if tar -tf "$archive" 2>/dev/null | grep -qE '(^/|\.\./)'; then
                unsafe=1
            fi
            ;;
        zip)
            if has_cmd zipinfo; then
                if zipinfo -1 "$archive" 2>/dev/null | grep -qE '(^/|\.\./)'; then
                    unsafe=1
                fi
            elif has_cmd unzip; then
                if unzip -l "$archive" 2>/dev/null | awk 'NR>3{print $4}' | grep -qE '(^/|\.\./)'; then
                    unsafe=1
                fi
            fi
            ;;
        7z)
            if has_cmd 7z; then
                if 7z l "$archive" 2>/dev/null | grep -qE '(^/|\.\./)'; then
                    unsafe=1
                fi
            fi
            ;;
    esac

    if [[ "$unsafe" -eq 1 ]]; then
        msg_error "Path traversal detected in archive: $archive"
        msg_error "This archive contains absolute paths or '../' references."
        msg_error "This could be a malicious archive attempting to overwrite system files."
        msg_warn "Use --force-unsafe if you understand the risk and want to proceed."
        return 1
    fi
    return 0
}

# Generate SHA256 checksum
generate_checksum() {
    local file="$1"
    if has_cmd sha256sum; then
        sha256sum "$file"
    elif has_cmd shasum; then
        shasum -a 256 "$file"
    else
        msg_warn "No checksum tool available (sha256sum/shasum)."
    fi
}

# Create secure temporary directory
make_temp_dir() {
    UAM_TMPDIR="$(mktemp -d "${TMPDIR_BASE}/uam.XXXXXXXXXX")"
    echo "$UAM_TMPDIR"
}

# --- Dependency Management ---

# Map of tools to package names per distro
declare -A TOOL_PKG_APT=(
    [7z]="p7zip-full" [unrar]="unrar" [rar]="rar" [lz4]="lz4"
    [zstd]="zstd" [brotli]="brotli" [lzip]="lzip" [lzop]="lzop"
    [arj]="arj" [unace]="unace" [cabextract]="cabextract"
    [rpm2cpio]="rpm" [cpio]="cpio" [ar]="binutils"
    [unsquashfs]="squashfs-tools" [dar]="dar" [zpaq]="zpaq"
    [fuseiso]="fuseiso" [dmg2img]="dmg2img" [john]="john"
    [hashcat]="hashcat" [fcrackzip]="fcrackzip" [rarcrack]="rarcrack"
    [file]="file" [xxd]="xxd" [bc]="bc" [pigz]="pigz"
    [pbzip2]="pbzip2" [pixz]="pixz" [pzstd]="zstd"
    [isoinfo]="genisoimage" [bsdtar]="libarchive-tools"
)

declare -A TOOL_PKG_YUM=(
    [7z]="p7zip-plugins" [unrar]="unrar" [lz4]="lz4"
    [zstd]="zstd" [lzip]="lzip" [lzop]="lzop"
    [cabextract]="cabextract" [rpm2cpio]="rpm" [cpio]="cpio"
    [ar]="binutils" [unsquashfs]="squashfs-tools" [file]="file"
    [xxd]="vim-common" [bc]="bc" [pigz]="pigz"
    [bsdtar]="bsdtar" [isoinfo]="genisoimage"
)

declare -A TOOL_PKG_PACMAN=(
    [7z]="p7zip" [unrar]="unrar" [lz4]="lz4" [zstd]="zstd"
    [brotli]="brotli" [lzip]="lzip" [lzop]="lzop" [arj]="arj"
    [cabextract]="cabextract" [cpio]="cpio" [ar]="binutils"
    [unsquashfs]="squashfs-tools" [dar]="dar" [zpaq]="zpaq"
    [file]="file" [xxd]="xxd" [bc]="bc" [pigz]="pigz"
    [bsdtar]="libarchive" [isoinfo]="cdrtools"
)

detect_pkg_manager() {
    if has_cmd apt-get; then echo "apt"
    elif has_cmd dnf; then echo "dnf"
    elif has_cmd yum; then echo "yum"
    elif has_cmd pacman; then echo "pacman"
    elif has_cmd zypper; then echo "zypper"
    elif has_cmd emerge; then echo "emerge"
    elif has_cmd apk; then echo "apk"
    elif has_cmd brew; then echo "brew"
    else echo "unknown"
    fi
}

get_install_cmd() {
    local tool="$1"
    local pm
    pm="$(detect_pkg_manager)"

    case "$pm" in
        apt)
            local pkg="${TOOL_PKG_APT[$tool]:-$tool}"
            echo "sudo apt-get install -y $pkg"
            ;;
        dnf)
            local pkg="${TOOL_PKG_YUM[$tool]:-$tool}"
            echo "sudo dnf install -y $pkg"
            ;;
        yum)
            local pkg="${TOOL_PKG_YUM[$tool]:-$tool}"
            echo "sudo yum install -y $pkg"
            ;;
        pacman)
            local pkg="${TOOL_PKG_PACMAN[$tool]:-$tool}"
            echo "sudo pacman -S --noconfirm $pkg"
            ;;
        zypper)
            echo "sudo zypper install -y $tool"
            ;;
        emerge)
            echo "sudo emerge $tool"
            ;;
        apk)
            echo "sudo apk add $tool"
            ;;
        brew)
            echo "brew install $tool"
            ;;
        *)
            echo "# Install '$tool' using your system's package manager"
            ;;
    esac
}

check_dependency() {
    local tool="$1"
    local required="${2:-optional}"

    if ! has_cmd "$tool"; then
        if [[ "$required" == "required" ]]; then
            msg_error "'$tool' is required but not installed."
            msg_info "Install with: $(get_install_cmd "$tool")"
            return 1
        else
            msg_debug "'$tool' not found (optional)."
            return 1
        fi
    fi
    return 0
}

check_core_dependencies() {
    local missing=0
    local core_tools=("file" "tar" "gzip" "bzip2" "xz")

    for tool in "${core_tools[@]}"; do
        if ! has_cmd "$tool"; then
            msg_error "Core dependency missing: $tool"
            msg_info "Install with: $(get_install_cmd "$tool")"
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        msg_fatal "Core dependencies are missing. Install them and retry."
    fi
}

install_all_dependencies() {
    msg_info "Generating installation commands for all supported tools..."
    local pm
    pm="$(detect_pkg_manager)"
    msg_info "Detected package manager: $pm"
    echo ""

    local all_tools=(
        "7z" "unrar" "rar" "lz4" "zstd" "brotli" "lzip" "lzop"
        "arj" "unace" "cabextract" "rpm2cpio" "cpio" "ar"
        "unsquashfs" "dar" "zpaq" "fuseiso" "dmg2img"
        "file" "xxd" "bc" "pigz" "pbzip2" "bsdtar" "isoinfo"
    )

    local missing_tools=()
    for tool in "${all_tools[@]}"; do
        if ! has_cmd "$tool"; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        msg_ok "All tools are already installed."
        return 0
    fi

    msg_info "Missing tools: ${missing_tools[*]}"
    echo ""
    echo "Run the following commands to install missing tools:"
    echo "-----------------------------------------------------"
    for tool in "${missing_tools[@]}"; do
        echo "  $(get_install_cmd "$tool")"
    done
    echo "-----------------------------------------------------"

    # One-liner for apt-based systems
    if [[ "$pm" == "apt" ]]; then
        echo ""
        echo "Or install all at once:"
        local pkgs=""
        for tool in "${missing_tools[@]}"; do
            pkgs+="${TOOL_PKG_APT[$tool]:-$tool} "
        done
        echo "  sudo apt-get install -y $pkgs"
    fi
}

# --- Format Detection ---

# Detect format by magic bytes (file signature)
detect_by_magic() {
    local file="$1"
    local magic

    # Read first 16 bytes as hex
    magic="$(xxd -p -l 16 "$file" 2>/dev/null | tr -d '\n')" || magic=""

    if [[ -z "$magic" ]]; then
        # Fallback to file command
        file --brief --mime-type "$file" 2>/dev/null || echo "unknown"
        return
    fi

    # Match known signatures
    case "$magic" in
        504b0304*|504b0506*|504b0708*)  echo "zip" ;;
        526172211a07*)
            if [[ "$magic" == 526172211a0700* ]]; then echo "rar5"
            else echo "rar4"
            fi
            ;;
        377abcaf271c*)                   echo "7z" ;;
        1f8b*)                           echo "gzip" ;;
        425a68*)                         echo "bzip2" ;;
        fd377a585a00*)                   echo "xz" ;;
        28b52ffd*)                       echo "zstd" ;;
        04224d18*)                       echo "lz4" ;;
        4c5a4950*)                       echo "lzip" ;;
        5d00*)                           echo "lzma" ;;
        894c5a4f*)                       echo "lzo" ;;
        1f9d*)                           echo "compress" ;; # .Z
        60ea*)                           echo "arj" ;;
        4d534346*)                       echo "cab" ;;
        edabeedb*)                       echo "rpm" ;;
        213c617263683e*)                 echo "deb" ;;  # !<arch>
        4344303031*)                     echo "iso" ;;  # CD001
        68737173*)                       echo "squashfs" ;;
        30373037*)                       echo "cpio" ;;  # 070707
        23212f*)                         echo "shar" ;;  # #!/
        *)
            # Secondary detection via file command
            local ftype
            ftype="$(file --brief "$file" 2>/dev/null)" || ftype=""
            case "$ftype" in
                *"Zip archive"*)         echo "zip" ;;
                *"RAR archive"*)         echo "rar" ;;
                *"7-zip"*)               echo "7z" ;;
                *"gzip"*)                echo "gzip" ;;
                *"bzip2"*)               echo "bzip2" ;;
                *"XZ compressed"*)       echo "xz" ;;
                *"Zstandard"*)           echo "zstd" ;;
                *"LZ4"*)                 echo "lz4" ;;
                *"LZMA"*)               echo "lzma" ;;
                *"lzip"*)                echo "lzip" ;;
                *"ISO 9660"*)            echo "iso" ;;
                *"RPM"*)                 echo "rpm" ;;
                *"Debian"*)              echo "deb" ;;
                *"Java archive"*|*"JAR"*) echo "jar" ;;
                *"tar archive"*)         echo "tar" ;;
                *"cpio archive"*)        echo "cpio" ;;
                *"ar archive"*)          echo "ar" ;;
                *"Squashfs"*)            echo "squashfs" ;;
                *"Microsoft Cabinet"*)   echo "cab" ;;
                *"ARJ archive"*)         echo "arj" ;;
                *"ACE archive"*)         echo "ace" ;;
                *"VMDK"*)                echo "vmdk" ;;
                *"VHD"*)                 echo "vhd" ;;
                *"Apple Disk Image"*)    echo "dmg" ;;
                *"ELF"*|*"executable"*)  echo "elf" ;;
                *"PE32"*|*"MS-DOS"*)     echo "exe" ;;
                *"Brotli"*)              echo "brotli" ;;
                *"DAR archive"*)         echo "dar" ;;
                *"ZPAQ"*)               echo "zpaq" ;;
                *"AppImage"*)            echo "appimage" ;;
                *)                       echo "unknown" ;;
            esac
            ;;
    esac
}

# Detect format by file extension
detect_by_extension() {
    local file="$1"
    local name
    name="$(basename "$file" | tr '[:upper:]' '[:lower:]')"

    # Check double extensions first (order matters)
    case "$name" in
        *.tar.gz|*.tgz)       echo "tar.gz" ;;
        *.tar.bz2|*.tbz2|*.tbz) echo "tar.bz2" ;;
        *.tar.xz|*.txz)      echo "tar.xz" ;;
        *.tar.zst|*.tzst)     echo "tar.zst" ;;
        *.tar.lz4)            echo "tar.lz4" ;;
        *.tar.lz|*.tar.lzip)  echo "tar.lzip" ;;
        *.tar.lzma)           echo "tar.lzma" ;;
        *.tar.lzo)            echo "tar.lzo" ;;
        *.tar.br)             echo "tar.br" ;;
        *.tar.z)              echo "tar.Z" ;;
        *.tar.zpaq)           echo "tar.zpaq" ;;
        *.pkg.tar.zst)        echo "pkg.tar.zst" ;;
        *.pkg.tar.xz)         echo "pkg.tar.xz" ;;
        *.pkg.tar.gz)         echo "pkg.tar.gz" ;;
        # Single extensions
        *.tar)                echo "tar" ;;
        *.zip)                echo "zip" ;;
        *.gz)                 echo "gz" ;;
        *.bz2)                echo "bz2" ;;
        *.xz)                 echo "xz" ;;
        *.zst)                echo "zst" ;;
        *.lz4)                echo "lz4" ;;
        *.lzma)               echo "lzma" ;;
        *.lz|*.lzip)          echo "lzip" ;;
        *.lzo)                echo "lzo" ;;
        *.z)                  echo "Z" ;;
        *.br)                 echo "brotli" ;;
        *.7z)                 echo "7z" ;;
        *.rar)                echo "rar" ;;
        *.arj)                echo "arj" ;;
        *.ace)                echo "ace" ;;
        *.cab)                echo "cab" ;;
        *.rpm)                echo "rpm" ;;
        *.deb)                echo "deb" ;;
        *.pkg)                echo "pkg" ;;
        *.dmg)                echo "dmg" ;;
        *.iso)                echo "iso" ;;
        *.img)                echo "img" ;;
        *.bin)                echo "bin" ;;
        *.cue)                echo "cue" ;;
        *.nrg)                echo "nrg" ;;
        *.mdf)                echo "mdf" ;;
        *.vhd)                echo "vhd" ;;
        *.vmdk)               echo "vmdk" ;;
        *.cpio)               echo "cpio" ;;
        *.shar|*.sh)          echo "shar" ;;
        *.ar|*.a)             echo "ar" ;;
        *.msi)                echo "msi" ;;
        *.jar)                echo "jar" ;;
        *.war)                echo "war" ;;
        *.ear)                echo "ear" ;;
        *.apk)                echo "apk" ;;
        *.ipa)                echo "ipa" ;;
        *.xpi)                echo "xpi" ;;
        *.squashfs|*.sqfs|*.sfs) echo "squashfs" ;;
        *.cramfs)             echo "cramfs" ;;
        *.dar)                echo "dar" ;;
        *.zpaq)               echo "zpaq" ;;
        *.exe)                echo "exe" ;;
        *.msu)                echo "msu" ;;
        *.msp)                echo "msp" ;;
        *.appimage)           echo "appimage" ;;
        *.snap)               echo "snap" ;;
        *.flatpak)            echo "flatpak" ;;
        *.flatpakref)         echo "flatpakref" ;;
        *.sbx)                echo "sbx" ;;
        *)                    echo "unknown" ;;
    esac
}

# Combined format detection: extension first, then magic bytes for verification/fallback
detect_format() {
    local file="$1"
    local ext_fmt magic_fmt final_fmt

    ext_fmt="$(detect_by_extension "$file")"
    magic_fmt="$(detect_by_magic "$file")"

    msg_debug "Extension detection: $ext_fmt"
    msg_debug "Magic byte detection: $magic_fmt"

    if [[ "$ext_fmt" == "unknown" && "$magic_fmt" == "unknown" ]]; then
        # Last resort: try bsdtar
        if has_cmd bsdtar && bsdtar -tf "$file" &>/dev/null; then
            echo "tar"
            return
        fi
        # Try 7z as universal fallback
        if has_cmd 7z && 7z l "$file" &>/dev/null; then
            echo "7z-generic"
            return
        fi
        echo "unknown"
        return
    fi

    # If extension says unknown, trust magic
    if [[ "$ext_fmt" == "unknown" ]]; then
        final_fmt="$magic_fmt"
    # If magic says unknown, trust extension
    elif [[ "$magic_fmt" == "unknown" ]]; then
        final_fmt="$ext_fmt"
    else
        # Both have opinions - extension takes priority for compound formats
        final_fmt="$ext_fmt"
    fi

    echo "$final_fmt"
}

# --- Password Protection Detection ---

detect_password_protection() {
    local file="$1"
    local fmt="$2"
    local is_encrypted=0

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            if has_cmd 7z; then
                if 7z l -slt "$file" 2>/dev/null | grep -qi "Encrypted = +"; then
                    is_encrypted=1
                fi
            elif has_cmd unzip; then
                # Try listing; if entries show encryption flags
                if unzip -l "$file" 2>&1 | grep -qi "unsupported compression\|need password\|encrypted"; then
                    is_encrypted=1
                fi
                # Also check: unzip -t will fail on encrypted
                if unzip -tq "$file" 2>&1 | grep -qi "incorrect password\|need password\|unsupported compression"; then
                    is_encrypted=1
                fi
            fi
            ;;
        rar|rar4|rar5)
            if has_cmd unrar; then
                if unrar lt "$file" 2>&1 | grep -qi "encrypted\|password"; then
                    is_encrypted=1
                fi
            elif has_cmd 7z; then
                if 7z l -slt "$file" 2>/dev/null | grep -qi "Encrypted = +"; then
                    is_encrypted=1
                fi
            fi
            ;;
        7z|7z-generic)
            if has_cmd 7z; then
                local output
                output="$(7z l -slt "$file" 2>/dev/null)"
                if echo "$output" | grep -qi "Encrypted = +"; then
                    is_encrypted=1
                fi
                # Check for encrypted headers
                if echo "$output" | grep -qi "Headers Error\|Can not open encrypted archive"; then
                    is_encrypted=2  # encrypted headers
                fi
            fi
            ;;
        *)
            # For other formats, try 7z as a generic test
            if has_cmd 7z; then
                if 7z l "$file" 2>&1 | grep -qi "Encrypted\|password"; then
                    is_encrypted=1
                fi
            fi
            ;;
    esac

    return $((is_encrypted > 0 ? 0 : 1))
}

# --- Archive Corruption Detection & Repair ---

check_archive_integrity() {
    local file="$1"
    local fmt="$2"
    local result=0

    msg_info "Testing integrity of: $(basename "$file")"
    log_msg "Integrity test: $file (format: $fmt)"

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            if has_cmd zip; then
                if ! zip -T "$file" 2>/dev/null; then
                    msg_warn "zip -T reports corruption."
                    result=1
                fi
            fi
            if has_cmd unzip; then
                if ! unzip -tq "$file" 2>/dev/null; then
                    msg_warn "unzip -t reports errors."
                    result=1
                fi
            fi
            ;;
        tar|tar.gz|tar.bz2|tar.xz|tar.zst|tar.lz4|tar.lzip|tar.lzma|tar.lzo|tar.br|tar.Z|tar.zpaq)
            local tar_test_ok=1
            case "$fmt" in
                tar)       tar -tf "$file" &>/dev/null || tar_test_ok=0 ;;
                tar.gz)    tar -tzf "$file" &>/dev/null || tar_test_ok=0 ;;
                tar.bz2)   tar -tjf "$file" &>/dev/null || tar_test_ok=0 ;;
                tar.xz)    tar -tJf "$file" &>/dev/null || tar_test_ok=0 ;;
                tar.zst)   zstd -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.lz4)   lz4 -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.lzip)  lzip -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.lzma)  xz --format=lzma -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.lzo)   lzop -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.br)    brotli -dc "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                tar.Z)     uncompress -c "$file" 2>/dev/null | tar -tf - &>/dev/null || tar_test_ok=0 ;;
                *)         tar -tf "$file" &>/dev/null || tar_test_ok=0 ;;
            esac
            if [[ "$tar_test_ok" -eq 0 ]]; then
                msg_warn "Archive fails decompression/listing test."
                result=1
            fi
            ;;
        gz)
            if ! gzip -t "$file" 2>/dev/null; then
                msg_warn "gzip integrity test failed."
                result=1
            fi
            ;;
        bz2)
            if ! bzip2 -t "$file" 2>/dev/null; then
                msg_warn "bzip2 integrity test failed."
                result=1
            fi
            ;;
        xz)
            if ! xz -t "$file" 2>/dev/null; then
                msg_warn "xz integrity test failed."
                result=1
            fi
            ;;
        zst)
            if has_cmd zstd && ! zstd -t "$file" 2>/dev/null; then
                msg_warn "zstd integrity test failed."
                result=1
            fi
            ;;
        lz4)
            if has_cmd lz4 && ! lz4 -t "$file" 2>/dev/null; then
                msg_warn "lz4 integrity test failed."
                result=1
            fi
            ;;
        7z|7z-generic)
            if has_cmd 7z; then
                if ! 7z t "$file" 2>/dev/null; then
                    msg_warn "7z integrity test failed."
                    result=1
                fi
            fi
            ;;
        rar|rar4|rar5)
            if has_cmd unrar; then
                if ! unrar t "$file" 2>/dev/null; then
                    msg_warn "RAR integrity test failed."
                    result=1
                fi
            elif has_cmd 7z; then
                if ! 7z t "$file" 2>/dev/null; then
                    msg_warn "7z integrity test on RAR failed."
                    result=1
                fi
            fi
            ;;
        iso)
            if has_cmd 7z; then
                if ! 7z t "$file" 2>/dev/null; then
                    msg_warn "ISO integrity test failed."
                    result=1
                fi
            fi
            ;;
        deb)
            if has_cmd ar; then
                if ! ar t "$file" &>/dev/null; then
                    msg_warn "DEB (ar) integrity test failed."
                    result=1
                fi
            fi
            ;;
        rpm)
            if has_cmd rpm; then
                if ! rpm -K "$file" 2>/dev/null; then
                    msg_warn "RPM signature check failed."
                    result=1
                fi
            fi
            ;;
        cpio)
            if has_cmd cpio; then
                if ! cpio -it < "$file" &>/dev/null; then
                    msg_warn "CPIO listing test failed."
                    result=1
                fi
            fi
            ;;
        *)
            # Generic 7z test as fallback
            if has_cmd 7z; then
                if ! 7z t "$file" &>/dev/null; then
                    msg_warn "Generic integrity test failed."
                    result=1
                fi
            else
                msg_warn "No integrity test available for format: $fmt"
            fi
            ;;
    esac

    if [[ "$result" -eq 0 ]]; then
        msg_ok "Integrity test passed."
    else
        msg_error "Integrity test FAILED. Archive may be corrupted."
    fi

    return "$result"
}

# Attempt to repair corrupted archives
repair_archive() {
    local file="$1"
    local fmt="$2"
    local output_dir="${3:-.}"

    msg_info "Attempting repair of: $(basename "$file")"
    log_msg "Repair attempt: $file (format: $fmt)"

    local repaired=0
    local repaired_file=""

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            # Method 1: zip -FF (fix/fixfix)
            if has_cmd zip; then
                repaired_file="${output_dir}/REPAIRED_$(basename "$file")"
                msg_info "Attempting zip -FF (full fix)..."
                if zip -FF "$file" --out "$repaired_file" 2>/dev/null; then
                    msg_ok "zip -FF repair succeeded: $repaired_file"
                    repaired=1
                else
                    msg_warn "zip -FF failed, trying zip -F (single fix)..."
                    if zip -F "$file" --out "$repaired_file" 2>/dev/null; then
                        msg_ok "zip -F repair succeeded: $repaired_file"
                        repaired=1
                    fi
                fi
            fi

            # Method 2: 7z partial extraction (extract what we can)
            if [[ "$repaired" -eq 0 ]] && has_cmd 7z; then
                local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.[^.]*$//')"
                mkdir -p "$rescue_dir"
                msg_info "Attempting partial extraction with 7z..."
                if 7z x -o"$rescue_dir" -y "$file" 2>/dev/null; then
                    msg_ok "Partial extraction to: $rescue_dir"
                    repaired=1
                fi
            fi

            # Method 3: jar fix for Java archives
            if [[ "$repaired" -eq 0 && ("$fmt" == "jar" || "$fmt" == "war" || "$fmt" == "ear") ]]; then
                if has_cmd jar; then
                    msg_info "Attempting jar extraction..."
                    local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.[^.]*$//')"
                    mkdir -p "$rescue_dir"
                    (cd "$rescue_dir" && jar xf "$file" 2>/dev/null) && repaired=1
                fi
            fi
            ;;

        rar|rar4|rar5)
            # Method 1: unrar with keep-broken flag
            if has_cmd unrar; then
                local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.[^.]*$//')"
                mkdir -p "$rescue_dir"
                msg_info "Attempting unrar with -kb (keep broken)..."
                if unrar x -kb -y "$file" "$rescue_dir/" 2>/dev/null; then
                    msg_ok "RAR partial extraction succeeded: $rescue_dir"
                    repaired=1
                fi
            fi

            # Method 2: rar r (repair)
            if [[ "$repaired" -eq 0 ]] && has_cmd rar; then
                repaired_file="${output_dir}/REPAIRED_$(basename "$file")"
                msg_info "Attempting rar repair (rar r)..."
                cp "$file" "$repaired_file"
                if rar r "$repaired_file" 2>/dev/null; then
                    msg_ok "RAR repair succeeded: $repaired_file"
                    repaired=1
                fi
            fi
            ;;

        7z|7z-generic)
            if has_cmd 7z; then
                local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.[^.]*$//')"
                mkdir -p "$rescue_dir"
                msg_info "Attempting 7z extraction with skip errors..."
                # 7z doesn't have a repair mode, but we can extract what's possible
                if 7z x -o"$rescue_dir" -y -ai\!"$file" 2>/dev/null || \
                   7z e -o"$rescue_dir" -y "$file" 2>/dev/null; then
                    msg_ok "Partial extraction: $rescue_dir"
                    repaired=1
                fi
            fi
            ;;

        tar|tar.gz|tar.bz2|tar.xz|tar.zst|tar.lz4|tar.lzip|tar.lzma)
            local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.tar\.[^.]*$//; s/\.tar$//')"
            mkdir -p "$rescue_dir"

            # Method 1: bsdtar (more tolerant of corruption)
            if has_cmd bsdtar; then
                msg_info "Attempting extraction with bsdtar (corruption tolerant)..."
                if bsdtar -xf "$file" -C "$rescue_dir" --ignore-zeros 2>/dev/null; then
                    msg_ok "bsdtar extraction succeeded: $rescue_dir"
                    repaired=1
                fi
            fi

            # Method 2: GNU tar with --ignore-zeros
            if [[ "$repaired" -eq 0 ]]; then
                msg_info "Attempting GNU tar with --ignore-zeros..."
                local tar_opts=("--ignore-zeros" "-xf" "$file" "-C" "$rescue_dir")
                case "$fmt" in
                    tar.gz)  tar_opts=("--ignore-zeros" "-xzf" "$file" "-C" "$rescue_dir") ;;
                    tar.bz2) tar_opts=("--ignore-zeros" "-xjf" "$file" "-C" "$rescue_dir") ;;
                    tar.xz)  tar_opts=("--ignore-zeros" "-xJf" "$file" "-C" "$rescue_dir") ;;
                esac
                if tar "${tar_opts[@]}" 2>/dev/null; then
                    msg_ok "GNU tar partial extraction: $rescue_dir"
                    repaired=1
                fi
            fi

            # Method 3: Decompress first, then salvage the tar
            if [[ "$repaired" -eq 0 && "$fmt" != "tar" ]]; then
                msg_info "Attempting decompress-then-salvage approach..."
                local tmp_tar
                tmp_tar="$(make_temp_dir)/salvage.tar"
                local dc_result=0
                case "$fmt" in
                    tar.gz)  gzip -dc "$file" > "$tmp_tar" 2>/dev/null || dc_result=1 ;;
                    tar.bz2) bzip2 -dc "$file" > "$tmp_tar" 2>/dev/null || dc_result=1 ;;
                    tar.xz)  xz -dc "$file" > "$tmp_tar" 2>/dev/null || dc_result=1 ;;
                    tar.zst) zstd -dc "$file" > "$tmp_tar" 2>/dev/null || dc_result=1 ;;
                esac
                if [[ "$dc_result" -eq 0 || -s "$tmp_tar" ]]; then
                    tar -xf "$tmp_tar" -C "$rescue_dir" --ignore-zeros 2>/dev/null && repaired=1
                    if [[ "$repaired" -eq 1 ]]; then
                        msg_ok "Decompress-salvage extraction: $rescue_dir"
                    fi
                fi
            fi
            ;;

        gz)
            if has_cmd gzrecover; then
                repaired_file="${output_dir}/RECOVERED_$(basename "$file" .gz)"
                msg_info "Attempting gzrecover..."
                if gzrecover -o "$repaired_file" "$file" 2>/dev/null; then
                    msg_ok "gzrecover succeeded: $repaired_file"
                    repaired=1
                fi
            else
                msg_info "Install gzrecover for gz repair: $(get_install_cmd gzrecover)"
                # Try partial decompression
                repaired_file="${output_dir}/PARTIAL_$(basename "$file" .gz)"
                msg_info "Attempting partial gzip decompression..."
                if gzip -dc "$file" > "$repaired_file" 2>/dev/null; then
                    if [[ -s "$repaired_file" ]]; then
                        msg_ok "Partial decompression saved: $repaired_file"
                        repaired=1
                    fi
                fi
            fi
            ;;

        *)
            # Generic rescue via 7z
            if has_cmd 7z; then
                local rescue_dir="${output_dir}/RESCUED_$(basename "$file" | sed 's/\.[^.]*$//')"
                mkdir -p "$rescue_dir"
                msg_info "Attempting generic rescue with 7z..."
                if 7z x -o"$rescue_dir" -y "$file" 2>/dev/null; then
                    msg_ok "Generic rescue extraction: $rescue_dir"
                    repaired=1
                fi
            fi
            ;;
    esac

    if [[ "$repaired" -eq 0 ]]; then
        msg_error "All repair attempts failed."
        msg_info "Manual recovery options:"
        echo "  1. Try 'foremost' or 'scalpel' for carving files from the archive"
        echo "  2. Use 'binwalk' to analyze and extract embedded files"
        echo "  3. Hex edit the archive headers with 'hexedit' or 'xxd'"
        echo "  4. For ZIP: python3 -c \"import zipfile; z=zipfile.ZipFile('$file'); z.extractall()\""
        echo "  5. For forensic recovery: 'photorec' can recover files from damaged archives"
        return 1
    fi

    return 0
}

# --- Forensic Archive Analysis ---

forensic_info() {
    local file="$1"
    local fmt="$2"

    echo "================================================================"
    echo " Archive Forensic Analysis"
    echo "================================================================"
    echo ""
    echo "File:      $(basename "$file")"
    echo "Full Path: $(realpath "$file" 2>/dev/null || echo "$file")"
    echo "Size:      $(human_size "$(get_file_size "$file")")"
    echo "Format:    $fmt"
    echo ""

    # File metadata
    echo "--- File System Metadata ---"
    if stat --version &>/dev/null 2>&1; then
        stat "$file" 2>/dev/null
    else
        stat -x "$file" 2>/dev/null || stat "$file" 2>/dev/null
    fi
    echo ""

    # Magic bytes
    echo "--- Magic Bytes (first 32 bytes) ---"
    if has_cmd xxd; then
        xxd -l 32 "$file" 2>/dev/null
    elif has_cmd od; then
        od -A x -t x1z -N 32 "$file" 2>/dev/null
    fi
    echo ""

    # file command output
    echo "--- File Type Analysis ---"
    file "$file" 2>/dev/null
    if has_cmd file; then
        echo "MIME: $(file --brief --mime "$file" 2>/dev/null)"
    fi
    echo ""

    # Checksums
    echo "--- Checksums ---"
    if has_cmd md5sum; then
        echo "MD5:    $(md5sum "$file" | awk '{print $1}')"
    elif has_cmd md5; then
        echo "MD5:    $(md5 -q "$file")"
    fi
    if has_cmd sha1sum; then
        echo "SHA1:   $(sha1sum "$file" | awk '{print $1}')"
    elif has_cmd shasum; then
        echo "SHA1:   $(shasum -a 1 "$file" | awk '{print $1}')"
    fi
    if has_cmd sha256sum; then
        echo "SHA256: $(sha256sum "$file" | awk '{print $1}')"
    elif has_cmd shasum; then
        echo "SHA256: $(shasum -a 256 "$file" | awk '{print $1}')"
    fi
    echo ""

    # Entropy analysis (detect encryption/compression quality)
    if has_cmd ent; then
        echo "--- Entropy Analysis ---"
        ent "$file" 2>/dev/null
        echo ""
    fi

    # Binwalk scan
    if has_cmd binwalk; then
        echo "--- Binwalk Scan ---"
        binwalk "$file" 2>/dev/null
        echo ""
    fi

    # Format-specific details
    echo "--- Format-Specific Details ---"
    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            if has_cmd zipinfo; then
                zipinfo "$file" 2>/dev/null || true
            elif has_cmd unzip; then
                unzip -l "$file" 2>/dev/null || true
            fi
            # Encryption details
            if has_cmd 7z; then
                echo ""
                echo "--- Encryption Details ---"
                7z l -slt "$file" 2>/dev/null | grep -E "(Encrypted|Method|CRC|Modified|Size)" || true
            fi
            ;;
        rar|rar4|rar5)
            if has_cmd unrar; then
                unrar lt "$file" 2>/dev/null || true
            fi
            ;;
        7z|7z-generic)
            if has_cmd 7z; then
                7z l -slt "$file" 2>/dev/null | head -100 || true
            fi
            ;;
        tar|tar.gz|tar.bz2|tar.xz|tar.zst)
            tar -tvf "$file" 2>/dev/null | head -50 || true
            ;;
        iso)
            if has_cmd isoinfo; then
                isoinfo -d -i "$file" 2>/dev/null || true
            fi
            ;;
        deb)
            if has_cmd dpkg-deb; then
                dpkg-deb -I "$file" 2>/dev/null || true
            fi
            ;;
        rpm)
            if has_cmd rpm; then
                rpm -qip "$file" 2>/dev/null || true
            fi
            ;;
    esac
    echo ""

    # Password protection status
    echo "--- Password Protection ---"
    if detect_password_protection "$file" "$fmt" 2>/dev/null; then
        echo "Status: ENCRYPTED / PASSWORD PROTECTED"
        echo "Run: $SCRIPT_NAME -p '$file' for cracking guidance."
    else
        echo "Status: Not encrypted"
    fi
    echo ""

    # Integrity
    echo "--- Quick Integrity Check ---"
    check_archive_integrity "$file" "$fmt" 2>/dev/null || true
    echo ""
    echo "================================================================"
}

# --- List Archive Contents ---

list_archive() {
    local file="$1"
    local fmt="$2"

    msg_info "Listing contents of: $(basename "$file") (format: $fmt)"

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            if has_cmd unzip; then
                unzip -l "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        tar)
            tar -tvf "$file" 2>/dev/null
            ;;
        tar.gz)
            tar -tzvf "$file" 2>/dev/null
            ;;
        tar.bz2)
            tar -tjvf "$file" 2>/dev/null
            ;;
        tar.xz)
            tar -tJvf "$file" 2>/dev/null
            ;;
        tar.zst)
            if has_cmd zstd; then
                zstd -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.lz4)
            if has_cmd lz4; then
                lz4 -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.lzip)
            if has_cmd lzip; then
                lzip -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.lzma)
            if has_cmd lzma; then
                lzma -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            elif has_cmd xz; then
                xz --format=lzma -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.lzo)
            if has_cmd lzop; then
                lzop -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.br)
            if has_cmd brotli; then
                brotli -dc "$file" 2>/dev/null | tar -tv 2>/dev/null
            fi
            ;;
        tar.Z)
            uncompress -c "$file" 2>/dev/null | tar -tv 2>/dev/null
            ;;
        7z|7z-generic)
            if has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        rar|rar4|rar5)
            if has_cmd unrar; then
                unrar l "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        gz|bz2|xz|zst|lz4|lzma|lzip|lzo|brotli|Z)
            msg_info "Single-file compressed format. Decompressed name:"
            echo "  $(basename "$file" | sed 's/\.\(gz\|bz2\|xz\|zst\|lz4\|lzma\|lz\|lzip\|lzo\|br\|Z\)$//')"
            msg_info "Size compressed:   $(human_size "$(get_file_size "$file")")"
            ;;
        arj)
            if has_cmd arj; then
                arj l "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        ace)
            if has_cmd unace; then
                unace l "$file" 2>/dev/null
            fi
            ;;
        cab)
            if has_cmd cabextract; then
                cabextract -l "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        rpm)
            if has_cmd rpm; then
                rpm -qlp "$file" 2>/dev/null
            elif has_cmd rpm2cpio && has_cmd cpio; then
                rpm2cpio "$file" 2>/dev/null | cpio -t 2>/dev/null
            fi
            ;;
        deb)
            if has_cmd dpkg-deb; then
                dpkg-deb -c "$file" 2>/dev/null
            elif has_cmd ar; then
                ar t "$file" 2>/dev/null
            fi
            ;;
        iso)
            if has_cmd isoinfo; then
                isoinfo -lR -i "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            elif has_cmd bsdtar; then
                bsdtar -tf "$file" 2>/dev/null
            fi
            ;;
        cpio)
            cpio -t < "$file" 2>/dev/null
            ;;
        ar)
            ar t "$file" 2>/dev/null
            ;;
        squashfs)
            if has_cmd unsquashfs; then
                unsquashfs -l "$file" 2>/dev/null
            fi
            ;;
        dmg)
            if has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        dar)
            if has_cmd dar; then
                dar -l "$file" 2>/dev/null
            fi
            ;;
        zpaq)
            if has_cmd zpaq; then
                zpaq l "$file" 2>/dev/null
            fi
            ;;
        exe|msi|msu|msp)
            if has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        img|bin|nrg|mdf|vhd|vmdk)
            if has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        appimage)
            msg_info "AppImage contents (--appimage-extract --list):"
            chmod +x "$file" 2>/dev/null || true
            "$file" --appimage-extract --list 2>/dev/null || {
                if has_cmd 7z; then
                    7z l "$file" 2>/dev/null
                fi
            }
            ;;
        snap)
            if has_cmd unsquashfs; then
                unsquashfs -l "$file" 2>/dev/null
            elif has_cmd 7z; then
                7z l "$file" 2>/dev/null
            fi
            ;;
        pkg.tar.zst|pkg.tar.xz|pkg.tar.gz)
            case "$fmt" in
                pkg.tar.zst) zstd -dc "$file" 2>/dev/null | tar -tv 2>/dev/null ;;
                pkg.tar.xz)  tar -tJvf "$file" 2>/dev/null ;;
                pkg.tar.gz)  tar -tzvf "$file" 2>/dev/null ;;
            esac
            ;;
        *)
            # Fallback
            if has_cmd 7z; then
                7z l "$file" 2>/dev/null
            elif has_cmd bsdtar; then
                bsdtar -tf "$file" 2>/dev/null
            else
                msg_error "Cannot list contents: unsupported format '$fmt'"
                return 1
            fi
            ;;
    esac
}

# --- Extraction Engine ---

extract_archive() {
    local file="$1"
    local fmt="$2"
    local output_dir="${3:-.}"
    local password="${4:-}"
    local force_unsafe="${5:-0}"

    # Ensure output directory exists
    mkdir -p "$output_dir" 2>/dev/null || {
        msg_error "Cannot create output directory: $output_dir"
        return 1
    }

    # Check write permission
    if [[ ! -w "$output_dir" ]]; then
        msg_error "Output directory is not writable: $output_dir"
        return 1
    fi

    # Check available disk space (rough estimate: archive size * 5)
    local file_size available_space
    file_size="$(get_file_size "$file")"
    available_space="$(get_available_space "$output_dir")"
    local estimated_extracted=$((file_size * 5))

    if [[ "$available_space" -gt 0 && "$estimated_extracted" -gt "$available_space" ]]; then
        msg_warn "Low disk space warning."
        msg_warn "Archive size: $(human_size "$file_size")"
        msg_warn "Available:    $(human_size "$available_space")"
        msg_warn "Estimated need: $(human_size "$estimated_extracted") (5x archive size)"
    fi

    # Path traversal check
    if [[ "$force_unsafe" -ne 1 ]]; then
        case "$fmt" in
            tar*) validate_path_safety "$file" "tar" || return 1 ;;
            zip*|jar|war|ear|xpi|apk) validate_path_safety "$file" "zip" || return 1 ;;
            7z*) validate_path_safety "$file" "7z" || return 1 ;;
        esac
    fi

    local pw_opts=()
    if [[ -n "$password" ]]; then
        pw_opts=("-p$password")
    fi

    msg_info "Extracting: $(basename "$file") -> $output_dir"
    log_msg "Extract: $file -> $output_dir (format: $fmt)"

    case "$fmt" in
        # --- TAR variants ---
        tar)
            tar -xf "$file" -C "$output_dir" --no-same-owner 2>/dev/null || \
            tar -xf "$file" -C "$output_dir" 2>/dev/null
            ;;
        tar.gz)
            tar -xzf "$file" -C "$output_dir" --no-same-owner 2>/dev/null || \
            tar -xzf "$file" -C "$output_dir" 2>/dev/null
            ;;
        tar.bz2)
            tar -xjf "$file" -C "$output_dir" --no-same-owner 2>/dev/null || \
            tar -xjf "$file" -C "$output_dir" 2>/dev/null
            ;;
        tar.xz)
            tar -xJf "$file" -C "$output_dir" --no-same-owner 2>/dev/null || \
            tar -xJf "$file" -C "$output_dir" 2>/dev/null
            ;;
        tar.zst)
            check_dependency "zstd" "required" || return 1
            zstd -dc "$file" | tar -xf - -C "$output_dir" --no-same-owner 2>/dev/null || \
            zstd -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.lz4)
            check_dependency "lz4" "required" || return 1
            lz4 -dc "$file" | tar -xf - -C "$output_dir" --no-same-owner 2>/dev/null || \
            lz4 -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.lzip)
            check_dependency "lzip" "required" || return 1
            lzip -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.lzma)
            if has_cmd lzma; then
                lzma -dc "$file" | tar -xf - -C "$output_dir"
            elif has_cmd xz; then
                xz --format=lzma -dc "$file" | tar -xf - -C "$output_dir"
            else
                msg_fatal "No LZMA decompressor found. Install xz-utils or lzma."
            fi
            ;;
        tar.lzo)
            check_dependency "lzop" "required" || return 1
            lzop -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.br)
            check_dependency "brotli" "required" || return 1
            brotli -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.Z)
            uncompress -c "$file" | tar -xf - -C "$output_dir"
            ;;
        tar.zpaq)
            check_dependency "zpaq" "required" || return 1
            local tmp
            tmp="$(make_temp_dir)"
            zpaq x "$file" -to "$tmp/" 2>/dev/null
            # Find the tar inside and extract it
            local inner_tar
            inner_tar="$(find "$tmp" -name '*.tar' -type f | head -1)"
            if [[ -n "$inner_tar" ]]; then
                tar -xf "$inner_tar" -C "$output_dir"
            else
                msg_warn "No tar found inside zpaq, copying extracted files."
                cp -r "$tmp"/* "$output_dir/" 2>/dev/null || true
            fi
            ;;

        # --- Single-file compression ---
        gz)
            local out_name
            out_name="$(basename "$file" .gz)"
            gzip -dc "$file" > "$output_dir/$out_name"
            ;;
        bz2)
            local out_name
            out_name="$(basename "$file" .bz2)"
            bzip2 -dc "$file" > "$output_dir/$out_name"
            ;;
        xz)
            local out_name
            out_name="$(basename "$file" .xz)"
            xz -dc "$file" > "$output_dir/$out_name"
            ;;
        zst)
            check_dependency "zstd" "required" || return 1
            local out_name
            out_name="$(basename "$file" .zst)"
            zstd -dc "$file" > "$output_dir/$out_name"
            ;;
        lz4)
            check_dependency "lz4" "required" || return 1
            local out_name
            out_name="$(basename "$file" .lz4)"
            lz4 -dc "$file" > "$output_dir/$out_name"
            ;;
        lzma)
            local out_name
            out_name="$(basename "$file" .lzma)"
            if has_cmd lzma; then
                lzma -dc "$file" > "$output_dir/$out_name"
            elif has_cmd xz; then
                xz --format=lzma -dc "$file" > "$output_dir/$out_name"
            fi
            ;;
        lzip)
            check_dependency "lzip" "required" || return 1
            local out_name
            out_name="$(basename "$file" | sed 's/\.lz\(ip\)\?$//')"
            lzip -dc "$file" > "$output_dir/$out_name"
            ;;
        lzo)
            check_dependency "lzop" "required" || return 1
            local out_name
            out_name="$(basename "$file" .lzo)"
            lzop -dc "$file" > "$output_dir/$out_name"
            ;;
        Z)
            local out_name
            out_name="$(basename "$file" .Z)"
            uncompress -c "$file" > "$output_dir/$out_name"
            ;;
        brotli)
            check_dependency "brotli" "required" || return 1
            local out_name
            out_name="$(basename "$file" .br)"
            brotli -dc "$file" > "$output_dir/$out_name"
            ;;

        # --- Container/archive formats ---
        zip)
            if [[ -n "$password" ]]; then
                if has_cmd 7z; then
                    7z x -o"$output_dir" -p"$password" -y "$file"
                elif has_cmd unzip; then
                    unzip -P "$password" -o "$file" -d "$output_dir"
                fi
            else
                if has_cmd unzip; then
                    unzip -o "$file" -d "$output_dir"
                elif has_cmd 7z; then
                    7z x -o"$output_dir" -y "$file"
                fi
            fi
            ;;
        7z|7z-generic)
            check_dependency "7z" "required" || return 1
            if [[ -n "$password" ]]; then
                7z x -o"$output_dir" -p"$password" -y "$file"
            else
                7z x -o"$output_dir" -y "$file"
            fi
            ;;
        rar|rar4|rar5)
            if has_cmd unrar; then
                if [[ -n "$password" ]]; then
                    unrar x -p"$password" -o+ -y "$file" "$output_dir/"
                else
                    unrar x -o+ -y "$file" "$output_dir/"
                fi
            elif has_cmd 7z; then
                if [[ -n "$password" ]]; then
                    7z x -o"$output_dir" -p"$password" -y "$file"
                else
                    7z x -o"$output_dir" -y "$file"
                fi
            else
                msg_fatal "No RAR extractor found. Install: $(get_install_cmd unrar)"
            fi
            ;;
        arj)
            if has_cmd arj; then
                arj x "$file" "$output_dir/" -y
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_fatal "No ARJ extractor found. Install: $(get_install_cmd arj)"
            fi
            ;;
        ace)
            if has_cmd unace; then
                (cd "$output_dir" && unace x "$file")
            else
                msg_fatal "No ACE extractor found. Install: $(get_install_cmd unace)"
            fi
            ;;
        cab)
            if has_cmd cabextract; then
                cabextract -d "$output_dir" "$file"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_fatal "No CAB extractor found. Install: $(get_install_cmd cabextract)"
            fi
            ;;
        rpm)
            if has_cmd rpm2cpio && has_cmd cpio; then
                (cd "$output_dir" && rpm2cpio "$file" | cpio -idmv 2>/dev/null)
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_fatal "Missing rpm2cpio/cpio. Install: $(get_install_cmd rpm2cpio)"
            fi
            ;;
        deb)
            if has_cmd dpkg-deb; then
                dpkg-deb -x "$file" "$output_dir"
            elif has_cmd ar; then
                local tmp
                tmp="$(make_temp_dir)"
                (cd "$tmp" && ar x "$file")
                # Extract data.tar.* from the deb
                local data_tar
                data_tar="$(find "$tmp" -name 'data.tar.*' | head -1)"
                if [[ -n "$data_tar" ]]; then
                    tar -xf "$data_tar" -C "$output_dir"
                fi
                # Also extract control info
                local ctrl_tar
                ctrl_tar="$(find "$tmp" -name 'control.tar.*' | head -1)"
                if [[ -n "$ctrl_tar" ]]; then
                    mkdir -p "$output_dir/DEBIAN"
                    tar -xf "$ctrl_tar" -C "$output_dir/DEBIAN"
                fi
            else
                msg_fatal "No DEB extractor found. Install: $(get_install_cmd ar)"
            fi
            ;;
        iso)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd bsdtar; then
                bsdtar -xf "$file" -C "$output_dir"
            elif has_cmd isoinfo; then
                msg_info "Using isoinfo for extraction (limited)..."
                local files
                files="$(isoinfo -lR -i "$file" 2>/dev/null | grep -E '^\s' | awk '{print $NF}')"
                while IFS= read -r f; do
                    local dir
                    dir="$(dirname "$f")"
                    mkdir -p "$output_dir/$dir"
                    isoinfo -R -x "$f" -i "$file" > "$output_dir/$f" 2>/dev/null
                done <<< "$files"
            else
                msg_fatal "No ISO extractor found. Install: $(get_install_cmd 7z)"
            fi
            ;;
        img|bin|nrg|mdf)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_error "Format '$fmt' requires 7z for extraction."
                msg_info "Install: $(get_install_cmd 7z)"
                return 1
            fi
            ;;
        vhd|vmdk)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd qemu-img; then
                msg_info "Converting with qemu-img..."
                local raw_file="${output_dir}/$(basename "$file").raw"
                qemu-img convert -O raw "$file" "$raw_file"
                msg_ok "Converted to raw: $raw_file"
            else
                msg_error "Format '$fmt' requires 7z or qemu-img."
                return 1
            fi
            ;;
        dmg)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd dmg2img; then
                local img_file="${output_dir}/$(basename "$file" .dmg).img"
                dmg2img "$file" "$img_file"
                msg_ok "Converted to IMG: $img_file"
            else
                msg_error "DMG extraction requires 7z or dmg2img."
                msg_info "Install: $(get_install_cmd 7z) OR $(get_install_cmd dmg2img)"
                return 1
            fi
            ;;
        cpio)
            (cd "$output_dir" && cpio -idmv < "$file" 2>/dev/null)
            ;;
        shar)
            msg_warn "SHAR archives contain shell scripts. Review before running."
            msg_info "To extract: (cd '$output_dir' && sh '$file')"
            msg_info "To review first: less '$file'"
            return 0
            ;;
        ar)
            (cd "$output_dir" && ar x "$file")
            ;;
        msi|msu|msp)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_fatal "MSI/MSU/MSP extraction requires 7z. Install: $(get_install_cmd 7z)"
            fi
            ;;
        jar|war|ear)
            if has_cmd jar; then
                (cd "$output_dir" && jar xf "$file")
            elif has_cmd unzip; then
                unzip -o "$file" -d "$output_dir"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            fi
            ;;
        apk)
            # Could be Android APK (zip-based) or Alpine APK (tar.gz-based)
            local magic_type
            magic_type="$(detect_by_magic "$file")"
            if [[ "$magic_type" == "gzip" ]]; then
                # Alpine APK
                tar -xzf "$file" -C "$output_dir"
            else
                # Android APK
                if has_cmd unzip; then
                    unzip -o "$file" -d "$output_dir"
                elif has_cmd 7z; then
                    7z x -o"$output_dir" -y "$file"
                fi
            fi
            ;;
        ipa)
            if has_cmd unzip; then
                unzip -o "$file" -d "$output_dir"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            fi
            ;;
        xpi)
            if has_cmd unzip; then
                unzip -o "$file" -d "$output_dir"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            fi
            ;;
        squashfs)
            if has_cmd unsquashfs; then
                unsquashfs -d "$output_dir/squashfs-root" -f "$file"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_fatal "SquashFS extraction requires unsquashfs. Install: $(get_install_cmd unsquashfs)"
            fi
            ;;
        cramfs)
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            else
                msg_error "CramFS extraction requires 7z or mounting."
                msg_info "Manual mount: sudo mount -t cramfs -o loop '$file' /mnt/cramfs"
                return 1
            fi
            ;;
        dar)
            if has_cmd dar; then
                dar -x "$file" -R "$output_dir" -O
            else
                msg_fatal "DAR extraction requires dar. Install: $(get_install_cmd dar)"
            fi
            ;;
        zpaq)
            if has_cmd zpaq; then
                zpaq x "$file" -to "$output_dir/"
            else
                msg_fatal "ZPAQ extraction requires zpaq. Install: $(get_install_cmd zpaq)"
            fi
            ;;
        exe)
            # Could be self-extracting archive, NSIS installer, etc.
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd cabextract; then
                cabextract -d "$output_dir" "$file" 2>/dev/null
            else
                msg_error "EXE extraction requires 7z. Install: $(get_install_cmd 7z)"
                return 1
            fi
            ;;
        appimage)
            chmod +x "$file" 2>/dev/null || true
            if "$file" --appimage-extract 2>/dev/null; then
                if [[ -d "squashfs-root" ]]; then
                    mv squashfs-root "$output_dir/" 2>/dev/null || \
                    cp -r squashfs-root/* "$output_dir/" 2>/dev/null
                    rm -rf squashfs-root 2>/dev/null
                fi
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd unsquashfs; then
                unsquashfs -d "$output_dir/squashfs-root" -f "$file"
            fi
            ;;
        snap)
            if has_cmd unsquashfs; then
                unsquashfs -d "$output_dir/snap-contents" -f "$file"
            elif has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            fi
            ;;
        pkg)
            # macOS .pkg or Solaris
            if has_cmd 7z; then
                7z x -o"$output_dir" -y "$file"
            elif has_cmd xar; then
                (cd "$output_dir" && xar -xf "$file")
            fi
            ;;
        pkg.tar.zst)
            check_dependency "zstd" "required" || return 1
            zstd -dc "$file" | tar -xf - -C "$output_dir"
            ;;
        pkg.tar.xz)
            tar -xJf "$file" -C "$output_dir"
            ;;
        pkg.tar.gz)
            tar -xzf "$file" -C "$output_dir"
            ;;
        flatpak|flatpakref)
            msg_info "Flatpak files are metadata/refs, not archives."
            msg_info "Install with: flatpak install '$file'"
            return 0
            ;;
        sbx)
            msg_info "SBX (SeqBox) files require sbxdec to decode."
            msg_info "Get it from: https://github.com/MarcoPon/SeqBox"
            if has_cmd sbxdec; then
                sbxdec "$file" -o "$output_dir/"
            fi
            ;;

        *)
            # Universal fallback chain
            msg_warn "Format '$fmt' not directly supported. Trying fallback chain..."

            if has_cmd 7z && 7z x -o"$output_dir" -y "$file" 2>/dev/null; then
                msg_ok "7z fallback extraction succeeded."
            elif has_cmd bsdtar && bsdtar -xf "$file" -C "$output_dir" 2>/dev/null; then
                msg_ok "bsdtar fallback extraction succeeded."
            elif has_cmd file; then
                local ftype
                ftype="$(file --brief "$file")"
                msg_error "Unrecognized format. file(1) says: $ftype"
                msg_info "Try: 7z x '$file' OR binwalk -e '$file'"
                return 1
            else
                msg_error "Cannot extract: unknown format and no fallback tools available."
                return 1
            fi
            ;;
    esac

    local exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        msg_ok "Extraction complete: $output_dir"
        # Generate checksum of extracted contents
        if [[ "${UAM_CHECKSUM:-0}" == "1" ]]; then
            msg_info "Generating checksums..."
            find "$output_dir" -type f -exec sha256sum {} \; 2>/dev/null | tee "$output_dir/.uam_checksums.txt"
        fi
    else
        msg_error "Extraction failed with exit code: $exit_code"
    fi

    return "$exit_code"
}

# --- Archive Creation Engine ---

create_archive() {
    local format="$1"
    local output="$2"
    shift 2
    local inputs=("$@")

    # Parse creation options from environment
    local compression_level="${UAM_COMPRESSION_LEVEL:-}"
    local password="${UAM_CREATE_PASSWORD:-}"
    local exclude_pattern="${UAM_EXCLUDE:-}"
    local split_size="${UAM_SPLIT_SIZE:-}"
    local threads="${UAM_THREADS:-1}"

    # Validate inputs exist
    for input in "${inputs[@]}"; do
        if [[ ! -e "$input" ]]; then
            msg_error "Input does not exist: $input"
            return 1
        fi
    done

    # Check output directory is writable
    local out_dir
    out_dir="$(dirname "$output")"
    if [[ ! -w "$out_dir" ]]; then
        msg_error "Output directory not writable: $out_dir"
        return 1
    fi

    # Warn if output already exists
    if [[ -e "$output" ]]; then
        msg_warn "Output file already exists: $output"
        msg_warn "It will be overwritten."
    fi

    msg_info "Creating archive: $output (format: $format)"
    log_msg "Create: $output (format: $format, inputs: ${inputs[*]})"

    local exclude_opts=()
    if [[ -n "$exclude_pattern" ]]; then
        IFS=',' read -ra patterns <<< "$exclude_pattern"
        for pat in "${patterns[@]}"; do
            exclude_opts+=("--exclude=$pat")
        done
    fi

    case "$format" in
        tar)
            tar -cf "$output" "${exclude_opts[@]}" "${inputs[@]}"
            ;;
        tar.gz|tgz)
            if [[ "$threads" -gt 1 ]] && has_cmd pigz; then
                tar -cf - "${exclude_opts[@]}" "${inputs[@]}" | \
                    pigz -p "$threads" ${compression_level:+-$compression_level} > "$output"
            else
                tar -czf "$output" ${compression_level:+--gzip} "${exclude_opts[@]}" "${inputs[@]}"
            fi
            ;;
        tar.bz2|tbz2)
            if [[ "$threads" -gt 1 ]] && has_cmd pbzip2; then
                tar -cf - "${exclude_opts[@]}" "${inputs[@]}" | \
                    pbzip2 -p"$threads" ${compression_level:+-$compression_level} > "$output"
            else
                tar -cjf "$output" "${exclude_opts[@]}" "${inputs[@]}"
            fi
            ;;
        tar.xz|txz)
            if [[ "$threads" -gt 1 ]] && has_cmd pixz; then
                tar -cf - "${exclude_opts[@]}" "${inputs[@]}" | \
                    pixz -p "$threads" ${compression_level:+-$compression_level} > "$output"
            else
                local xz_opts=""
                [[ -n "$compression_level" ]] && xz_opts="-${compression_level}"
                XZ_OPT="$xz_opts" tar -cJf "$output" "${exclude_opts[@]}" "${inputs[@]}"
            fi
            ;;
        tar.zst|tzst)
            check_dependency "zstd" "required" || return 1
            local zst_opts=()
            [[ -n "$compression_level" ]] && zst_opts+=("-$compression_level")
            [[ "$threads" -gt 1 ]] && zst_opts+=("-T$threads")
            tar -cf - "${exclude_opts[@]}" "${inputs[@]}" | zstd "${zst_opts[@]}" -o "$output"
            ;;
        tar.lz4)
            check_dependency "lz4" "required" || return 1
            local lz4_opts=()
            [[ -n "$compression_level" ]] && lz4_opts+=("-$compression_level")
            tar -cf - "${exclude_opts[@]}" "${inputs[@]}" | lz4 "${lz4_opts[@]}" - "$output"
            ;;
        zip)
            if has_cmd zip; then
                local zip_opts=(-r)
                [[ -n "$compression_level" ]] && zip_opts+=("-$compression_level")
                [[ -n "$password" ]] && zip_opts+=(-P "$password")
                if [[ -n "$split_size" ]]; then
                    zip_opts+=(-s "$split_size")
                fi
                if [[ -n "$exclude_pattern" ]]; then
                    IFS=',' read -ra patterns <<< "$exclude_pattern"
                    for pat in "${patterns[@]}"; do
                        zip_opts+=(-x "$pat")
                    done
                fi
                zip "${zip_opts[@]}" "$output" "${inputs[@]}"
            elif has_cmd 7z; then
                local sz_opts=(-tzip)
                [[ -n "$compression_level" ]] && sz_opts+=("-mx=$compression_level")
                [[ -n "$password" ]] && sz_opts+=("-p$password")
                7z a "${sz_opts[@]}" "$output" "${inputs[@]}"
            fi
            ;;
        7z)
            check_dependency "7z" "required" || return 1
            local sz_opts=()
            [[ -n "$compression_level" ]] && sz_opts+=("-mx=$compression_level")
            [[ -n "$password" ]] && sz_opts+=("-p$password" "-mhe=on")
            if [[ -n "$split_size" ]]; then
                sz_opts+=("-v${split_size}")
            fi
            if [[ "$threads" -gt 1 ]]; then
                sz_opts+=("-mmt=$threads")
            fi
            7z a "${sz_opts[@]}" "$output" "${inputs[@]}"
            ;;
        gz)
            # Single file only
            if [[ ${#inputs[@]} -ne 1 || -d "${inputs[0]}" ]]; then
                msg_error "gz format only supports a single file (not directories)."
                msg_info "Use tar.gz for multiple files or directories."
                return 1
            fi
            local gz_opts=()
            [[ -n "$compression_level" ]] && gz_opts+=("-$compression_level")
            gzip "${gz_opts[@]}" -c "${inputs[0]}" > "$output"
            ;;
        cpio)
            find "${inputs[@]}" -print 2>/dev/null | cpio -ov > "$output" 2>/dev/null
            ;;
        ar)
            ar rcs "$output" "${inputs[@]}"
            ;;
        *)
            msg_error "Archive creation not supported for format: $format"
            msg_info "Supported creation formats: tar, tar.gz, tar.bz2, tar.xz, tar.zst, tar.lz4, zip, 7z, gz, cpio, ar"
            return 1
            ;;
    esac

    local exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        msg_ok "Archive created: $output ($(human_size "$(get_file_size "$output")"))"
        if [[ "${UAM_CHECKSUM:-0}" == "1" ]]; then
            generate_checksum "$output"
        fi
    else
        msg_error "Archive creation failed."
    fi

    return "$exit_code"
}

# --- Batch Processing ---

batch_extract() {
    local output_dir="${1:-.}"
    shift
    local files=("$@")
    local success=0
    local fail=0
    local total=${#files[@]}

    msg_info "Batch extraction: $total files -> $output_dir"

    for file in "${files[@]}"; do
        if [[ ! -f "$file" ]]; then
            msg_warn "Skipping (not a file): $file"
            ((fail++))
            continue
        fi

        local fmt
        fmt="$(detect_format "$file")"
        local file_out_dir="$output_dir/$(basename "$file" | sed 's/\.[^.]*$//')"
        mkdir -p "$file_out_dir"

        if extract_archive "$file" "$fmt" "$file_out_dir" "" 0; then
            ((success++))
        else
            ((fail++))
        fi
    done

    echo ""
    msg_info "Batch results: $success/$total succeeded, $fail/$total failed."
}

# --- Password Cracking Guidance Generator ---

generate_crack_guide() {
    local file="$1"
    local fmt="$2"

    local abs_path
    abs_path="$(realpath "$file" 2>/dev/null || echo "$file")"
    local base_name
    base_name="$(basename "$file")"

    echo "================================================================"
    echo " Password Cracking Guide"
    echo " Target: $base_name"
    echo " Format: $fmt"
    echo "================================================================"
    echo ""

    # ---- Tool Installation ----
    echo "--- Step 1: Install Required Tools ---"
    echo ""
    echo "# Core cracking tools"
    echo "$(get_install_cmd john)"
    echo "$(get_install_cmd hashcat)"
    echo ""

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            echo "# ZIP-specific tools"
            echo "$(get_install_cmd fcrackzip)"
            echo ""
            ;;
        rar|rar4|rar5)
            echo "# RAR-specific tools"
            echo "$(get_install_cmd rarcrack)"
            echo ""
            ;;
    esac

    echo "# Build john from source (latest features):"
    echo "git clone https://github.com/openwall/john.git /opt/john"
    echo "cd /opt/john/src && ./configure && make -s clean && make -sj\$(nproc)"
    echo "export PATH=/opt/john/run:\$PATH"
    echo ""

    # ---- Wordlists ----
    echo "--- Step 2: Prepare Wordlists ---"
    echo ""
    echo "# Download rockyou (most common first-choice wordlist)"
    echo "# Kali Linux default location: /usr/share/wordlists/rockyou.txt"
    echo "wget -O /tmp/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz"
    echo "gunzip /tmp/rockyou.txt.gz"
    echo ""
    echo "# Clone SecLists (comprehensive collection)"
    echo "git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists"
    echo ""
    echo "# Key wordlists from SecLists:"
    echo "#   /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    echo "#   /opt/SecLists/Passwords/Leaked-Databases/rockyou-75.txt"
    echo "#   /opt/SecLists/Passwords/darkweb2017-top10000.txt"
    echo ""
    echo "# Custom wordlist from target info (CeWL):"
    echo "# cewl -d 3 -m 5 https://target-website.com -w /tmp/custom_wordlist.txt"
    echo ""
    echo "# Combine and deduplicate wordlists:"
    echo "cat /tmp/rockyou.txt /opt/SecLists/Passwords/darkweb2017-top10000.txt | sort -u > /tmp/combined.txt"
    echo ""

    # ---- Hash Extraction ----
    echo "--- Step 3: Extract Hash ---"
    echo ""

    case "$fmt" in
        zip|jar|war|ear|xpi|apk)
            echo "# Extract ZIP hash for John the Ripper"
            echo "zip2john '$abs_path' > /tmp/zip_hash.txt"
            echo ""
            echo "# For PKZIP (legacy) encryption - check encryption type:"
            echo "7z l -slt '$abs_path' | grep -i method"
            echo "# If Method shows 'ZipCrypto' -> weak, fast to crack"
            echo "# If Method shows 'AES-256' -> strong, slower to crack"
            echo ""
            echo "# Extract hash for Hashcat"
            echo "zip2john '$abs_path' | cut -d: -f2 > /tmp/zip_hash_hc.txt"
            echo ""
            echo "# Hashcat mode reference:"
            echo "#   13600 = ZIP with AES encryption (WinZip)"
            echo "#   17200 = PKZIP (Compressed)"
            echo "#   17210 = PKZIP (Uncompressed)"
            echo "#   17220 = PKZIP (Compressed Multi-File)"
            echo "#   17225 = PKZIP (Mixed Multi-File)"
            echo "#   17230 = PKZIP (Compressed Multi-File Checksum-Only)"
            ;;
        rar|rar4|rar5)
            echo "# Extract RAR hash for John the Ripper"
            echo "rar2john '$abs_path' > /tmp/rar_hash.txt"
            echo ""
            echo "# Determine RAR version:"
            echo "file '$abs_path'"
            echo "# RAR4 uses AES-128, RAR5 uses AES-256"
            echo ""
            echo "# Extract hash for Hashcat"
            echo "rar2john '$abs_path' | cut -d: -f2 > /tmp/rar_hash_hc.txt"
            echo ""
            echo "# Hashcat mode reference:"
            echo "#   12500 = RAR3-hp (RAR3 with header protection)"
            echo "#   13000 = RAR5"
            echo "#   23700 = RAR3-p (RAR3 without header protection)"
            ;;
        7z|7z-generic)
            echo "# Extract 7z hash for John the Ripper"
            echo "7z2john '$abs_path' > /tmp/7z_hash.txt"
            echo ""
            echo "# Check if headers are encrypted (harder to crack):"
            echo "7z l -slt '$abs_path' 2>&1 | grep -i 'encrypted'"
            echo "# Encrypted headers = no file listing visible without password"
            echo ""
            echo "# Extract hash for Hashcat"
            echo "7z2john '$abs_path' | cut -d: -f2 > /tmp/7z_hash_hc.txt"
            echo ""
            echo "# Hashcat mode: 11600 = 7-Zip"
            ;;
        *)
            echo "# Generic hash extraction (try these in order):"
            echo "zip2john '$abs_path' > /tmp/hash.txt 2>/dev/null"
            echo "rar2john '$abs_path' > /tmp/hash.txt 2>/dev/null"
            echo "7z2john '$abs_path' > /tmp/hash.txt 2>/dev/null"
            echo ""
            echo "# Or use John's auto-detection:"
            echo "# john --list=formats | grep -i <format>"
            ;;
    esac
    echo ""

    # ---- Attack Methods ----
    echo "--- Step 4: Attack Methods ---"
    echo ""

    # Method 1: Dictionary Attack
    echo "## Method 1: Dictionary Attack (fastest, try first)"
    echo ""
    case "$fmt" in
        zip*)
            echo "# John the Ripper - dictionary attack"
            echo "john --wordlist=/tmp/rockyou.txt /tmp/zip_hash.txt"
            echo ""
            echo "# Hashcat - dictionary attack (GPU accelerated)"
            echo "hashcat -m 17200 -a 0 /tmp/zip_hash_hc.txt /tmp/rockyou.txt"
            echo ""
            echo "# fcrackzip - fast ZIP-specific cracker (ZipCrypto only)"
            echo "fcrackzip -u -D -p /tmp/rockyou.txt '$abs_path'"
            ;;
        rar*)
            echo "# John the Ripper - dictionary attack"
            echo "john --wordlist=/tmp/rockyou.txt /tmp/rar_hash.txt"
            echo ""
            echo "# Hashcat - dictionary attack (GPU accelerated)"
            echo "hashcat -m 13000 -a 0 /tmp/rar_hash_hc.txt /tmp/rockyou.txt"
            echo ""
            echo "# rarcrack - RAR-specific brute force"
            echo "rarcrack '$abs_path' --type rar --threads \$(nproc)"
            ;;
        7z*)
            echo "# John the Ripper - dictionary attack"
            echo "john --wordlist=/tmp/rockyou.txt /tmp/7z_hash.txt"
            echo ""
            echo "# Hashcat - dictionary attack (GPU accelerated)"
            echo "hashcat -m 11600 -a 0 /tmp/7z_hash_hc.txt /tmp/rockyou.txt"
            ;;
    esac
    echo ""

    # Method 2: Rule-Based Attack
    echo "## Method 2: Rule-Based Attack (dictionary + mutations)"
    echo ""
    echo "# John with rules (adds common variations: capitalize, add numbers, etc.)"
    echo "john --wordlist=/tmp/rockyou.txt --rules=All /tmp/*_hash.txt"
    echo ""
    echo "# Hashcat with rules"
    echo "hashcat -m <MODE> -a 0 /tmp/*_hash_hc.txt /tmp/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
    echo ""
    echo "# Popular hashcat rule files:"
    echo "#   /usr/share/hashcat/rules/best64.rule          # Fast, good coverage"
    echo "#   /usr/share/hashcat/rules/rockyou-30000.rule   # Extensive"
    echo "#   /usr/share/hashcat/rules/d3ad0ne.rule         # Classic"
    echo "#   /usr/share/hashcat/rules/dive.rule            # Very thorough"
    echo "#   /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule  # Download separately"
    echo ""
    echo "# Download OneRuleToRuleThemAll:"
    echo "wget -O /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \\"
    echo "  https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule"
    echo ""

    # Method 3: Mask Attack
    echo "## Method 3: Mask Attack (targeted patterns)"
    echo ""
    echo "# Common password patterns:"
    echo "# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special, ?a = all"
    echo ""
    echo "# 4-8 digit PIN"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?d?d?d?d'"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?d?d?d?d?d?d'"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?d?d?d?d?d?d?d?d'"
    echo ""
    echo "# Word + digits (e.g., Password123)"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?u?l?l?l?l?l?l?d?d?d'"
    echo ""
    echo "# Common patterns"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?u?l?l?l?l?l?d?d?s'    # Word99!"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt '?l?l?l?l?l?l?l?l'      # 8 lowercase"
    echo ""
    echo "# Incremental mask (1-8 chars)"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt --increment --increment-min=1 --increment-max=8 '?a?a?a?a?a?a?a?a'"
    echo ""

    # Method 4: Combinator Attack
    echo "## Method 4: Combinator Attack (combine two wordlists)"
    echo ""
    echo "# Combine words from two lists (word1+word2)"
    echo "hashcat -m <MODE> -a 1 /tmp/*_hash_hc.txt /tmp/wordlist1.txt /tmp/wordlist2.txt"
    echo ""
    echo "# Create number/year suffix list"
    echo "seq 0 9999 | while read n; do printf '%04d\n' \$n; done > /tmp/numbers.txt"
    echo "seq 1950 2030 > /tmp/years.txt"
    echo ""

    # Method 5: Hybrid Attack
    echo "## Method 5: Hybrid Attack (wordlist + mask)"
    echo ""
    echo "# Wordlist + digits appended"
    echo "hashcat -m <MODE> -a 6 /tmp/*_hash_hc.txt /tmp/rockyou.txt '?d?d?d'"
    echo ""
    echo "# Digits prepended + wordlist"
    echo "hashcat -m <MODE> -a 7 /tmp/*_hash_hc.txt '?d?d?d' /tmp/rockyou.txt"
    echo ""

    # Method 6: Pure Brute Force
    echo "## Method 6: Pure Brute Force (last resort, very slow)"
    echo ""
    echo "# All printable ASCII, incrementing length"
    echo "hashcat -m <MODE> -a 3 /tmp/*_hash_hc.txt --increment --increment-min=1 --increment-max=12 '?a?a?a?a?a?a?a?a?a?a?a?a'"
    echo ""
    echo "# John brute force (incremental mode)"
    echo "john --incremental /tmp/*_hash.txt"
    echo ""

    case "$fmt" in
        zip*)
            echo "## Method 7: fcrackzip Brute Force (ZIP only)"
            echo ""
            echo "# Brute force with charset"
            echo "fcrackzip -b -c 'aA1!' -l 1-8 -u '$abs_path'"
            echo ""
            echo "# Options:"
            echo "#   -b    = brute force"
            echo "#   -c    = charset (a=lowercase, A=uppercase, 1=digits, !=special)"
            echo "#   -l    = length range"
            echo "#   -u    = unzip test (validates password, slower but no false positives)"
            echo ""
            echo "## Known-Plaintext Attack (bkcrack - for ZipCrypto)"
            echo ""
            echo "# If you know any file inside the ZIP (e.g., a common file):"
            echo "# 1. Install bkcrack"
            echo "git clone https://github.com/kimci86/bkcrack.git && cd bkcrack"
            echo "cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install"
            echo "cmake --build build --config Release --target install"
            echo ""
            echo "# 2. Create a plaintext file matching a known file in the archive"
            echo "# 3. Run the attack"
            echo "./build/src/bkcrack -C '$abs_path' -c 'known_file.txt' -p /tmp/known_plaintext.txt"
            echo ""
            echo "# 4. Once keys are found, extract without password"
            echo "./build/src/bkcrack -C '$abs_path' -k <key0> <key1> <key2> -U /tmp/unlocked.zip ''"
            echo "unzip /tmp/unlocked.zip"
            echo ""
            ;;
    esac

    # ---- Session Management ----
    echo "--- Step 5: Session Management ---"
    echo ""
    echo "# Save/restore Hashcat sessions (auto-saves on interrupt)"
    echo "hashcat -m <MODE> -a 0 /tmp/*_hash_hc.txt /tmp/rockyou.txt --session=crack1"
    echo ""
    echo "# Resume interrupted session"
    echo "hashcat --session=crack1 --restore"
    echo ""
    echo "# John session management"
    echo "john --session=crack1 --wordlist=/tmp/rockyou.txt /tmp/*_hash.txt"
    echo ""
    echo "# Resume John session"
    echo "john --restore=crack1"
    echo ""
    echo "# Show cracked passwords"
    echo "john --show /tmp/*_hash.txt"
    echo "hashcat -m <MODE> /tmp/*_hash_hc.txt --show"
    echo ""

    # ---- Performance Tuning ----
    echo "--- Step 6: Performance Tuning ---"
    echo ""
    echo "# Hashcat GPU optimization"
    echo "hashcat -m <MODE> -a 0 /tmp/*_hash_hc.txt /tmp/rockyou.txt \\"
    echo "  -w 3 \\                    # Workload profile (1=low, 2=default, 3=high, 4=nightmare)"
    echo "  -O \\                      # Optimized kernels (limits password length to 32)"
    echo "  --force \\                 # Ignore warnings"
    echo "  -D 1,2 \\                  # Device types (1=CPU, 2=GPU)"
    echo "  --gpu-temp-abort=90 \\     # Abort if GPU hits 90C"
    echo "  --gpu-temp-retain=80       # Try to keep GPU at 80C"
    echo ""
    echo "# Check GPU status"
    echo "hashcat -I                    # Show detected compute devices"
    echo "hashcat -b -m <MODE>          # Benchmark specific hash mode"
    echo ""
    echo "# John CPU optimization"
    echo "john --fork=\$(nproc) --wordlist=/tmp/rockyou.txt /tmp/*_hash.txt"
    echo ""
    echo "# Distributed cracking with Hashtopolis:"
    echo "# https://github.com/hashtopolis/server"
    echo ""

    # ---- Time Estimates ----
    echo "--- Step 7: Estimated Crack Times ---"
    echo ""
    echo "# These are rough estimates based on a mid-range GPU (RTX 3070):"
    echo "#"
    echo "# Password Type          | ZIP (PKZIP) | ZIP (AES) | RAR5    | 7z"
    echo "# -----------------------|-------------|-----------|---------|--------"
    echo "# 4-digit PIN            | < 1 sec     | < 1 sec   | < 1 sec | seconds"
    echo "# 6-char lowercase       | seconds     | minutes   | minutes | minutes"
    echo "# 8-char mixed           | minutes     | hours     | hours   | hours"
    echo "# 8-char + special       | hours       | days      | days    | days"
    echo "# 10-char complex        | days        | weeks     | weeks   | weeks"
    echo "# 12-char complex        | weeks       | months    | months  | months"
    echo "#"
    echo "# PKZIP (ZipCrypto) is MUCH faster to crack than AES-based encryption."
    echo "# Use 'bkcrack' for known-plaintext attacks on ZipCrypto (instant if you have plaintext)."
    echo ""

    # ---- Alternative Approaches ----
    echo "--- Step 8: Alternative Approaches ---"
    echo ""
    echo "# 1. Try common passwords manually"
    echo "for pw in password 123456 admin letmein welcome monkey dragon; do"
    case "$fmt" in
        zip*)
            echo "    unzip -P \"\$pw\" -tq '$abs_path' 2>/dev/null && echo \"PASSWORD: \$pw\" && break"
            ;;
        rar*)
            echo "    unrar t -p\"\$pw\" '$abs_path' 2>/dev/null && echo \"PASSWORD: \$pw\" && break"
            ;;
        7z*)
            echo "    7z t -p\"\$pw\" '$abs_path' 2>/dev/null && echo \"PASSWORD: \$pw\" && break"
            ;;
    esac
    echo "done"
    echo ""
    echo "# 2. Generate targeted wordlist from OSINT"
    echo "# Use username, company name, dates, common words from target"
    echo "# Tool: CUPP (Common User Password Profiler)"
    echo "git clone https://github.com/Mebus/cupp.git && cd cupp"
    echo "python3 cupp.py -i  # Interactive mode, enter target info"
    echo ""
    echo "# 3. Check if hash exists in online databases"
    echo "# https://hashes.org"
    echo "# https://crackstation.net"
    echo ""
    echo "# 4. Use cloud GPU instances for faster cracking"
    echo "# AWS p3.2xlarge (V100) or Google Cloud with T4/A100"
    echo "# Penguin's hashcat benchmark: https://github.com/siseci/hashcat-benchmark-comparison"
    echo ""
    echo "================================================================"
}

# --- Help / Usage ---

show_help() {
    cat << 'HELPEOF'
Universal Archive Manager (UAM) v2.0.0

USAGE:
    uam [OPTIONS] [ARGUMENTS]

OPERATIONS:
    -x, --extract <archive> [output_dir]    Extract archive to directory
    -c, --create <fmt> <output> <inputs..>  Create archive in specified format
    -l, --list <archive>                    List archive contents
    -t, --test <archive>                    Test archive integrity
    -p, --password-crack <archive>          Generate password cracking guide
    -i, --info <archive>                    Forensic analysis of archive
    -r, --repair <archive> [output_dir]     Attempt to repair corrupted archive
    -b, --batch <output_dir> <archives..>   Batch extract multiple archives
    --deps                                  Show/install dependency status
    -h, --help                              Show this help
    -v, --version                           Show version

EXTRACTION EXAMPLES:
    uam -x archive.tar.gz
    uam -x archive.tar.gz /tmp/output
    uam -x archive.zip /tmp/output
    uam -x encrypted.7z /tmp/output          # Prompts for password
    UAM_PASSWORD=secret uam -x enc.zip /out  # Password via env var

CREATION EXAMPLES:
    uam -c tar.gz backup.tar.gz /home/user/docs
    uam -c zip archive.zip file1.txt dir1/
    uam -c 7z archive.7z file1 file2 dir/

    # With options (via environment variables):
    UAM_COMPRESSION_LEVEL=9 uam -c tar.gz max_compressed.tar.gz ./data
    UAM_CREATE_PASSWORD=secret uam -c zip encrypted.zip ./sensitive/
    UAM_EXCLUDE="*.log,*.tmp,.git" uam -c tar.gz clean.tar.gz ./project
    UAM_SPLIT_SIZE=100m uam -c 7z split.7z ./large_dir
    UAM_THREADS=4 uam -c tar.gz fast.tar.gz ./data
    UAM_CHECKSUM=1 uam -c tar.gz verified.tar.gz ./data

BATCH EXTRACTION:
    uam -b /tmp/output *.zip *.tar.gz *.7z

INTEGRITY TESTING:
    uam -t archive.zip
    uam -t suspicious.rar

CORRUPTION REPAIR:
    uam -r corrupted.zip /tmp/repaired
    uam -r damaged.tar.gz /tmp/rescued

FORENSIC ANALYSIS:
    uam -i suspicious_archive.zip
    uam -i unknown_file

PASSWORD CRACKING GUIDE:
    uam -p encrypted.zip
    uam -p protected.rar
    uam -p locked.7z

SUPPORTED FORMATS (EXTRACTION):
    Compressed:  .gz .bz2 .xz .zst .lz4 .lzma .lz .lzip .lzo .Z .br
    Tar:         .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz
                 .tar.zst .tar.lz4 .tar.lzip .tar.lzma .tar.lzo
                 .tar.br .tar.Z .tar.zpaq
    Archives:    .zip .7z .rar .arj .ace .cab
    Packages:    .rpm .deb .pkg .msi .msu .msp .jar .war .ear
                 .apk .ipa .xpi .snap .flatpak .pkg.tar.zst
    Disk Images: .iso .img .bin .nrg .mdf .dmg .vhd .vmdk
    Special:     .cpio .shar .ar .a .squashfs .cramfs .dar .zpaq
                 .exe (self-extracting) .appimage

SUPPORTED FORMATS (CREATION):
    .tar .tar.gz .tar.bz2 .tar.xz .tar.zst .tar.lz4
    .zip .7z .gz .cpio .ar

ENVIRONMENT VARIABLES:
    UAM_PASSWORD            Password for extracting encrypted archives
    UAM_CREATE_PASSWORD     Password for creating encrypted archives
    UAM_COMPRESSION_LEVEL   Compression level (1-9, format dependent)
    UAM_THREADS             Number of threads for parallel compression
    UAM_EXCLUDE             Comma-separated exclusion patterns
    UAM_SPLIT_SIZE          Split archive size (e.g., 100m, 1g)
    UAM_CHECKSUM            Set to 1 to generate checksums
    UAM_LOG_FILE            Path to log file
    UAM_DEBUG               Set to 1 for debug output
    UAM_FORCE_UNSAFE        Set to 1 to skip path traversal checks

NOTES:
    - Format is auto-detected by extension and magic bytes
    - If extension is missing/wrong, magic bytes are used
    - Password-protected archives are detected automatically
    - Corrupted archives can be partially recovered with -r
    - Path traversal protection is enabled by default
    - All operations support SIGINT (Ctrl+C) for clean abort
HELPEOF
}

# --- Main Entry Point ---

main() {
    # No arguments
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    # Check core dependencies
    check_core_dependencies

    local action=""
    local archive=""
    local output_dir=""
    local create_format=""
    local create_output=""
    local create_inputs=()
    local batch_files=()
    local force_unsafe="${UAM_FORCE_UNSAFE:-0}"

    # Parse arguments
    case "$1" in
        -x|--extract)
            action="extract"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -x <archive> [output_dir]"
            archive="$1"
            output_dir="${2:-.}"
            ;;
        -c|--create)
            action="create"
            shift
            [[ $# -ge 3 ]] || msg_fatal "Usage: $SCRIPT_NAME -c <format> <output> <input_files...>"
            create_format="$1"
            create_output="$2"
            shift 2
            create_inputs=("$@")
            ;;
        -l|--list)
            action="list"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -l <archive>"
            archive="$1"
            ;;
        -t|--test)
            action="test"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -t <archive>"
            archive="$1"
            ;;
        -p|--password-crack)
            action="crack"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -p <archive>"
            archive="$1"
            ;;
        -i|--info)
            action="info"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -i <archive>"
            archive="$1"
            ;;
        -r|--repair)
            action="repair"
            shift
            [[ $# -ge 1 ]] || msg_fatal "Usage: $SCRIPT_NAME -r <archive> [output_dir]"
            archive="$1"
            output_dir="${2:-.}"
            ;;
        -b|--batch)
            action="batch"
            shift
            [[ $# -ge 2 ]] || msg_fatal "Usage: $SCRIPT_NAME -b <output_dir> <archives...>"
            output_dir="$1"
            shift
            batch_files=("$@")
            ;;
        --deps|--dependencies)
            install_all_dependencies
            exit 0
            ;;
        --force-unsafe)
            force_unsafe=1
            shift
            # Re-parse remaining args
            main "$@"
            return
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "Universal Archive Manager v${VERSION}"
            exit 0
            ;;
        *)
            # Smart mode: if first arg is a file, assume extract
            if [[ -f "$1" ]]; then
                action="extract"
                archive="$1"
                output_dir="${2:-.}"
            else
                msg_error "Unknown option: $1"
                echo "Run '$SCRIPT_NAME --help' for usage information."
                exit 1
            fi
            ;;
    esac

    # Validate archive file exists (for operations that need it)
    if [[ -n "$archive" ]]; then
        if [[ ! -f "$archive" ]]; then
            msg_fatal "File not found: $archive"
        fi
        if [[ ! -r "$archive" ]]; then
            msg_fatal "File not readable: $archive (permission denied)"
        fi
    fi

    # Execute action
    case "$action" in
        extract)
            local fmt
            fmt="$(detect_format "$archive")"
            if [[ "$fmt" == "unknown" ]]; then
                msg_fatal "Cannot determine archive format: $archive"
            fi
            msg_info "Detected format: $fmt"

            # Check for password protection
            local password="${UAM_PASSWORD:-}"
            if detect_password_protection "$archive" "$fmt" 2>/dev/null; then
                msg_warn "Archive is password protected."
                if [[ -z "$password" ]]; then
                    echo -n "Enter password (or Ctrl+C to abort): "
                    read -rs password
                    echo ""
                fi
            fi

            extract_archive "$archive" "$fmt" "$output_dir" "$password" "$force_unsafe"
            ;;
        create)
            create_archive "$create_format" "$create_output" "${create_inputs[@]}"
            ;;
        list)
            local fmt
            fmt="$(detect_format "$archive")"
            [[ "$fmt" == "unknown" ]] && msg_fatal "Cannot determine format: $archive"
            list_archive "$archive" "$fmt"
            ;;
        test)
            local fmt
            fmt="$(detect_format "$archive")"
            [[ "$fmt" == "unknown" ]] && msg_fatal "Cannot determine format: $archive"
            check_archive_integrity "$archive" "$fmt"
            ;;
        crack)
            local fmt
            fmt="$(detect_format "$archive")"
            [[ "$fmt" == "unknown" ]] && msg_fatal "Cannot determine format: $archive"
            generate_crack_guide "$archive" "$fmt"
            ;;
        info)
            local fmt
            fmt="$(detect_format "$archive")"
            forensic_info "$archive" "$fmt"
            ;;
        repair)
            local fmt
            fmt="$(detect_format "$archive")"
            [[ "$fmt" == "unknown" ]] && msg_fatal "Cannot determine format: $archive"
            repair_archive "$archive" "$fmt" "$output_dir"
            ;;
        batch)
            batch_extract "$output_dir" "${batch_files[@]}"
            ;;
    esac
}

main "$@"

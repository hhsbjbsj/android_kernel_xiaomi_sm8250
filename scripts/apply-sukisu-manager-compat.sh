#!/usr/bin/env bash
set -euo pipefail

# SUKISU_V412_MANAGER_SCAN_COMPAT
# Target: SukiSU-Ultra v4.1.2 (app-profile ABI v2, pre-v4.1.3 layout).
# This script intentionally does NOT apply the v2/v3 -> v4 ABI migration used
# by SukiSU v4.1.3. It only supplies the SUSFS Kconfig symbols already backed
# by this kernel tree and performs an initial manager APK scan at post-fs-data.

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

KSU_DIR="${1:-}"
[[ -n "$KSU_DIR" ]] || die "pass the SukiSU-Ultra source directory as argument 1"
KSU_DIR="$(cd "$KSU_DIR" && pwd)"

[[ -d "$KSU_DIR/.git" ]] || die "$KSU_DIR is not a Git work tree"

EXPECTED_TAG="v4.1.2"
ACTUAL_TAG="$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)"
[[ "$ACTUAL_TAG" == "$EXPECTED_TAG" ]] ||
    die "this script only supports exact tag $EXPECTED_TAG; detected ${ACTUAL_TAG:-none}"

KCONFIG="$KSU_DIR/kernel/Kconfig"
KSUD="$KSU_DIR/kernel/ksud.c"
APP_PROFILE="$KSU_DIR/kernel/app_profile.h"

for file in "$KCONFIG" "$KSUD" "$APP_PROFILE"; do
    [[ -f "$file" ]] || die "missing $file"
done

PROFILE_VER="$(awk '/^[[:space:]]*#define[[:space:]]+KSU_APP_PROFILE_VER[[:space:]]+[0-9]+/{print $3; exit}' "$APP_PROFILE")"
[[ "$PROFILE_VER" == "2" ]] ||
    die "v4.1.2 app-profile ABI v2 expected; detected ${PROFILE_VER:-unknown}"

ensure_susfs_kconfig() {
    local symbol

    if ! grep -qE '^[[:space:]]*config[[:space:]]+KSU_SUSFS[[:space:]]*$' "$KCONFIG"; then
        cat >> "$KCONFIG" <<'KCONFIG_SUSFS'

menu "KernelSU - SUSFS"
    depends on KSU

config KSU_SUSFS
    bool "Enable SUSFS support"
    default y
    help
      Build the SUSFS implementation already integrated in this kernel tree.

config KSU_SUSFS_SUS_PATH
    bool "Enable suspicious-path hiding"
    depends on KSU_SUSFS
    default y

config KSU_SUSFS_SUS_MOUNT
    bool "Enable suspicious-mount hiding"
    depends on KSU_SUSFS
    default y

config KSU_SUSFS_SUS_KSTAT
    bool "Enable suspicious-kstat spoofing"
    depends on KSU_SUSFS
    default y

config KSU_SUSFS_SPOOF_UNAME
    bool "Enable uname spoofing"
    depends on KSU_SUSFS
    default y

config KSU_SUSFS_ENABLE_LOG
    bool "Enable SUSFS kernel logging"
    depends on KSU_SUSFS
    default n

config KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
    bool "Hide KSU and SUSFS symbols from kallsyms"
    depends on KSU_SUSFS
    default n

config KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
    bool "Enable cmdline or bootconfig spoofing"
    depends on KSU_SUSFS
    default y

config KSU_SUSFS_OPEN_REDIRECT
    bool "Enable open redirect"
    depends on KSU_SUSFS
    default n

config KSU_SUSFS_SUS_MAP
    bool "Enable hiding selected mapped files"
    depends on KSU_SUSFS
    default y

endmenu
KCONFIG_SUSFS
        echo "Injected missing SUSFS Kconfig symbols into: $KCONFIG"
    else
        echo "SUSFS Kconfig symbols are already present."
    fi

    for symbol in \
        KSU_SUSFS \
        KSU_SUSFS_SUS_PATH \
        KSU_SUSFS_SUS_MOUNT \
        KSU_SUSFS_SUS_KSTAT \
        KSU_SUSFS_SPOOF_UNAME \
        KSU_SUSFS_ENABLE_LOG \
        KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS \
        KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG \
        KSU_SUSFS_OPEN_REDIRECT \
        KSU_SUSFS_SUS_MAP; do
        grep -qE "^[[:space:]]*config[[:space:]]+${symbol}[[:space:]]*$" "$KCONFIG" ||
            die "failed to provide Kconfig symbol $symbol"
    done
}

patch_initial_manager_scan() {
    if grep -q 'SUKISU_V412_MANAGER_SCAN_COMPAT' "$KSUD"; then
        echo "Initial manager scan compatibility is already applied."
        return 0
    fi

    python3 - "$KSUD" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = """    ksu_load_allow_list();
    ksu_observer_init();
    // sanity check, this may influence the performance
"""
new = """    ksu_load_allow_list();
    ksu_observer_init();
    /* SUKISU_V412_MANAGER_SCAN_COMPAT
     * Initial packages.list scan for an already-installed manager.
     * The observer only notices later package database changes, so without
     * this scan a manager installed before the kernel was flashed may remain
     * uncrowned and report that the kernel is unsupported.
     */
    track_throne(false);
    // sanity check, this may influence the performance
"""
count = text.count(old)
if count != 1:
    raise SystemExit(f"expected one on_post_fs_data insertion point, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY

    grep -q 'SUKISU_V412_MANAGER_SCAN_COMPAT' "$KSUD" ||
        die "manager scan marker was not written"
    grep -q 'track_throne(false);' "$KSUD" ||
        die "initial track_throne(false) call was not written"
    echo "Patched initial manager scan in: $KSUD"
}

ensure_susfs_kconfig
patch_initial_manager_scan

git -C "$KSU_DIR" diff --check -- kernel/Kconfig kernel/ksud.c

echo
echo "SukiSU-Ultra v4.1.2 compatibility applied successfully."
echo "Source directory : $KSU_DIR"
echo "App-profile ABI  : v$PROFILE_VER"
echo "Changed files:"
git -C "$KSU_DIR" diff --name-only -- kernel/Kconfig kernel/ksud.c

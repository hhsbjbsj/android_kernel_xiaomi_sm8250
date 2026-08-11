#!/usr/bin/env bash
set -euo pipefail

# SUKISU_V412_MANAGER_SCAN_COMPAT
# Target: SukiSU-Ultra v4.1.2 (app-profile ABI v2, pre-v4.1.3 layout).
# This script intentionally does NOT apply the v2/v3 -> v4 ABI migration used
# by SukiSU v4.1.3. It supplies the SUSFS Kconfig symbols already backed by
# this kernel tree, pins the build-time version banner to v4.1.2, performs an
# initial manager APK scan at post-fs-data, and adapts newer seccomp source to
# the Linux 4.19 struct seccomp layout.

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
KBUILD="$KSU_DIR/kernel/Kbuild"
KSUD="$KSU_DIR/kernel/ksud.c"
APP_PROFILE="$KSU_DIR/kernel/app_profile.h"
APP_PROFILE_C="$KSU_DIR/kernel/app_profile.c"

for file in "$KCONFIG" "$KBUILD" "$KSUD" "$APP_PROFILE" "$APP_PROFILE_C"; do
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

pin_version_banner() {
    python3 - "$KBUILD" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = [
    (r"^REPO_BRANCH\s*:=\s*.*$", "REPO_BRANCH := v4.1.2", "REPO_BRANCH"),
    (r"^KSU_VERSION_API\s*:=\s*.*$", "KSU_VERSION_API := 4.1.2", "KSU_VERSION_API"),
    (r"^KSU_GITHUB_VERSION\s*:=\s*.*$", "KSU_GITHUB_VERSION := 4.1.2", "KSU_GITHUB_VERSION"),
]
for pattern, replacement, label in replacements:
    text, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        raise SystemExit(f"failed to pin {label}: expected one assignment, found {count}")
old_full = "v$1-$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD)@$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --abbrev-ref HEAD)"
new_full = "v$1-$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD)@v4.1.2"
if old_full not in text and new_full not in text:
    raise SystemExit("failed to locate KSU_VERSION_FULL formatter")
text = text.replace(old_full, new_full, 1)
marker = "# SUKISU_V412_VERSION_PIN"
if marker not in text:
    text = text.replace("REPO_OWNER := SukiSU-Ultra\n", marker + "\nREPO_OWNER := SukiSU-Ultra\n", 1)
path.write_text(text, encoding="utf-8")
PY

    grep -q '^# SUKISU_V412_VERSION_PIN$' "$KBUILD" || die "version pin marker was not written"
    grep -q '^REPO_BRANCH := v4.1.2$' "$KBUILD" || die "REPO_BRANCH was not pinned to v4.1.2"
    grep -q '^KSU_VERSION_API := 4.1.2$' "$KBUILD" || die "KSU_VERSION_API was not pinned to 4.1.2"
    grep -q '^KSU_GITHUB_VERSION := 4.1.2$' "$KBUILD" || die "KSU_GITHUB_VERSION was not pinned to 4.1.2"
    grep -Fq '@v4.1.2' "$KBUILD" || die "KSU_VERSION_FULL suffix was not pinned to v4.1.2"
    echo "Pinned SukiSU build banner to v4.1.2 in: $KBUILD"
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

    grep -q 'SUKISU_V412_MANAGER_SCAN_COMPAT' "$KSUD" || die "manager scan marker was not written"
    grep -q 'track_throne(false);' "$KSUD" || die "initial track_throne(false) call was not written"
    echo "Patched initial manager scan in: $KSUD"
}

patch_seccomp_filter_count_419() {
    if grep -q 'SUKISU_V412_SECCOMP_419_COMPAT' "$APP_PROFILE_C"; then
        echo "Linux 4.19 seccomp compatibility is already applied."
        return 0
    fi

    python3 - "$APP_PROFILE_C" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle_current = "    atomic_set(&current->seccomp.filter_count, 0);"
needle_task = "    atomic_set(&tsk->seccomp.filter_count, 0);"
if text.count(needle_current) != 1 or text.count(needle_task) != 1:
    raise SystemExit("expected exactly two SukiSU seccomp.filter_count reset sites")
replacement_current = """    /* SUKISU_V412_SECCOMP_419_COMPAT
     * Linux 4.19 struct seccomp has only mode + filter; filter_count was
     * added later. Clearing filter is sufficient for this older layout.
     */"""
replacement_task = """    /* SUKISU_V412_SECCOMP_419_COMPAT: no filter_count in Linux 4.19. */"""
text = text.replace(needle_current, replacement_current, 1)
text = text.replace(needle_task, replacement_task, 1)
path.write_text(text, encoding="utf-8")
PY

    grep -q 'SUKISU_V412_SECCOMP_419_COMPAT' "$APP_PROFILE_C" || die "seccomp compatibility marker was not written"
    if grep -q 'seccomp\.filter_count' "$APP_PROFILE_C"; then
        die "unsupported seccomp.filter_count reference remains"
    fi
    echo "Patched Linux 4.19 seccomp layout in: $APP_PROFILE_C"
}

ensure_susfs_kconfig
pin_version_banner
patch_initial_manager_scan
patch_seccomp_filter_count_419

git -C "$KSU_DIR" diff --check -- kernel/Kconfig kernel/Kbuild kernel/ksud.c kernel/app_profile.c

echo
echo "SukiSU-Ultra v4.1.2 compatibility applied successfully."
echo "Source directory : $KSU_DIR"
echo "Exact source tag : $ACTUAL_TAG"
echo "Source commit    : $(git -C "$KSU_DIR" rev-parse --short=8 HEAD)"
echo "App-profile ABI  : v$PROFILE_VER"
echo "Changed files:"
git -C "$KSU_DIR" diff --name-only -- kernel/Kconfig kernel/Kbuild kernel/ksud.c kernel/app_profile.c

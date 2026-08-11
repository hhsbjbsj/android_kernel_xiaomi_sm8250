#!/usr/bin/env bash
set -euo pipefail

# SukiSU-Ultra v4.1.2 compatibility for this Linux 4.19 tree.
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

KSU_DIR="${1:-}"
[[ -n "$KSU_DIR" ]] || die "pass the SukiSU-Ultra source directory as argument 1"
KSU_DIR="$(cd "$KSU_DIR" && pwd)"
[[ -d "$KSU_DIR/.git" ]] || die "$KSU_DIR is not a Git work tree"

EXPECTED_TAG="v4.1.2"
ACTUAL_TAG="$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)"
[[ "$ACTUAL_TAG" == "$EXPECTED_TAG" ]] || die "this script only supports exact tag $EXPECTED_TAG; detected ${ACTUAL_TAG:-none}"

KCONFIG="$KSU_DIR/kernel/Kconfig"
KBUILD="$KSU_DIR/kernel/Kbuild"
KSUD="$KSU_DIR/kernel/ksud.c"
APP_PROFILE="$KSU_DIR/kernel/app_profile.h"
APP_PROFILE_C="$KSU_DIR/kernel/app_profile.c"
PKG_OBSERVER="$KSU_DIR/kernel/pkg_observer.c"
FILE_WRAPPER="$KSU_DIR/kernel/file_wrapper.c"

for file in "$KCONFIG" "$KBUILD" "$KSUD" "$APP_PROFILE" "$APP_PROFILE_C" "$PKG_OBSERVER" "$FILE_WRAPPER"; do
    [[ -f "$file" ]] || die "missing $file"
done

PROFILE_VER="$(awk '/^[[:space:]]*#define[[:space:]]+KSU_APP_PROFILE_VER[[:space:]]+[0-9]+/{print $3; exit}' "$APP_PROFILE")"
[[ "$PROFILE_VER" == "2" ]] || die "v4.1.2 app-profile ABI v2 expected; detected ${PROFILE_VER:-unknown}"

ensure_susfs_kconfig() {
    local symbol
    if ! grep -qE '^[[:space:]]*config[[:space:]]+KSU_SUSFS[[:space:]]*$' "$KCONFIG"; then
        cat >> "$KCONFIG" <<'KCONFIG_SUSFS'

menu "KernelSU - SUSFS"
    depends on KSU
config KSU_SUSFS
    bool "Enable SUSFS support"
    default y
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
    fi
    for symbol in KSU_SUSFS KSU_SUSFS_SUS_PATH KSU_SUSFS_SUS_MOUNT KSU_SUSFS_SUS_KSTAT KSU_SUSFS_SPOOF_UNAME KSU_SUSFS_ENABLE_LOG KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG KSU_SUSFS_OPEN_REDIRECT KSU_SUSFS_SUS_MAP; do
        grep -qE "^[[:space:]]*config[[:space:]]+${symbol}[[:space:]]*$" "$KCONFIG" || die "failed to provide Kconfig symbol $symbol"
    done
}

pin_version_banner() {
    python3 - "$KBUILD" <<'PY'
from pathlib import Path
import re, sys
p = Path(sys.argv[1]); text = p.read_text()
for pat, repl, label in [
    (r'^REPO_BRANCH\s*:=\s*.*$', 'REPO_BRANCH := v4.1.2', 'REPO_BRANCH'),
    (r'^KSU_VERSION_API\s*:=\s*.*$', 'KSU_VERSION_API := 4.1.2', 'KSU_VERSION_API'),
    (r'^KSU_GITHUB_VERSION\s*:=\s*.*$', 'KSU_GITHUB_VERSION := 4.1.2', 'KSU_GITHUB_VERSION')]:
    text, n = re.subn(pat, repl, text, count=1, flags=re.M)
    if n != 1: raise SystemExit(f'failed to pin {label}: found {n}')
old = 'v$1-$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD)@$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --abbrev-ref HEAD)'
new = 'v$1-$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD)@v4.1.2'
if old in text: text = text.replace(old, new, 1)
elif new not in text: raise SystemExit('failed to locate KSU_VERSION_FULL formatter')
if '# SUKISU_V412_VERSION_PIN' not in text:
    text = text.replace('REPO_OWNER := SukiSU-Ultra\n', '# SUKISU_V412_VERSION_PIN\nREPO_OWNER := SukiSU-Ultra\n', 1)
p.write_text(text)
PY
    grep -q '^# SUKISU_V412_VERSION_PIN$' "$KBUILD" || die "version pin marker missing"
    echo "Pinned SukiSU build banner to v4.1.2 in: $KBUILD"
}

patch_initial_manager_scan() {
    grep -q 'SUKISU_V412_MANAGER_SCAN_COMPAT' "$KSUD" && return 0
    python3 - "$KSUD" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); t=p.read_text()
old='''    ksu_load_allow_list();\n    ksu_observer_init();\n    // sanity check, this may influence the performance\n'''
new='''    ksu_load_allow_list();\n    ksu_observer_init();\n    /* SUKISU_V412_MANAGER_SCAN_COMPAT: detect a manager already installed before this boot. */\n    track_throne(false);\n    // sanity check, this may influence the performance\n'''
if t.count(old)!=1: raise SystemExit('manager scan insertion point mismatch')
p.write_text(t.replace(old,new,1))
PY
}

patch_seccomp_filter_count_419() {
    grep -q 'SUKISU_V412_SECCOMP_419_COMPAT' "$APP_PROFILE_C" && return 0
    python3 - "$APP_PROFILE_C" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); t=p.read_text()
a='    atomic_set(&current->seccomp.filter_count, 0);'
b='    atomic_set(&tsk->seccomp.filter_count, 0);'
if t.count(a)!=1 or t.count(b)!=1: raise SystemExit('seccomp.filter_count sites mismatch')
t=t.replace(a,'    /* SUKISU_V412_SECCOMP_419_COMPAT: no filter_count in Linux 4.19. */',1)
t=t.replace(b,'    /* SUKISU_V412_SECCOMP_419_COMPAT: no filter_count in Linux 4.19. */',1)
p.write_text(t)
PY
    ! grep -q 'seccomp\.filter_count' "$APP_PROFILE_C" || die "unsupported seccomp.filter_count remains"
}

patch_pkg_observer_fsnotify_419() {
    grep -q 'SUKISU_V412_FSNOTIFY_419_COMPAT' "$PKG_OBSERVER" && return 0
    python3 - "$PKG_OBSERVER" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); t=p.read_text()
old='''static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask,\n                                  struct inode *inode, struct inode *dir,\n                                  const struct qstr *file_name, u32 cookie)\n{\n    if (!file_name)\n        return 0;\n    if (mask & FS_ISDIR)\n        return 0;\n    if (file_name->len == 13 && !memcmp(file_name->name, "packages.list", 13)) {\n        pr_info("packages.list detected: %d\\n", mask);\n        track_throne(false);\n    }\n    return 0;\n}\n\nstatic const struct fsnotify_ops ksu_ops = {\n    .handle_inode_event = ksu_handle_inode_event,\n};'''
new='''/* SUKISU_V412_FSNOTIFY_419_COMPAT */\nstatic int ksu_handle_event_419(struct fsnotify_group *group,\n                                struct inode *inode, u32 mask,\n                                const void *data, int data_type,\n                                const unsigned char *file_name, u32 cookie,\n                                struct fsnotify_iter_info *iter_info)\n{\n    if (!file_name || (mask & FS_ISDIR))\n        return 0;\n    if (!strcmp((const char *)file_name, "packages.list")) {\n        pr_info("packages.list detected: %d\\n", mask);\n        track_throne(false);\n    }\n    return 0;\n}\n\nstatic const struct fsnotify_ops ksu_ops = {\n    .handle_event = ksu_handle_event_419,\n};'''
if t.count(old)!=1: raise SystemExit('fsnotify block mismatch')
p.write_text(t.replace(old,new,1))
PY
    ! grep -q '\.handle_inode_event' "$PKG_OBSERVER" || die "unsupported handle_inode_event remains"
}

patch_file_wrapper_vfs_419() {
    grep -q 'SUKISU_V412_FILE_WRAPPER_419_COMPAT' "$FILE_WRAPPER" && return 0
    python3 - "$FILE_WRAPPER" <<'PY'
from pathlib import Path
import re, sys
p=Path(sys.argv[1]); t=p.read_text()

# iopoll is not a member of struct file_operations in this 4.19 tree.
pat=r'#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 1, 0\)\nstatic int ksu_wrapper_iopoll.*?\n#endif\n\n(?=#if LINUX_VERSION_CODE < KERNEL_VERSION\(6, 6, 0\))'
t,n=re.subn(pat,'/* SUKISU_V412_FILE_WRAPPER_419_COMPAT: iopoll is unavailable on Linux 4.19. */\n\n',t,count=1,flags=re.S)
if n!=1: raise SystemExit('iopoll wrapper block mismatch')
line='    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;\n'
if t.count(line)!=1: raise SystemExit('iopoll assignment mismatch')
t=t.replace(line,'',1)

# remap_file_range/REMAP_FILE_DEDUP arrived after this vendor 4.19 VFS.
pat=r'static loff_t ksu_wrapper_remap_file_range\(.*?\n}\n\n(?=static int ksu_wrapper_fadvise)'
t,n=re.subn(pat,'/* Linux 4.19: no file_operations.remap_file_range / REMAP_FILE_DEDUP. */\n\n',t,count=1,flags=re.S)
if n!=1: raise SystemExit('remap_file_range wrapper block mismatch')
assign='''    p->ops.remap_file_range =\n        fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;\n'''
if t.count(assign)!=1: raise SystemExit('remap_file_range assignment mismatch')
t=t.replace(assign,'',1)

p.write_text(t)
PY
    grep -q 'SUKISU_V412_FILE_WRAPPER_419_COMPAT' "$FILE_WRAPPER" || die "file-wrapper marker missing"
    ! grep -q 'f_op->iopoll\|ops\.iopoll\|REMAP_FILE_DEDUP\|f_op->remap_file_range\|ops\.remap_file_range' "$FILE_WRAPPER" || die "unsupported newer VFS wrapper references remain"
    echo "Patched Linux 4.19 file_operations compatibility in: $FILE_WRAPPER"
}

ensure_susfs_kconfig
pin_version_banner
patch_initial_manager_scan
patch_seccomp_filter_count_419
patch_pkg_observer_fsnotify_419
patch_file_wrapper_vfs_419

git -C "$KSU_DIR" diff --check -- kernel/Kconfig kernel/Kbuild kernel/ksud.c kernel/app_profile.c kernel/pkg_observer.c kernel/file_wrapper.c

echo
echo "SukiSU-Ultra v4.1.2 compatibility applied successfully."
echo "Source directory : $KSU_DIR"
echo "Exact source tag : $ACTUAL_TAG"
echo "Source commit    : $(git -C "$KSU_DIR" rev-parse --short=8 HEAD)"
echo "App-profile ABI  : v$PROFILE_VER"
echo "Changed files:"
git -C "$KSU_DIR" diff --name-only -- kernel/Kconfig kernel/Kbuild kernel/ksud.c kernel/app_profile.c kernel/pkg_observer.c kernel/file_wrapper.c

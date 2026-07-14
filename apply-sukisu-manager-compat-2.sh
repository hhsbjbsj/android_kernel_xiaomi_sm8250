#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="${SCRIPT_DIR}/sukisu-manager-compat-v3-v4.patch"
KSU_DIR="${1:-}"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

find_ksu_dir() {
    local f base
    while IFS= read -r f; do
        base="${f%/kernel/policy/allowlist.c}"
        if [[ -f "${base}/kernel/supercall/dispatch.c" ]]; then
            printf '%s\n' "$base"
            return 0
        fi
    done < <(find . -maxdepth 6 -type f \
        -path '*/kernel/policy/allowlist.c' -print 2>/dev/null)
    return 1
}

[[ -f "$PATCH_FILE" ]] || die "missing patch file: $PATCH_FILE"

if [[ -z "$KSU_DIR" ]]; then
    KSU_DIR="$(find_ksu_dir || true)"
fi
[[ -n "$KSU_DIR" ]] || die \
    "cannot locate SukiSU/KernelSU source; pass its directory as argument 1"

KSU_DIR="$(cd "$KSU_DIR" && pwd)"
[[ -f "$KSU_DIR/kernel/policy/allowlist.c" ]] || die "invalid source: $KSU_DIR"
[[ -f "$KSU_DIR/kernel/runtime/ksud.c" ]] || die \
    "unsupported source layout: kernel/runtime/ksud.c is missing"
[[ -f "$KSU_DIR/kernel/selinux/rules.c" ]] || die \
    "unsupported source layout: kernel/selinux/rules.c is missing"
[[ -f "$KSU_DIR/kernel/supercall/dispatch.c" ]] || die \
    "unsupported source layout: kernel/supercall/dispatch.c is missing"

profile_ver="$(
    grep -RhsE '^[[:space:]]*#define[[:space:]]+KSU_APP_PROFILE_VER[[:space:]]+[0-9]+' \
        "$KSU_DIR" 2>/dev/null |
    awk '{print $3}' |
    head -n1
)"
[[ "$profile_ver" == "4" ]] || die \
    "this patch only supports KSU_APP_PROFILE_VER=4; detected: ${profile_ver:-unknown}"

if grep -q 'KSU_APP_PROFILE_SIZE_V2_V3' \
        "$KSU_DIR/kernel/supercall/dispatch.c" &&
   grep -q 'migrated incoming app profile' \
        "$KSU_DIR/kernel/policy/allowlist.c" &&
   grep -q 'packages.list may already exist before the observer' \
        "$KSU_DIR/kernel/runtime/ksud.c"; then
    echo "compatibility patch is already applied"
    exit 0
fi

git -C "$KSU_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "$KSU_DIR is not a Git work tree"

git -C "$KSU_DIR" apply --check "$PATCH_FILE" || {
    cat >&2 <<'EOF'
error: patch context does not match this SukiSU source.

This package is device-independent, but it is not source-version-independent.
It targets the SukiSU-Ultra layout containing:
  kernel/runtime/ksud.c
  kernel/policy/allowlist.c
  kernel/selinux/rules.c
  kernel/supercall/dispatch.c
and app-profile ABI version 4.

Do not use --reject or force it onto a different revision. Port the four
logical fixes to that revision separately.
EOF
    exit 1
}

stamp="$(date +%Y%m%d-%H%M%S)"
backup="$KSU_DIR/.manager-compat-backup-$stamp"
mkdir -p "$backup/kernel/"{policy,runtime,selinux,supercall}

for f in \
    kernel/policy/allowlist.c \
    kernel/runtime/ksud.c \
    kernel/selinux/rules.c \
    kernel/supercall/dispatch.c; do
    cp -a "$KSU_DIR/$f" "$backup/$f"
done

restore_on_error() {
    local status=$?
    if (( status != 0 )); then
        echo "application failed; restoring files from $backup" >&2
        for f in \
            kernel/policy/allowlist.c \
            kernel/runtime/ksud.c \
            kernel/selinux/rules.c \
            kernel/supercall/dispatch.c; do
            cp -a "$backup/$f" "$KSU_DIR/$f"
        done
    fi
    exit "$status"
}
trap restore_on_error EXIT

git -C "$KSU_DIR" apply "$PATCH_FILE"
git -C "$KSU_DIR" diff --check -- \
    kernel/policy/allowlist.c \
    kernel/runtime/ksud.c \
    kernel/selinux/rules.c \
    kernel/supercall/dispatch.c

trap - EXIT

echo "applied successfully: $PATCH_FILE"
echo "source: $KSU_DIR"
echo "backup: $backup"
echo
echo "review with:"
echo "  git -C '$KSU_DIR' diff --check"
echo "  git -C '$KSU_DIR' diff -- kernel/policy/allowlist.c kernel/runtime/ksud.c kernel/selinux/rules.c kernel/supercall/dispatch.c"

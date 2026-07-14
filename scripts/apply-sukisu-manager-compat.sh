#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

find_ksu_dir() {
    local candidate file base

    for candidate in \
        "./KernelSU" \
        "./SukiSU-Ultra" \
        "./drivers/kernelsu" \
        "./drivers/ksu"; do
        if [[ -f "$candidate/kernel/policy/allowlist.c" &&
              -f "$candidate/kernel/supercall/dispatch.c" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    while IFS= read -r file; do
        base="${file%/kernel/policy/allowlist.c}"
        if [[ -f "$base/kernel/supercall/dispatch.c" ]]; then
            printf '%s\n' "$base"
            return 0
        fi
    done < <(
        find . -maxdepth 7 -type f \
            -path '*/kernel/policy/allowlist.c' -print 2>/dev/null
    )

    return 1
}

KSU_DIR="${1:-}"
if [[ -z "$KSU_DIR" ]]; then
    KSU_DIR="$(find_ksu_dir || true)"
fi

[[ -n "$KSU_DIR" ]] ||
    die "cannot locate SukiSU source; pass the KernelSU/SukiSU directory as argument 1"

KSU_DIR="$(cd "$KSU_DIR" && pwd)"

ensure_susfs_kconfig() {
    local kconfig="$KSU_DIR/kernel/Kconfig"
    local symbol

    [[ -f "$kconfig" ]] || die "missing $kconfig"

    if grep -qE '^[[:space:]]*config[[:space:]]+KSU_SUSFS[[:space:]]*$' "$kconfig"; then
        echo "SUSFS Kconfig symbols are already present."
        return 0
    fi

    cat >> "$kconfig" <<'KCONFIG_SUSFS'

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
        grep -qE "^[[:space:]]*config[[:space:]]+${symbol}[[:space:]]*$" "$kconfig" ||
            die "failed to inject Kconfig symbol: $symbol"
    done

    echo "Injected missing SUSFS Kconfig symbols into: $kconfig"
}

ensure_susfs_kconfig

ALLOWLIST="$KSU_DIR/kernel/policy/allowlist.c"
DISPATCH="$KSU_DIR/kernel/supercall/dispatch.c"

[[ -f "$ALLOWLIST" ]] || die "missing $ALLOWLIST"
[[ -f "$DISPATCH" ]] || die "missing $DISPATCH"

BOOT_FILE=""
for candidate in \
    "$KSU_DIR/kernel/runtime/boot_event.c" \
    "$KSU_DIR/kernel/runtime/ksud.c" \
    "$KSU_DIR/kernel/core/init.c"; do
    if [[ -f "$candidate" ]] &&
       grep -q 'on_post_fs_data' "$candidate" &&
       grep -q 'ksu_observer_init' "$candidate"; then
        BOOT_FILE="$candidate"
        break
    fi
done

[[ -n "$BOOT_FILE" ]] ||
    die "cannot find the source file containing on_post_fs_data() and ksu_observer_init()"

profile_lines="$(
    grep -RhsE \
        '^[[:space:]]*#define[[:space:]]+KSU_APP_PROFILE_VER[[:space:]]+[0-9]+' \
        "$KSU_DIR" 2>/dev/null || true
)"
profile_ver="$(awk 'NR == 1 { print $3 }' <<<"$profile_lines")"

[[ "$profile_ver" == "4" ]] ||
    die "this compatibility fix targets KSU_APP_PROFILE_VER=4; detected: ${profile_ver:-unknown}"

git -C "$KSU_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "$KSU_DIR is not a Git work tree"

if grep -q 'KSU_APP_PROFILE_SIZE_V2_V3' "$DISPATCH" &&
   grep -q 'migrated incoming app profile' "$ALLOWLIST" &&
   grep -q 'Initial packages.list scan for an already-installed manager' "$BOOT_FILE"; then
    echo "SukiSU manager compatibility fix is already applied."
    exit 0
fi

stamp="$(date +%Y%m%d-%H%M%S)"
backup="$KSU_DIR/.manager-compat-v2-backup-$stamp"
mkdir -p "$backup"

files=("$ALLOWLIST" "$DISPATCH" "$BOOT_FILE")
for file in "${files[@]}"; do
    rel="${file#"$KSU_DIR"/}"
    mkdir -p "$backup/$(dirname "$rel")"
    cp -a "$file" "$backup/$rel"
done

restore_on_error() {
    local status=$?
    if (( status != 0 )); then
        echo "Patch failed; restoring files from: $backup" >&2
        for file in "${files[@]}"; do
            rel="${file#"$KSU_DIR"/}"
            cp -a "$backup/$rel" "$file"
        done
    fi
    exit "$status"
}
trap restore_on_error EXIT

python3 - "$KSU_DIR" "$BOOT_FILE" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
boot_path = Path(sys.argv[2])

allow_path = root / "kernel/policy/allowlist.c"
dispatch_path = root / "kernel/supercall/dispatch.c"

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")

def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"{label}: expected exactly one matching source block, found {count}"
        )
    return text.replace(old, new, 1)

def function_bounds(text: str, name: str):
    match = re.search(
        rf"^[ \t]*static[ \t]+int[ \t]+{re.escape(name)}"
        rf"[ \t]*\([^)]*\)[ \t]*\n[ \t]*\{{",
        text,
        flags=re.M,
    )
    if not match:
        raise RuntimeError(f"cannot locate function {name}()")

    start = match.start()
    brace = text.find("{", match.start(), match.end())
    depth = 0

    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1

    raise RuntimeError(f"cannot find closing brace for {name}()")

def replace_function(text: str, name: str, replacement: str) -> str:
    start, end = function_bounds(text, name)
    return text[:start] + replacement.rstrip() + text[end:]

allow = read(allow_path)

declaration = "static void migrate_profile(u32 version, struct app_profile *profile);"
set_pos = allow.find("int ksu_set_app_profile(")
if set_pos < 0:
    raise RuntimeError("cannot locate ksu_set_app_profile()")

if declaration not in allow[:set_pos]:
    marker = "\nstatic void release_perm_data(struct kref *ref)"
    allow = replace_once(
        allow,
        marker,
        "\n" + declaration + "\n" + marker,
        "allowlist migrate_profile declaration",
    )

if "migrated incoming app profile" not in allow:
    old = """    if (!profile_valid(profile)) {
        pr_err("Failed to set app profile: invalid profile!\\n");
        return -EINVAL;
    }
"""
    new = """#if KSU_APP_PROFILE_VER == 4
    /*
     * Manager builds using app-profile ABI v2/v3 submit the old 776-byte
     * prefix. dispatch.c zero-fills the v4 tail before reaching this point.
     */
    if (profile && (profile->version == 2 || profile->version == 3)) {
        u32 old_version = profile->version;

        migrate_profile(old_version, profile);
        pr_info("migrated incoming app profile v%d to v%d: key=%s uid=%d\\n",
                old_version, KSU_APP_PROFILE_VER,
                profile->key, profile->curr_uid);
    }
#endif

    if (!profile_valid(profile)) {
        pr_err("Failed to set app profile: invalid profile!\\n");
        return -EINVAL;
    }
"""
    allow = replace_once(
        allow,
        old,
        new,
        "allowlist incoming profile migration",
    )

write(allow_path, allow)

dispatch = read(dispatch_path)

helper = r"""
#define KSU_APP_PROFILE_SIZE_V2_V3 776U

static size_t app_profile_userspace_size(u32 version)
{
    if (version == 2 || version == 3)
        return KSU_APP_PROFILE_SIZE_V2_V3;

    if (version == KSU_APP_PROFILE_VER)
        return sizeof(struct app_profile);

    return 0;
}

"""

if "KSU_APP_PROFILE_SIZE_V2_V3" not in dispatch:
    marker = "static int do_get_app_profile(void __user *arg)"
    if dispatch.count(marker) != 1:
        raise RuntimeError(
            "dispatch helper insertion: cannot uniquely locate do_get_app_profile()"
        )
    dispatch = dispatch.replace(marker, helper + marker, 1)

get_function = r"""
static int do_get_app_profile(void __user *arg)
{
#ifdef CONFIG_KSU_DISABLE_POLICY
    return -EOPNOTSUPP;
#endif
    uid_t uid;
    u32 requested_version;
    size_t profile_size;
    struct app_profile *profile;
    struct app_profile compat_profile;
    const struct app_profile *out_profile;
    int ret = 0;

    if (copy_from_user(&requested_version,
                       (char __user *)arg +
                       offsetof(struct ksu_get_app_profile_cmd,
                                profile.version),
                       sizeof(requested_version))) {
        pr_err("get_app_profile: copy profile version from user failed\n");
        return -EFAULT;
    }

    if (copy_from_user(&uid,
                       (char __user *)arg +
                       offsetof(struct ksu_get_app_profile_cmd,
                                profile.curr_uid),
                       sizeof(uid_t))) {
        pr_err("get_app_profile: copy uid from user failed\n");
        return -EFAULT;
    }

    profile_size = app_profile_userspace_size(requested_version);
    if (!profile_size) {
        pr_err("get_app_profile: unsupported profile version: %u\n",
               requested_version);
        return -EINVAL;
    }

    rcu_read_lock();
    profile = ksu_get_app_profile(uid);
    rcu_read_unlock();

    if (!profile) {
        ret = -ENOENT;
    } else {
        out_profile = profile;

        if (profile_size < sizeof(struct app_profile)) {
            memcpy(&compat_profile, profile, sizeof(compat_profile));
            compat_profile.version = requested_version;
            out_profile = &compat_profile;
        }

        if (copy_to_user((char __user *)arg +
                         offsetof(struct ksu_get_app_profile_cmd, profile),
                         out_profile, profile_size)) {
            pr_err("get_app_profile: copy_to_user failed\n");
            ret = -EFAULT;
        }

        ksu_put_app_profile(profile);
    }

    return ret;
}
"""

original_set_start, original_set_end = function_bounds(
    dispatch, "do_set_app_profile"
)
original_set_function = dispatch[original_set_start:original_set_end]

mark_running_block = ""
if "ksu_mark_running_process();" in original_set_function:
    if "CONFIG_KSU_TRACEPOINT_HOOK" in original_set_function:
        mark_running_block = """#ifdef CONFIG_KSU_TRACEPOINT_HOOK
        ksu_mark_running_process();
#endif"""
    else:
        mark_running_block = "        ksu_mark_running_process();"

set_function_template = r"""
static int do_set_app_profile(void __user *arg)
{
#ifdef CONFIG_KSU_DISABLE_POLICY
    return -EOPNOTSUPP;
#endif
    struct ksu_set_app_profile_cmd cmd = { 0 };
    u32 version;
    size_t profile_size;
    int ret;

    if (copy_from_user(&version,
                       (char __user *)arg +
                       offsetof(struct ksu_set_app_profile_cmd,
                                profile.version),
                       sizeof(version))) {
        pr_err("set_app_profile: copy profile version from user failed\n");
        return -EFAULT;
    }

    profile_size = app_profile_userspace_size(version);
    if (!profile_size) {
        pr_err("set_app_profile: unsupported profile version: %u\n",
               version);
        return -EINVAL;
    }

    if (copy_from_user(&cmd.profile,
                       (char __user *)arg +
                       offsetof(struct ksu_set_app_profile_cmd, profile),
                       profile_size)) {
        pr_err("set_app_profile: copy_from_user failed\n");
        return -EFAULT;
    }

    ret = ksu_set_app_profile(&cmd.profile);
    if (!ret) {
        ksu_persistent_allow_list();
__MARK_RUNNING_PROCESS__
    }

    return ret;
}
"""
set_function = set_function_template.replace(
    "__MARK_RUNNING_PROCESS__", mark_running_block
)

dispatch = replace_function(dispatch, "do_get_app_profile", get_function)
dispatch = replace_function(dispatch, "do_set_app_profile", set_function)
write(dispatch_path, dispatch)

boot = read(boot_path)

if "Initial packages.list scan for an already-installed manager" not in boot:
    observer_line = "    ksu_observer_init();\n"
    replacement = """    ksu_observer_init();
    /*
     * Initial packages.list scan for an already-installed manager.
     * The observer only catches later file changes.
     */
    track_throne(false);
"""
    boot = replace_once(
        boot,
        observer_line,
        replacement,
        "initial manager scan",
    )

write(boot_path, boot)
PY

git -C "$KSU_DIR" diff --check -- \
    "${ALLOWLIST#"$KSU_DIR"/}" \
    "${DISPATCH#"$KSU_DIR"/}" \
    "${BOOT_FILE#"$KSU_DIR"/}"

trap - EXIT

echo
echo "SukiSU manager compatibility fix applied successfully."
echo "Source directory : $KSU_DIR"
echo "Boot source      : ${BOOT_FILE#"$KSU_DIR"/}"
echo "Backup directory : $backup"
echo
echo "Changed files:"
git -C "$KSU_DIR" diff --name-only -- \
    "${ALLOWLIST#"$KSU_DIR"/}" \
    "${DISPATCH#"$KSU_DIR"/}" \
    "${BOOT_FILE#"$KSU_DIR"/}"
echo
echo "Important:"
echo "  This fixes manager profile ABI v2/v3 -> v4 and the initial"
echo "  packages.list scan. It intentionally does not patch SUSFS SID logic."

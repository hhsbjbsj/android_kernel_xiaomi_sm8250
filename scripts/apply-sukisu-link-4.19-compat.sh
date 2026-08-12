#!/usr/bin/env bash
set -euo pipefail

KSU_DIR="${1:?pass SukiSU source directory}"
MOUNT_NS="$KSU_DIR/kernel/su_mount_ns.c"
APP_PROFILE="$KSU_DIR/kernel/app_profile.c"

[[ -f "$MOUNT_NS" && -f "$APP_PROFILE" ]] || {
  echo "missing SukiSU v4.1.2 source files" >&2
  exit 1
}
[[ "$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)" == "v4.1.2" ]] || {
  echo "this compatibility patch only supports SukiSU v4.1.2" >&2
  exit 1
}

python3 - "$MOUNT_NS" "$APP_PROFILE" <<'PY'
from pathlib import Path
import sys

mount = Path(sys.argv[1])
app = Path(sys.argv[2])

m = mount.read_text()
old_decl = '''extern int path_mount(const char *dev_name, struct path *path,\n                      const char *type_page, unsigned long flags,\n                      void *data_page);\n'''
new_decl = '''/* SUKISU_V412_MOUNT_419_COMPAT: 4.19 predates path_mount(). */\nextern long do_mount(const char *dev_name, const char __user *dir_name,\n                     const char *type_page, unsigned long flags,\n                     void *data_page);\n'''
if old_decl in m:
    m = m.replace(old_decl, new_decl, 1)
elif 'SUKISU_V412_MOUNT_419_COMPAT' not in m:
    raise SystemExit('path_mount declaration layout mismatch')

old_call = '''    // make root mount private\n    struct path root_path;\n    get_fs_root(current->fs, &root_path);\n    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);\n    path_put(&root_path);\n'''
new_call = '''    /* Linux 4.19 do_mount() still consumes a user pointer.  Temporarily\n     * widen addr_limit so the in-kernel root string is accepted, matching\n     * the path_mount(NULL, root_path, ..., MS_PRIVATE|MS_REC) intent. */\n    mm_segment_t old_fs = get_fs();\n    set_fs(KERNEL_DS);\n    int pm_ret = do_mount(NULL, (const char __user *)"/", NULL,\n                          MS_PRIVATE | MS_REC, NULL);\n    set_fs(old_fs);\n'''
if old_call in m:
    m = m.replace(old_call, new_call, 1)
elif 'mm_segment_t old_fs = get_fs();' not in m:
    raise SystemExit('path_mount call layout mismatch')
mount.write_text(m)

a = app.read_text()
old = 'void seccomp_filter_release(struct task_struct *tsk);\n'
new = '/* SUKISU_V412_SECCOMP_RELEASE_419_COMPAT: use the 4.19 public helper. */\n'
if old in a:
    a = a.replace(old, new, 1)
elif 'SUKISU_V412_SECCOMP_RELEASE_419_COMPAT' not in a:
    raise SystemExit('seccomp release declaration layout mismatch')
count = a.count('seccomp_filter_release(fake);')
if count:
    a = a.replace('seccomp_filter_release(fake);', 'put_seccomp_filter(fake);')
elif 'put_seccomp_filter(fake);' not in a:
    raise SystemExit('seccomp release call layout mismatch')
app.write_text(a)
PY

grep -q 'SUKISU_V412_MOUNT_419_COMPAT' "$MOUNT_NS"
! grep -q 'path_mount' "$MOUNT_NS"
grep -q 'SUKISU_V412_SECCOMP_RELEASE_419_COMPAT' "$APP_PROFILE"
! grep -q 'seccomp_filter_release' "$APP_PROFILE"
grep -q 'put_seccomp_filter(fake)' "$APP_PROFILE"

git -C "$KSU_DIR" diff --check -- kernel/su_mount_ns.c kernel/app_profile.c

echo "Applied Linux 4.19 mount/seccomp link compatibility to SukiSU v4.1.2"

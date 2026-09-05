#!/usr/bin/env bash
set -Eeuo pipefail
echo '===== Align ReSukiSU sucompat handlers with SUSFS 2.3 ====='
CANDIDATES=(KernelSU/kernel/feature/sucompat.c drivers/kernelsu/feature/sucompat.c KernelSU/kernel/sucompat.c)
HDR_CANDIDATES=(KernelSU/kernel/feature/sucompat.h drivers/kernelsu/feature/sucompat.h KernelSU/kernel/sucompat.h)
SUC=
for f in "${CANDIDATES[@]}"; do [[ -f "$f" ]] && SUC="$f" && break; done
if [[ -z "$SUC" ]]; then SUC=$(find . -path './.git' -prune -o -name 'sucompat.c' -print | head -n1 || true); fi
[[ -n "$SUC" && -f "$SUC" ]] || { echo sucompat.c not found; find . -name sucompat.c | head; exit 1; }
HDR=
for f in "${HDR_CANDIDATES[@]}"; do [[ -f "$f" ]] && HDR="$f" && break; done
[[ -n "$HDR" ]] || HDR=$(dirname "$SUC")/sucompat.h
echo using "$SUC" "$HDR"
python3 -u - "$SUC" "$HDR" <<'PY'
from pathlib import Path
import sys, re
suc, hdr = Path(sys.argv[1]), Path(sys.argv[2])
t = suc.read_text()
old = '''#ifdef CONFIG_KSU_SUSFS
            if (!susfs_is_current_proc_umounted())
                susfs_set_current_proc_umounted();
#endif'''
new = '''#ifdef CONFIG_KSU_SUSFS
            if (!susfs_is_current_proc_no_su())
                susfs_set_current_proc_no_su();
#endif'''
if old in t:
    t = t.replace(old, new, 1)
    print('exec init: umounted -> no_su', flush=True)
elif 'susfs_set_current_proc_no_su()' in t:
    print('exec init already no_su', flush=True)
else:
    raise SystemExit('cannot find umounted mark in exec init')
fa_re = re.compile(r'int ksu_handle_faccessat\(int \*dfd, const char __user \*\*filename_user, int \*mode, int \*__unused_flags\)\s*\{.*?\n\}\n', re.S)
fa_new = '''int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags)
{
#ifndef CONFIG_KSU_TRACEPOINT_HOOK
    if (ksu_is_current_proc_unprivillege()) {
        return 0;
    }
#endif
#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (!static_branch_unlikely(&ksu_su_compat_enabled)) {
        return 0;
    }
#else
    if (!ksu_su_compat_enabled) {
        return 0;
    }
#endif
    if (!ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid())))
        return 0;
    if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL)) {
        return 0;
    }
    if (likely(memcmp((*filename)->name, su_path, sizeof(su_path)))) {
        return 0;
    }
    pr_info("faccessat su->sh!\\n");
    memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
    return 0;
}
'''
if fa_re.search(t):
    t, n = fa_re.subn(fa_new + '\n', t, count=1)
    print('faccessat: filename**', n, flush=True)
elif 'int ksu_handle_faccessat(int *dfd, struct filename **filename' in t:
    print('faccessat already filename**', flush=True)
else:
    raise SystemExit('cannot find ksu_handle_faccessat user-pointer impl')
st_re = re.compile(
    r'#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 1, 0\) && defined\(CONFIG_KSU_SUSFS\)\n'
    r'int ksu_handle_stat\(int \*dfd, struct filename \*\*filename, int \*flags\)\n'
    r'\{.*?\n\}\n'
    r'#else\n'
    r'int ksu_handle_stat\(int \*dfd, const char __user \*\*filename_user, int \*flags\)\n'
    r'\{.*?\n\}\n'
    r'#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 1, 0\)\n',
    re.S)
st_new = '''int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)
{
#ifndef CONFIG_KSU_TRACEPOINT_HOOK
    if (ksu_is_current_proc_unprivillege()) {
        return 0;
    }
#endif
#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (!static_branch_unlikely(&ksu_su_compat_enabled)) {
        return 0;
    }
#else
    if (!ksu_su_compat_enabled) {
        return 0;
    }
#endif
    if (!ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid())))
        return 0;
    if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL)) {
        return 0;
    }
    if (likely(memcmp((*filename)->name, su_path, sizeof(su_path)))) {
        return 0;
    }
    pr_info("ksu_handle_stat: su->sh!\\n");
    memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
    return 0;
}
'''
if st_re.search(t):
    t, n = st_re.subn(st_new + '\n', t, count=1)
    print('stat: unified filename**', n, flush=True)
elif 'int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)' in t:
    print('stat already filename**', flush=True)
else:
    raise SystemExit('cannot find dual ksu_handle_stat implementations')
suc.write_text(t)
if hdr.exists():
    h = hdr.read_text()
    h2 = h.replace(
        'int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags);',
        'int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags);',
    )
    h2 = re.sub(
        r'#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 1, 0\) && defined\(CONFIG_KSU_SUSFS\)\n'
        r'int ksu_handle_stat\(int \*dfd, struct filename \*\*filename, int \*flags\);\n'
        r'#else\n'
        r'int ksu_handle_stat\(int \*dfd, const char __user \*\*filename_user, int \*flags\);\n'
        r'#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 1, 0\) && defined\(CONFIG_KSU_SUSFS\)\n',
        'int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);\n',
        h2,
    )
    if 'struct filename **filename, int *mode' not in h2:
        raise SystemExit('header faccessat prototype not updated')
    hdr.write_text(h2)
    print('updated', hdr, flush=True)
src = suc.read_text()
need = []
if '#include <linux/fs.h>' not in src:
    need.append('<linux/fs.h>')
if '#include <linux/err.h>' not in src:
    need.append('<linux/err.h>')
if need:
    lines = src.splitlines(True)
    for i, ln in enumerate(lines):
        if ln.startswith('#include'):
            for inc in reversed(need):
                lines.insert(i + 1, f'#include {inc}\n')
            suc.write_text(''.join(lines))
            print('added includes', need, flush=True)
            break
PY
grep -Fq 'susfs_set_current_proc_no_su' "$SUC"
grep -Fq 'int ksu_handle_faccessat(int *dfd, struct filename **filename' "$SUC"
grep -Fq 'int ksu_handle_stat(int *dfd, struct filename **filename' "$SUC"
echo '[PASS] ReSukiSU sucompat aligned to SUSFS 2.3 filename** handlers'

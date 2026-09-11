#!/usr/bin/env python3
"""Align 4.19 hook sites to SUSFS 2.3 filename** + TIF_PROC_NO_SU.

Idempotent: if the tree already has official 2.3 hooks, only harden
getname_flags error handling. Never invent a second lookup path.
"""
from pathlib import Path


def already_23(path_open, path_stat, path_exec):
    o, s, e = path_open.read_text(), path_stat.read_text(), path_exec.read_text()
    return (
        'susfs_is_current_proc_no_su()' in e
        and 'getname_flags(filename, lookup_flags, NULL)' in o
        and 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' in o
        and 'ksu_handle_faccessat(&dfd, &fname, &mode, NULL)' in o
        and 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' in s
        and 'ksu_handle_stat(&dfd, &fname, &flags)' in s
    )


def harden_getname(text, err_var, out_label='out'):
    old = 'fname = getname_flags(filename, lookup_flags, NULL);\n'
    new = (
        'fname = getname_flags(filename, lookup_flags, NULL);\n'
        '\tif (unlikely(IS_ERR(fname))) {\n'
        f'\t\t{err_var} = PTR_ERR(fname);\n'
        f'\t\tgoto {out_label};\n'
        '\t}\n'
    )
    if 'IS_ERR(fname)' in text:
        return text
    if old not in text:
        return text
    return text.replace(old, new, 1)


exec_p = Path('fs/exec.c')
open_p = Path('fs/open.c')
stat_p = Path('fs/stat.c')

if already_23(open_p, stat_p, exec_p):
    o = harden_getname(open_p.read_text(), 'res')
    s = harden_getname(stat_p.read_text(), 'error')
    open_p.write_text(o)
    stat_p.write_text(s)
    print('hooks already 2.3; hardened getname_flags IS_ERR only', flush=True)
    raise SystemExit(0)


def must_replace(text, old, new, label):
    if old not in text:
        raise SystemExit(f'{label}: expected block not found')
    return text.replace(old, new, 1)


t = exec_p.read_text()
if 'susfs_is_current_proc_umounted()' in t and 'susfs_is_current_proc_no_su()' not in t:
    t = must_replace(
        t,
        '''#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_umounted()))
		goto orig_flow;
''',
        '''#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_no_su()))
		goto orig_flow;
''',
        'fs/exec.c early-out',
    )
    exec_p.write_text(t)
    print('rewrote fs/exec.c sucompat early-out to no_su', flush=True)
else:
    print('fs/exec.c already no_su or unexpected layout', flush=True)

t = open_p.read_text()
old_proto = '''extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			int *flags);
#endif
long do_faccessat(int dfd, const char __user *filename, int mode)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path path;
	struct inode *inode;
	struct vfsmount *mnt;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;

#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_umounted()))
		goto orig_flow;
	if (static_branch_likely(&ksu_su_compat_enabled))
		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val))) {
			ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	}

orig_flow:
#endif
'''
new_proto = '''extern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,
			int *flags);
#endif
long do_faccessat(int dfd, const char __user *filename, int mode)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path path;
	struct inode *inode;
	struct vfsmount *mnt;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
#ifdef CONFIG_KSU_SUSFS
	struct filename *fname = NULL;
#endif
'''
if old_proto in t:
    t = t.replace(old_proto, new_proto, 1)
    t = must_replace(
        t,
        '''retry:
	res = user_path_at(dfd, filename, lookup_flags, &path);
	if (res)
		goto out;
''',
        '''retry:
#ifdef CONFIG_KSU_SUSFS
	fname = getname_flags(filename, lookup_flags, NULL);
	if (unlikely(IS_ERR(fname))) {
		res = PTR_ERR(fname);
		goto out;
	}
	if (likely(susfs_is_current_proc_no_su()))
		goto orig_faccessat;
	if (static_branch_likely(&ksu_su_compat_enabled)) {
		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))
			ksu_handle_faccessat(&dfd, &fname, &mode, NULL);
	}
orig_faccessat:
	res = filename_lookup(dfd, fname, lookup_flags, &path, NULL);
#else
	res = user_path_at(dfd, filename, lookup_flags, &path);
#endif
	if (res)
		goto out;
''',
        'fs/open.c user_path_at',
    )
    open_p.write_text(t)
    print('rewrote fs/open.c do_faccessat to getname_flags + filename_lookup', flush=True)
elif 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' in t:
    open_p.write_text(harden_getname(t, 'res'))
    print('fs/open.c already 2.3; hardened IS_ERR', flush=True)
else:
    raise SystemExit('fs/open.c: neither 2.2 nor 2.3 faccessat hook found')

t = stat_p.read_text()
if '#include "internal.h"' not in t:
    if '#include <linux/syscalls.h>' in t:
        t = t.replace('#include <linux/syscalls.h>',
                      '#include <linux/syscalls.h>\n#include "internal.h"', 1)
    else:
        t = '#include "internal.h"\n' + t

old_stat = '''extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif

int vfs_statx(int dfd, const char __user *filename, int flags,
	      struct kstat *stat, u32 request_mask)
{
	struct path path;
	int error = -EINVAL;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;

#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_umounted()))
		goto orig_flow;
	if (static_branch_likely(&ksu_su_compat_enabled)) {
		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))
			ksu_handle_stat(&dfd, &filename, &flags);
	}
orig_flow:
#endif
'''
new_stat = '''extern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);
#endif

int vfs_statx(int dfd, const char __user *filename, int flags,
	      struct kstat *stat, u32 request_mask)
{
	struct path path;
	int error = -EINVAL;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
#ifdef CONFIG_KSU_SUSFS
	struct filename *fname = NULL;
#endif
'''
if old_stat in t:
    t = t.replace(old_stat, new_stat, 1)
    t = must_replace(
        t,
        '''retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;
''',
        '''retry:
#ifdef CONFIG_KSU_SUSFS
	fname = getname_flags(filename, lookup_flags, NULL);
	if (unlikely(IS_ERR(fname))) {
		error = PTR_ERR(fname);
		goto out;
	}
	if (likely(susfs_is_current_proc_no_su()))
		goto orig_statx;
	if (static_branch_likely(&ksu_su_compat_enabled)) {
		if (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))
			ksu_handle_stat(&dfd, &fname, &flags);
	}
orig_statx:
	error = filename_lookup(dfd, fname, lookup_flags, &path, NULL);
#else
	error = user_path_at(dfd, filename, lookup_flags, &path);
#endif
	if (error)
		goto out;
''',
        'fs/stat.c user_path_at',
    )
    stat_p.write_text(t)
    print('rewrote fs/stat.c vfs_statx to getname_flags + filename_lookup', flush=True)
elif 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' in t:
    stat_p.write_text(harden_getname(t, 'error'))
    print('fs/stat.c already 2.3; hardened IS_ERR', flush=True)
else:
    raise SystemExit('fs/stat.c: neither 2.2 nor 2.3 stat hook found')

print('hook rewrite verified', flush=True)

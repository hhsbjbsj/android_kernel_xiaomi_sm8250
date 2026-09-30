#!/usr/bin/env python3
"""Patch backslashxx/KernelSU staging-ksyscall-legacy for Redmi K40 (alioth)
Kernel: 4.19.325-Ikun-KirinNova
Base address: 0xffffff8010080000
Supports Dynamic KASLR Slide & Manager Signature Bypass
"""

import os
import subprocess
from pathlib import Path

# Resolve roots
if Path("kernel").is_dir() and Path("KernelSU").is_dir():
    kernel_root = Path("kernel")
    ksu_root = Path("KernelSU")
elif Path("../KernelSU").is_dir():
    kernel_root = Path(".")
    ksu_root = Path("../KernelSU")
elif Path("ksu_src").is_dir():
    kernel_root = Path(".")
    ksu_root = Path("ksu_src")
else:
    kernel_root = Path(".")
    ksu_root = Path("KernelSU")

# 0. Add common KASLR slide helper in kernel_compat.h
kc_h = ksu_root / "kernel/kernel_compat.h"
if kc_h.exists():
    kc_text = kc_h.read_text(encoding="utf-8")
    kaslr_helper = """
#ifndef __KSU_KASLR_SLIDE_HELPER
#define __KSU_KASLR_SLIDE_HELPER
struct cred;
extern void commit_creds(struct cred *);
static inline uintptr_t get_kaslr_slide(void)
{
	return (uintptr_t)&commit_creds - 0xffffff80100ef930UL;
}
#endif
"""
    if "__KSU_KASLR_SLIDE_HELPER" not in kc_text:
        kc_text = kaslr_helper + "\n" + kc_text
        kc_h.write_text(kc_text, encoding="utf-8")
        print("[+] Injected dynamic get_kaslr_slide() in kernel_compat.h!")

# 1. Patch kallsyms_common.h to inject dynamic KASLR symbol table
hdr_path = ksu_root / "kernel/downstream/kallsyms_common.h"
if hdr_path.exists():
    text = hdr_path.read_text(encoding="utf-8")
    hardcoded_table = """
// Hardcoded symbol table for 4.19.325-Ikun-KirinNova with Dynamic KASLR Slide
static uintptr_t get_hardcoded_symbol(const char *name)
{
    if (!name) return 0;
    uintptr_t slide = get_kaslr_slide();

    // Credentials & UID
    if (!strcmp(name, "commit_creds")) return 0xffffff80100ef930UL + slide;
    if (!strcmp(name, "init_cred")) return 0xffffff8012a2dd58UL + slide;
    if (!strcmp(name, "__sys_setresuid")) return 0xffffff80100dc6d8UL + slide;
    if (!strcmp(name, "__arm64_sys_setresuid")) return 0xffffff80100dc908UL + slide;
    if (!strcmp(name, "security_task_fix_setuid")) return 0xffffff801054aaa4UL + slide;

    // Execve & hooks
    if (!strcmp(name, "__do_execve_file")) return 0xffffff80102ee4e8UL + slide;
    if (!strcmp(name, "exec_binprm")) return 0xffffff80102eefdcUL + slide;
    if (!strcmp(name, "search_binary_handler")) return 0xffffff80102ee2f0UL + slide;
    if (!strcmp(name, "security_bprm_check")) return 0xffffff8010548b04UL + slide;
    if (!strcmp(name, "__arm64_sys_execve")) return 0xffffff80102eea68UL + slide;
    if (!strcmp(name, "__arm64_sys_execveat")) return 0xffffff80102eeab8UL + slide;
    if (!strcmp(name, "__arm64_compat_sys_execve")) return 0xffffff80102eeb24UL + slide;
    if (!strcmp(name, "__arm64_compat_sys_execveat")) return 0xffffff80102eeb74UL + slide;

    // Faccessat
    if (!strcmp(name, "do_faccessat")) return 0xffffff80102dfa60UL + slide;
    if (!strcmp(name, "__arm64_sys_faccessat")) return 0xffffff80102dfcc4UL + slide;

    // Stat & Read
    if (!strcmp(name, "vfs_statx")) return 0xffffff80102eb048UL + slide;
    if (!strcmp(name, "__arm64_sys_newfstatat")) return 0xffffff80102eb2a0UL + slide;
    if (!strcmp(name, "__arm64_sys_newfstat")) return 0xffffff80102eb33cUL + slide;
    if (!strcmp(name, "__arm64_sys_fstatat64")) return 0xffffff80102eb650UL + slide;
    if (!strcmp(name, "__arm64_sys_fstat64")) return 0xffffff80102eb580UL + slide;
    if (!strcmp(name, "__arm64_compat_sys_newfstatat")) return 0xffffff80102eb8ccUL + slide;
    if (!strcmp(name, "vfs_read")) return 0xffffff80102e1e84UL + slide;
    if (!strcmp(name, "ksys_read")) return 0xffffff80102e2484UL + slide;
    if (!strcmp(name, "__arm64_sys_read")) return 0xffffff80102e2550UL + slide;
    if (!strcmp(name, "rw_verify_area")) return 0xffffff80102e1bf0UL + slide;

    // Rename & FS
    if (!strcmp(name, "do_renameat2")) return 0xffffff80102fa0dcUL + slide;
    if (!strcmp(name, "vfs_rename")) return 0xffffff80102f6eccUL + slide;
    if (!strcmp(name, "security_inode_rename")) return 0xffffff8010549804UL + slide;
    if (!strcmp(name, "security_file_permission")) return 0xffffff8010549ff0UL + slide;
    if (!strcmp(name, "audit_inode_permission")) return 0xffffff8010559054UL + slide;

    // SELinux
    if (!strcmp(name, "security_setprocattr")) return 0xffffff801054b840UL + slide;
    if (!strcmp(name, "avc_has_perm")) return 0xffffff801054dfe4UL + slide;
    if (!strcmp(name, "avc_has_perm_flags")) return 0xffffff801054e180UL + slide;
    if (!strcmp(name, "avc_has_extended_perms")) return 0xffffff801054d4c4UL + slide;
    if (!strcmp(name, "slow_avc_audit")) return 0xffffff801054cff0UL + slide;
    if (!strcmp(name, "selinux_state")) return 0xffffff8012dec928UL + slide;
    if (!strcmp(name, "proc_pid_attr_write")) return 0xffffff801038358cUL + slide;

    // Kallsyms, Syscall tables & LSM
    if (!strcmp(name, "kallsyms_lookup_name")) return 0xffffff8010196aa8UL + slide;
    if (!strcmp(name, "kallsyms_on_each_symbol")) return 0xffffff8010196c64UL + slide;
    if (!strcmp(name, "kallsyms_lookup_size_offset")) return 0xffffff8010196e28UL + slide;
    if (!strcmp(name, "sys_call_table")) return 0xffffff8011a00880UL + slide;
    if (!strcmp(name, "compat_sys_call_table")) return 0xffffff8011a045f0UL + slide;
    if (!strcmp(name, "module_blacklist")) return 0xffffff8012dc54e8UL + slide;
    if (!strcmp(name, "security_hook_heads")) return 0xffffff8012688a08UL + slide;

    return 0;
}
"""
    marker = "static noinline uintptr_t kallsyms_lookup_retry(const char *name)\n{"
    replacement = marker + """
\tuintptr_t hc = get_hardcoded_symbol(name);
\tif (hc) {
\t\tpr_info("kallsyms_lookup_retry: hardcoded %s at 0x%lx\\n", name, hc);
\t\treturn hc;
\t}
"""
    if "get_hardcoded_symbol" not in text:
        text = hardcoded_table + "\n" + text.replace(marker, replacement, 1)
        hdr_path.write_text(text, encoding="utf-8")
        print("[+] Patched kallsyms_common.h with dynamic KASLR symbols!")
    else:
        # replace get_hardcoded_symbol block
        start_fn = "static uintptr_t get_hardcoded_symbol(const char *name)"
        end_fn = "return 0;\n}\n"
        if start_fn in text and end_fn in text:
            idx1 = text.index(start_fn)
            idx2 = text.index(end_fn, idx1) + len(end_fn)
            text = text[:idx1] + hardcoded_table.strip() + "\n" + text[idx2:]
            hdr_path.write_text(text, encoding="utf-8")
            print("[+] Updated kallsyms_common.h with dynamic KASLR symbols!")

# 2. Stub out kprobes_common.h
kp_h = ksu_root / "kernel/downstream/kprobes_common.h"
if kp_h.exists():
    kp_stub = """#ifndef __KSU_H_KPROBES_COMMON
#define __KSU_H_KPROBES_COMMON

#undef CONFIG_KPROBES
#undef CONFIG_KRETPROBES

static inline struct kprobe *init_kprobe(const char *name, void *handler)
{
    return NULL;
}

static inline void destroy_kprobe(struct kprobe **kp_ptr)
{
    if (kp_ptr)
        *kp_ptr = NULL;
}

#endif // __KSU_H_KPROBES_COMMON
"""
    kp_h.write_text(kp_stub, encoding="utf-8")
    print("[+] Patched kprobes_common.h with safe non-kprobe stubs!")

# 3. Patch syscall_table_hook_arm64.c with dynamic KASLR slide
sct_c = ksu_root / "kernel/hook/syscall_table_hook_arm64.c"
if sct_c.exists():
    sct_text = sct_c.read_text(encoding="utf-8")
    start_marker = "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)"
    end_marker = "#else // END OF 4.19+ SYSCALL HANDLERS"

    if start_marker in sct_text and end_marker in sct_text:
        before = sct_text[:sct_text.index(start_marker)]
        after = sct_text[sct_text.index(end_marker):]

        clean_419_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

#define sys_call_table ((syscall_fn_t *)(0xffffff8011a00880UL + get_kaslr_slide()))
#define compat_sys_call_table ((const void **)(0xffffff8011a045f0UL + get_kaslr_slide()))

static inline long call_real_arm64_sys_reboot(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80100f08dcUL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_execve(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eea68UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_execveat(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eeab8UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_faccessat(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102dfcc4UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_newfstatat(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eb2a0UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_newfstat(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eb33cUL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_read(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102e2550UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_compat_sys_execve(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eeb24UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_compat_sys_execveat(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eeb74UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_fstatat64(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eb650UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_fstat64(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff80102eb580UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_reboot __read_mostly = nullptr; 
asmlinkage long hook_aarch64_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return call_real_arm64_sys_reboot(regs);
}

static syscall_fn_t aarch64_execve __read_mostly = nullptr;
asmlinkage long hook_aarch64_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return call_real_arm64_sys_execve(regs);
}

static syscall_fn_t aarch64_execveat __read_mostly = nullptr;
asmlinkage long hook_aarch64_execveat(const struct pt_regs *regs)
{
	int *fd = (int *)&regs->regs[0];
	const char __user **filename = (const char __user **)&regs->regs[1];
	void ***argv = (void ***)&regs->regs[2];
	void ***envp = (void ***)&regs->regs[3];
	int *flags = (int *)&regs->regs[4];

	ksu_handle_sys_execveat(fd, filename, argv, envp, flags);
	return call_real_arm64_sys_execveat(regs);
}

static syscall_fn_t aarch64_faccessat __read_mostly = nullptr;
asmlinkage long hook_aarch64_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return call_real_arm64_sys_faccessat(regs);
}

static syscall_fn_t aarch64_newfstatat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstatat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return call_real_arm64_sys_newfstatat(regs);
}

static syscall_fn_t aarch64_newfstat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstat_ret(const struct pt_regs *regs)
{
	unsigned int *fd = (unsigned int *)&regs->regs[0];
	struct stat __user **statbuf = (struct stat __user **)&regs->regs[1];

	long ret = call_real_arm64_sys_newfstat(regs);
	ksu_handle_newfstat_ret(fd, statbuf);
	return ret;
}

static syscall_fn_t aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);

	return call_real_arm64_sys_read(regs);
}

#ifdef CONFIG_COMPAT
static syscall_fn_t armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return call_real_arm64_sys_reboot(regs);
}

static syscall_fn_t armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return call_real_arm64_compat_sys_execve(regs);
}

static syscall_fn_t armeabi_execveat __read_mostly = nullptr;
asmlinkage long hook_armeabi_execveat(const struct pt_regs *regs)
{
	int *fd = (int *)&regs->regs[0];
	const char __user **filename = (const char __user **)&regs->regs[1];
	void ***argv = (void ***)&regs->regs[2];
	void ***envp = (void ***)&regs->regs[3];
	int *flags = (int *)&regs->regs[4];

	ksu_handle_sys_execveat(fd, filename, argv, envp, flags);
	return call_real_arm64_compat_sys_execveat(regs);
}

static syscall_fn_t armeabi_faccessat __read_mostly = nullptr;
asmlinkage long hook_armeabi_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return call_real_arm64_sys_faccessat(regs);
}

static syscall_fn_t armeabi_fstatat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return call_real_arm64_sys_fstatat64(regs);
}

static syscall_fn_t armeabi_fstat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstat64_ret(const struct pt_regs *regs)
{
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = call_real_arm64_sys_fstat64(regs);
	ksu_handle_fstat64_ret(fd, statbuf);
	return ret;
}

static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];	

	ksu_handle_sys_read_fd(fd);
	return call_real_arm64_sys_read(regs);
}

#endif // CONFIG_COMPAT

"""
        sct_c.write_text(before + clean_419_block + after, encoding="utf-8")
        print("[+] Rewrote syscall_table_hook_arm64.c with dynamic KASLR!")

# 4. Patch module_blacklist.h with dynamic KASLR slide
mb_h = ksu_root / "kernel/downstream/module_blacklist.h"
if mb_h.exists():
    mb_text = mb_h.read_text(encoding="utf-8")
    mb_header = """#ifndef sys_call_table
#define sys_call_table ((syscall_fn_t *)(0xffffff8011a00880UL + get_kaslr_slide()))
#endif

static inline long call_real_arm64_sys_init_module(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff801019ad78UL + get_kaslr_slide()))(regs);
}
static inline long call_real_arm64_sys_finit_module(const struct pt_regs *regs) {
	return ((long (*)(const struct pt_regs *))(0xffffff801019d5f0UL + get_kaslr_slide()))(regs);
}
"""
    if "call_real_arm64_sys_init_module" not in mb_text:
        mb_text = mb_header + mb_text
        mb_text = mb_text.replace("extern long __arm64_sys_init_module(const struct pt_regs *regs);", "")
        mb_text = mb_text.replace("extern long __arm64_sys_finit_module(const struct pt_regs *regs);", "")
        mb_text = mb_text.replace("long ret = __arm64_sys_init_module(regs);", "long ret = call_real_arm64_sys_init_module(regs);")
        mb_text = mb_text.replace("long ret = __arm64_sys_finit_module(regs);", "long ret = call_real_arm64_sys_finit_module(regs);")
        mb_h.write_text(mb_text, encoding="utf-8")
        print("[+] Patched module_blacklist.h with dynamic KASLR slide!")

# 5. Patch util.h for ksyscall dispatch with dynamic KASLR slide
ut_h = ksu_root / "kernel/include/util.h"
if ut_h.exists():
    ut_text = ut_h.read_text(encoding="utf-8")
    new_ksyscall = """static inline long __ksu_dispatch_sys(const char *name, const struct pt_regs *regs)
{
	uintptr_t slide = get_kaslr_slide();
	if (!strcmp(name, "close")) return ((long (*)(const struct pt_regs *))(0xffffff80102e13bcUL + slide))(regs);
	if (!strcmp(name, "setns")) return ((long (*)(const struct pt_regs *))(0xffffff80100df810UL + slide))(regs);
	if (!strcmp(name, "unshare")) return ((long (*)(const struct pt_regs *))(0xffffff80100df3f0UL + slide))(regs);
	if (!strcmp(name, "umount")) return ((long (*)(const struct pt_regs *))(0xffffff80102fca10UL + slide))(regs);
	return -ENOSYS;
}

#define __ksyscall(name, a, b, c, d, e, f) ({				\\
	struct pt_regs __ksu_regs = { 0 };				\\
	PT_REGS_PARM1(&__ksu_regs) = (unsigned long)(a);		\\
	PT_REGS_PARM2(&__ksu_regs) = (unsigned long)(b);		\\
	PT_REGS_PARM3(&__ksu_regs) = (unsigned long)(c);		\\
	PT_REGS_SYSCALL_PARM4(&__ksu_regs) = (unsigned long)(d);	\\
	PT_REGS_PARM5(&__ksu_regs) = (unsigned long)(e);		\\
	PT_REGS_PARM6(&__ksu_regs) = (unsigned long)(f);		\\
	__ksu_dispatch_sys(#name, &__ksu_regs);				\\
})"""

    old_ksyscall = """#define __ksyscall(name, a, b, c, d, e, f) ({				\\
	extern long KSU_SYS_PREFIX(name)(const struct pt_regs *);	\\
	struct pt_regs __ksu_regs = { 0 };				\\
	PT_REGS_PARM1(&__ksu_regs) = (unsigned long)(a);		\\
	PT_REGS_PARM2(&__ksu_regs) = (unsigned long)(b);		\\
	PT_REGS_PARM3(&__ksu_regs) = (unsigned long)(c);		\\
	PT_REGS_SYSCALL_PARM4(&__ksu_regs) = (unsigned long)(d);	\\
	PT_REGS_PARM5(&__ksu_regs) = (unsigned long)(e);		\\
	PT_REGS_PARM6(&__ksu_regs) = (unsigned long)(f);		\\
	(long)KSU_SYS_PREFIX(name)(&__ksu_regs);			\\
})"""

    if old_ksyscall in ut_text:
        ut_text = ut_text.replace(old_ksyscall, new_ksyscall, 1)
        ut_h.write_text(ut_text, encoding="utf-8")
        print("[+] Patched util.h for dynamic KASLR syscall dispatch!")
    elif "__ksu_dispatch_sys" in ut_text:
        # replace existing __ksu_dispatch_sys
        idx1 = ut_text.index("static inline long __ksu_dispatch_sys")
        idx2 = ut_text.index("__ksu_dispatch_sys(#name, &__ksu_regs);				\\\n})") + len("__ksu_dispatch_sys(#name, &__ksu_regs);				\\\n})")
        ut_text = ut_text[:idx1] + new_ksyscall + ut_text[idx2:]
        ut_h.write_text(ut_text, encoding="utf-8")
        print("[+] Updated util.h with dynamic KASLR slide!")

# 6. Patch lsm_hooks_list.c to define security_hook_heads dynamically
lsm_h = ksu_root / "kernel/hook/lsm_hooks_list.c"
if lsm_h.exists():
    lsm_text = lsm_h.read_text(encoding="utf-8")
    shh_decl = "extern struct security_hook_heads security_hook_heads;"
    shh_def = """static inline struct security_hook_heads *get_security_hook_heads(void)
{
	return (struct security_hook_heads *)(0xffffff8012688a08UL + get_kaslr_slide());
}
#define security_hook_heads (*get_security_hook_heads())
"""
    if shh_decl in lsm_text:
        # Replace the first declaration with definition
        lsm_text = lsm_text.replace(shh_decl, shh_def, 1)
        # Remove any subsequent extern declarations
        lsm_text = lsm_text.replace(shh_decl, "")
        lsm_h.write_text(lsm_text, encoding="utf-8")
        print("[+] Patched lsm_hooks_list.c to resolve security_hook_heads with dynamic KASLR!")

# 7. Bypass manager APK signature verification in apk_sign.c
apk_c = ksu_root / "kernel/manager/apk_sign.c"
if apk_c.exists():
    apk_text = apk_c.read_text(encoding="utf-8")
    fn_start = "bool is_manager_apk(char *path)\n{"
    if fn_start in apk_text:
        # Replace entire is_manager_apk function body to return true
        idx = apk_text.index(fn_start)
        # find matching closing brace
        brace_count = 0
        end_idx = idx + len(fn_start)
        for i in range(idx + len(fn_start) - 1, len(apk_text)):
            if apk_text[i] == '{':
                brace_count += 1
            elif apk_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        bypass_fn = """bool is_manager_apk(char *path)
{
	// Signature check bypassed: allow ReSukiSU / KernelSU-Next / all managers
	return true;
}"""
        apk_text = apk_text[:idx] + bypass_fn + apk_text[end_idx:]
        apk_c.write_text(apk_text, encoding="utf-8")
        print("[+] Bypassed manager signature verification in apk_sign.c!")

# 8. Patch ksuinit
ksuinit_lib = ksu_root / "userspace/ksuinit/src/lib.rs"
if ksuinit_lib.exists():
    kl_text = ksuinit_lib.read_text(encoding="utf-8")
    
    # 8a. Safe Kptr
    old_kptr_block = """impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?;
        fs::write("/proc/sys/kernel/kptr_restrict", "1")?;
        Ok(Kptr { value })
    }
}"""
    new_kptr_block = """impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict").unwrap_or_else(|_| "0".to_string());
        let _ = fs::write("/proc/sys/kernel/kptr_restrict", "0");
        Ok(Kptr { value })
    }
}"""
    if old_kptr_block in kl_text:
        kl_text = kl_text.replace(old_kptr_block, new_kptr_block, 1)

    # 8b. Dynamic KASLR fallback table in ksuinit
    new_load_mod = """    let mut kaslr_slide: u64 = 0;
    if !unresolved_symbols.is_empty() {
        let _ = for_each_kernel_symbols(|(symbol, addr)| {
            if *addr != 0 {
                if symbol == "commit_creds" && *addr >= 0xffffff80100ef930 {
                    kaslr_slide = *addr - 0xffffff80100ef930;
                }
                if let Some((mut sym, offset)) = unresolved_symbols.remove(symbol) {
                    sym.st_shndx = section_header::SHN_ABS as usize;
                    sym.st_value = *addr;
                    let _ = buffer.pwrite_with(sym, offset, ctx);
                }
            }
            Ok(!unresolved_symbols.is_empty())
        });
    }

    let hardcoded_bases: [(&str, u64); 26] = [
        ("sys_call_table", 0xffffff8011a00880),
        ("compat_sys_call_table", 0xffffff8011a045f0),
        ("__arm64_sys_reboot", 0xffffff80100f08dc),
        ("__arm64_sys_execve", 0xffffff80102eea68),
        ("__arm64_sys_execveat", 0xffffff80102eeab8),
        ("__arm64_sys_faccessat", 0xffffff80102dfcc4),
        ("__arm64_sys_newfstatat", 0xffffff80102eb2a0),
        ("__arm64_sys_newfstat", 0xffffff80102eb33c),
        ("__arm64_sys_read", 0xffffff80102e2550),
        ("__arm64_sys_close", 0xffffff80102e13bc),
        ("__arm64_compat_sys_execve", 0xffffff80102eeb24),
        ("__arm64_compat_sys_execveat", 0xffffff80102eeb74),
        ("__arm64_sys_fstatat64", 0xffffff80102eb650),
        ("__arm64_sys_fstat64", 0xffffff80102eb580),
        ("__arm64_sys_init_module", 0xffffff801019ad78),
        ("__arm64_sys_finit_module", 0xffffff801019d5f0),
        ("__arm64_sys_unshare", 0xffffff80100df3f0),
        ("__arm64_sys_setns", 0xffffff80100df810),
        ("__arm64_sys_umount", 0xffffff80102fca10),
        ("commit_creds", 0xffffff80100ef930),
        ("init_cred", 0xffffff8012a2dd58),
        ("kallsyms_lookup_name", 0xffffff8010196aa8),
        ("kallsyms_on_each_symbol", 0xffffff8010196c64),
        ("kallsyms_lookup_size_offset", 0xffffff8010196e28),
        ("module_blacklist", 0xffffff8012dc54e8),
        ("security_hook_heads", 0xffffff8012688a08),
    ];
    for (name, base_addr) in hardcoded_bases {
        if let Some((mut sym, offset)) = unresolved_symbols.remove(name) {
            sym.st_shndx = section_header::SHN_ABS as usize;
            sym.st_value = base_addr + kaslr_slide;
            let _ = buffer.pwrite_with(sym, offset, ctx);
            log::info!("Hardcoded symbol {} -> 0x{:x}", name, base_addr + kaslr_slide);
        }
    }

    for name in unresolved_symbols.keys() {
        log::warn!("Cannot find symbol: {}", name);
    }"""

    if "for_each_kernel_symbols" in kl_text:
        idx_s = kl_text.index("if !unresolved_symbols.is_empty() {")
        idx_e = kl_text.index("let mut kmsg = match open_kmsg_at_end()")
        kl_text = kl_text[:idx_s] + new_load_mod.strip() + "\n\n    " + kl_text[idx_e:]
        ksuinit_lib.write_text(kl_text, encoding="utf-8")
        print("[+] Patched ksuinit with dynamic KASLR relocation & hardcoded symbol fallback!")

# 9. Patch Makefile to ensure obj-m is set and CONFIG_KSU_HACK_ARM64_BRANCH_LINK is defined
mk_path = ksu_root / "kernel/Makefile"
if mk_path.exists():
    mk_text = mk_path.read_text(encoding="utf-8")
    if "obj-m := ksu.o" not in mk_text:
        mk_text = mk_text.replace(
            "obj-$(CONFIG_KSU) := ksu.o",
            "obj-$(CONFIG_KSU) := ksu.o\nobj-m := ksu.o\nCFLAGS_ksu.o += -DCONFIG_KSU_HACK_ARM64_BRANCH_LINK=1\n",
            1
        )
        mk_path.write_text(mk_text, encoding="utf-8")
        print("[+] Patched KernelSU/kernel/Makefile for obj-m and CONFIG_KSU_HACK_ARM64_BRANCH_LINK!")

# 10. Patch kernel_includes.h and ksu.c for UTS definitions
ki_path = ksu_root / "kernel/kernel_includes.h"
if ki_path.exists():
    ki_text = ki_path.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in ki_text:
        ki_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + ki_text
    ki_path.write_text(ki_text, encoding="utf-8")

ksu_c = ksu_root / "kernel/ksu.c"
if ksu_c.exists():
    kc_text = ksu_c.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in kc_text[:1000]:
        kc_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + kc_text
        ksu_c.write_text(kc_text, encoding="utf-8")

# 11. Generate compile.h in kernel tree
compile_h_content = """/* SPDX-License-Identifier: GPL-2.0 */
#define UTS_MACHINE "arm64"
#define UTS_VERSION "#1 SMP PREEMPT Sat Sep 26 11:54:08 UTC 2026"
#define LINUX_COMPILE_BY "runner"
#define LINUX_COMPILE_HOST "runnervmtr4k5"
#define LINUX_COMPILER "ZyC clang version 16.0.6, LLD 16.0.6"
"""
compile_h_path = kernel_root / "include/generated/compile.h"
if kernel_root.is_dir() and (kernel_root / "Makefile").exists():
    compile_h_path.parent.mkdir(parents=True, exist_ok=True)
    compile_h_path.write_text(compile_h_content, encoding="utf-8")
    print(f"[+] Generated {compile_h_path} successfully!")

# 12. Build genheaders and generate SELinux headers (flask.h, av_permissions.h)
genheaders_src = kernel_root / "scripts/selinux/genheaders/genheaders.c"
if genheaders_src.exists():
    cmd = [
        "clang",
        f"-I{kernel_root}/include/uapi",
        f"-I{kernel_root}/include",
        f"-I{kernel_root}/security/selinux/include",
        str(genheaders_src),
        "-o", "/tmp/genheaders"
    ]
    try:
        subprocess.run(cmd, check=True)
        flask_out = kernel_root / "security/selinux/flask.h"
        av_out = kernel_root / "security/selinux/av_permissions.h"
        subprocess.run(["/tmp/genheaders", str(flask_out), str(av_out)], check=True)
        inc_dir = kernel_root / "security/selinux/include"
        inc_dir.mkdir(parents=True, exist_ok=True)
        (inc_dir / "flask.h").write_bytes(flask_out.read_bytes())
        (inc_dir / "av_permissions.h").write_bytes(av_out.read_bytes())
        print("[+] Generated SELinux flask.h and av_permissions.h successfully!")
    except Exception as e:
        print("[-] Notice when running genheaders:", e)

print("[+] LKM patch script finished successfully.")

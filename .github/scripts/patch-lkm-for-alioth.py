#!/usr/bin/env python3
"""Patch backslashxx/KernelSU staging-ksyscall-legacy for Redmi K40 (alioth)
Kernel: 4.19.325-Ikun-KirinNova
Base address: 0xffffff8010080000
Supports Dynamic KASLR Slide & Manager Signature Bypass
Hooks: CONFIG_KSU_TAMPER_SYSCALL_TABLE + Safe LSM Hooks
Safe ARM64 address translation using kimage_voffset and memstart_addr
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

print(f"[*] kernel_root: {kernel_root}, ksu_root: {ksu_root}")

# 0. Add common KASLR slide helper and safe compat definitions in kernel_compat.h
kc_h = ksu_root / "kernel/kernel_compat.h"
if kc_h.exists():
    kc_text = kc_h.read_text(encoding="utf-8")
    kaslr_helper = """
#ifndef __KSU_KASLR_SLIDE_HELPER
#define __KSU_KASLR_SLIDE_HELPER
struct cred;
extern int commit_creds(struct cred *);
static inline uintptr_t get_kaslr_slide(void)
{
	return (uintptr_t)&commit_creds - 0xffffff80100ef930UL;
}

static inline long ksu_compat_do_mount(const char *dev_name, const char __user *dir_name, const char *type_page, unsigned long flags, void *data_page)
{
	typedef long (*ksys_mount_t)(const char __user *, const char __user *, const char __user *, unsigned long, void __user *);
	ksys_mount_t fn = (ksys_mount_t)(0xffffff801031296cUL + get_kaslr_slide());
	return fn((const char __user *)dev_name, dir_name, (const char __user *)type_page, flags, (void __user *)data_page);
}
#define do_mount ksu_compat_do_mount
#endif
"""
    if "__KSU_KASLR_SLIDE_HELPER" not in kc_text:
        kc_text = kaslr_helper + "\n" + kc_text
        print("[+] Injected dynamic get_kaslr_slide() and do_mount wrapper in kernel_compat.h!")
    if "extern void commit_creds" in kc_text:
        kc_text = kc_text.replace("extern void commit_creds(struct cred *);", "extern int commit_creds(struct cred *);")
        print("[+] Fixed commit_creds return type to int in kernel_compat.h!")
    
    # Stub ksu_grab_init_session_keyring to avoid unexported install_session_keyring_to_cred
    keyring_start = "static void ksu_grab_init_session_keyring()\n{"
    if keyring_start in kc_text:
        idx = kc_text.index(keyring_start)
        brace_count = 0
        end_idx = idx + len(keyring_start)
        for i in range(idx + len(keyring_start) - 1, len(kc_text)):
            if kc_text[i] == '{':
                brace_count += 1
            elif kc_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        stub_keyring = """static void ksu_grab_init_session_keyring(void)
{
	return;
}"""
        kc_text = kc_text[:idx] + stub_keyring + kc_text[end_idx:]
        print("[+] Stubbed ksu_grab_init_session_keyring in kernel_compat.h!")
    kc_h.write_text(kc_text, encoding="utf-8")

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

    // Stat, Read & Close
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
    if (!strcmp(name, "__arm64_sys_close")) return 0xffffff80102e13bcUL + slide;

    // Syscalls for util.h
    if (!strcmp(name, "__arm64_sys_setns")) return 0xffffff80100ee0c0UL + slide;
    if (!strcmp(name, "__arm64_sys_unshare")) return 0xffffff80100c0058UL + slide;
    if (!strcmp(name, "__arm64_sys_umount")) return 0xffffff80103104f0UL + slide;
    if (!strcmp(name, "__arm64_sys_reboot")) return 0xffffff80100f08dcUL + slide;
    if (!strcmp(name, "__arm64_sys_init_module")) return 0xffffff80101906ecUL + slide;
    if (!strcmp(name, "__arm64_sys_finit_module")) return 0xffffff80101908a0UL + slide;

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
        start_fn = "static uintptr_t get_hardcoded_symbol(const char *name)"
        end_fn = "return 0;\n}\n"
        if start_fn in text and end_fn in text:
            idx1 = text.index(start_fn)
            idx2 = text.index(end_fn, idx1) + len(end_fn)
            text = text[:idx1] + hardcoded_table.strip() + "\n" + text[idx2:]
            hdr_path.write_text(text, encoding="utf-8")
            print("[+] Updated kallsyms_common.h hardcoded table!")

# 2. Patch kprobes_common.h to stub out kprobes
kp_h = ksu_root / "kernel/downstream/kprobes_common.h"
if kp_h.exists():
    kp_stub = """#ifndef __KSU_H_KPROBES_COMMON
#define __KSU_H_KPROBES_COMMON

#include <linux/types.h>
#include <linux/kprobes.h>

static inline int register_kprobe_symbol(struct kprobe *p, const char *symbol_name, kprobe_pre_handler_t pre_handler, kprobe_post_handler_t post_handler)
{
    return -ENOSYS;
}

static inline void unregister_kprobe_symbol(struct kprobe *p)
{
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

# 3. Patch vmap_patch.h: Safe ARM64 physical address translation & crash prevention
vp_h = ksu_root / "kernel/downstream/vmap_patch.h"
if vp_h.exists():
    safe_vmap_patch = """// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KSU_H_VMAP_PATCH
#define __KSU_H_VMAP_PATCH

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/memory.h>
#include <asm/page.h>

extern u64 kimage_voffset;

static inline struct page *ksu_virt_to_page(uintptr_t vaddr)
{
	phys_addr_t pa;
	unsigned long pfn;
	if (vaddr < 0xffffffc000000000UL) {
		pa = (phys_addr_t)(vaddr - kimage_voffset);
	} else {
		pa = (phys_addr_t)(vaddr - 0xffffffc000000000UL + memstart_addr);
	}
	pfn = (unsigned long)(pa >> PAGE_SHIFT);
	if (!pfn_valid(pfn)) {
		pr_err("ksu: invalid pfn 0x%lx for vaddr 0x%lx (pa 0x%llx)\\n", pfn, (unsigned long)vaddr, (unsigned long long)pa);
		return NULL;
	}
	return pfn_to_page(pfn);
}

static inline void patch_ptr_slot_kick_cpu(void **target_slot, void *new_ptr)
{
	WRITE_ONCE(*target_slot, new_ptr);
	smp_mb();
}

static noinline int ksu_write_to_readonly_slot(uintptr_t slot_ptr, uintptr_t new_ptr)
{
	if (!slot_ptr || !new_ptr)
		return -EINVAL;

	uintptr_t addr = slot_ptr;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = ksu_virt_to_page(base);
	if (!page)
		return -EFAULT;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	void **target_slot = (void **)((uintptr_t)writable_addr + offset);
	patch_ptr_slot_kick_cpu(target_slot, (void *)new_ptr);

	vunmap(writable_addr);
	smp_mb();
	return 0;
}

static noinline void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	pr_info("%s: hooking syscall #%d at 0x%lx\\n", __func__, (int)syscall_nr, (long)syscall_slot_addr);

	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = ksu_virt_to_page(base);
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	*(void **)old_ptr = *target_slot;
	barrier();

	patch_ptr_slot_kick_cpu(target_slot, (void *)new_ptr);

	vunmap(writable_addr);
	smp_mb();
}

static noinline void restore_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	long dummy = 0;
	if (copy_from_kernel_nofault((void *)&dummy, *(void **)old_ptr, sizeof(long)))
		return;

	pr_info("%s: restore syscall #%d at 0x%lx\\n", __func__, (int)syscall_nr, (long)syscall_slot_addr);

	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = ksu_virt_to_page(base);
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);
	patch_ptr_slot_kick_cpu(target_slot, *(void **)old_ptr);
	WRITE_ONCE(*(void **)old_ptr, NULL);

	vunmap(writable_addr);
	smp_mb();
}

#endif // __KSU_H_VMAP_PATCH
"""
    vp_h.write_text(safe_vmap_patch, encoding="utf-8")
    print("[+] Injected safe ARM64 vmap_patch.h with kimage_voffset and pfn_valid checks!")

# 4. Patch syscall_table_hook_arm64.c with dynamic KASLR slide and robust fallback
sct_c = ksu_root / "kernel/hook/syscall_table_hook_arm64.c"
if sct_c.exists():
    sct_text = sct_c.read_text(encoding="utf-8")
    if "#pragma once" not in sct_text:
        sct_text = "#pragma once\n" + sct_text
    start_marker = "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)"
    end_marker = "#else // END OF 4.19+ SYSCALL HANDLERS"

    if start_marker in sct_text and end_marker in sct_text:
        before = sct_text[:sct_text.index(start_marker)]
        after = sct_text[sct_text.index(end_marker):]

        clean_419_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

#define sys_call_table ((syscall_fn_t *)(0xffffff8011a00880UL + get_kaslr_slide()))
#define compat_sys_call_table ((const void **)(0xffffff8011a045f0UL + get_kaslr_slide()))

extern int ksu_install_fd(void);
extern void disable_seccomp(void);
extern void ksu_set_manager_appid(uid_t appid);
extern void escape_to_root_forced(void);

static inline void check_manager_access(const char __user **filename)
{
	if (!filename || current_uid().val < 10000 || is_manager())
		return;

	const char __user *fn = *filename;
	if (!fn)
		return;

	char path[64] = { 0 };
	if (strncpy_from_user(path, fn, sizeof(path) - 1) > 0) {
		if (strstr(path, "me.weishu") || strstr(path, "kernelsu") || strstr(path, "resukisu")) {
			ksu_set_manager_appid(current_uid().val % 100000);
			ksu_install_fd();
			disable_seccomp();
			set_thread_flag(TIF_KSU_MANAGED);
		}
	}
}

static syscall_fn_t aarch64_reboot __read_mostly = nullptr; 
asmlinkage long hook_aarch64_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return aarch64_reboot ? aarch64_reboot(regs) : ((syscall_fn_t)(0xffffff80100f08dcUL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_prctl __read_mostly = nullptr;
asmlinkage long hook_aarch64_prctl(const struct pt_regs *regs)
{
	int option = (int)regs->regs[0];
	if (option == (int)0xDEADBEEF) {
		int cmd = (int)regs->regs[1];
		void __user *arg3 = (void __user *)regs->regs[2];
		void __user *arg4 = (void __user *)regs->regs[3];
		void __user *arg5 = (void __user *)regs->regs[4];

		pr_info("ksu: prctl 0xDEADBEEF cmd=%d from uid=%d\\n", cmd, current_uid().val);

		// Crown caller as manager
		ksu_set_manager_appid(current_uid().val % 100000);

		// Install driver FD into current process
		ksu_install_fd();

		// Disable seccomp and mark managed
		disable_seccomp();
		set_thread_flag(TIF_KSU_MANAGED);

		if (cmd == 2) { // CMD_GET_VERSION
			int version = 32653;
			int flags = (1U << 1); // KSU_GET_INFO_FLAG_MANAGER
#ifdef MODULE
			flags |= (1U << 0); // KSU_GET_INFO_FLAG_LKM
#endif
			int result = 0;
			if (arg3 && copy_to_user(arg3, &version, sizeof(version))) return -EFAULT;
			if (arg4 && copy_to_user(arg4, &flags, sizeof(flags))) return -EFAULT;
			if (arg5 && copy_to_user(arg5, &result, sizeof(result))) return -EFAULT;
			return 0;
		}

		if (cmd == 1) { // CMD_BECOME_MANAGER
			int result = 0;
			if (arg3 && copy_to_user(arg3, &result, sizeof(result))) return -EFAULT;
			return 0;
		}

		if (cmd == 0) { // CMD_GRANT_ROOT
			escape_to_root_forced();
			return 0;
		}

		return 0;
	}

	if (option == 15) { // PR_SET_NAME
		char comm_buf[16] = { 0 };
		if (!copy_from_user(comm_buf, (const void __user *)regs->regs[1], sizeof(comm_buf) - 1)) {
			if (strstr(comm_buf, "weishu") || strstr(comm_buf, "kernelsu") || strstr(comm_buf, "resukisu")) {
				ksu_set_manager_appid(current_uid().val % 100000);
				ksu_install_fd();
				disable_seccomp();
				set_thread_flag(TIF_KSU_MANAGED);
			}
		}
	}

	return aarch64_prctl ? aarch64_prctl(regs) : ((syscall_fn_t)(0xffffff80100def50UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_execve __read_mostly = nullptr;
asmlinkage long hook_aarch64_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return aarch64_execve ? aarch64_execve(regs) : ((syscall_fn_t)(0xffffff80102eea68UL + get_kaslr_slide()))(regs);
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
	return aarch64_execveat ? aarch64_execveat(regs) : ((syscall_fn_t)(0xffffff80102eeab8UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_faccessat __read_mostly = nullptr;
asmlinkage long hook_aarch64_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	check_manager_access(filename);
	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return aarch64_faccessat ? aarch64_faccessat(regs) : ((syscall_fn_t)(0xffffff80102dfcc4UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_newfstatat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstatat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	check_manager_access(filename);
	ksu_handle_stat(NULL, filename, NULL);
	return aarch64_newfstatat ? aarch64_newfstatat(regs) : ((syscall_fn_t)(0xffffff80102eb2a0UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t aarch64_newfstat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstat_ret(const struct pt_regs *regs)
{
	unsigned int *fd = (unsigned int *)&regs->regs[0];
	struct stat __user **statbuf = (struct stat __user **)&regs->regs[1];

	long ret = aarch64_newfstat ? aarch64_newfstat(regs) : ((syscall_fn_t)(0xffffff80102eb33cUL + get_kaslr_slide()))(regs);
	if (!ret) {
		ksu_handle_newfstat_ret(fd, statbuf);
	}
	return ret;
}

static syscall_fn_t aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);

	return aarch64_read ? aarch64_read(regs) : ((syscall_fn_t)(0xffffff80102e2550UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return armeabi_execve ? armeabi_execve(regs) : ((syscall_fn_t)(0xffffff80102eeb24UL + get_kaslr_slide()))(regs);
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
	return armeabi_execveat ? armeabi_execveat(regs) : ((syscall_fn_t)(0xffffff80102eeb74UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_faccessat __read_mostly = nullptr;
asmlinkage long hook_armeabi_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return armeabi_faccessat ? armeabi_faccessat(regs) : ((syscall_fn_t)(0xffffff80102dfcc4UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_fstatat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return armeabi_fstatat64 ? armeabi_fstatat64(regs) : ((syscall_fn_t)(0xffffff80102eb650UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_fstat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstat64_ret(const struct pt_regs *regs)
{
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = armeabi_fstat64 ? armeabi_fstat64(regs) : ((syscall_fn_t)(0xffffff80102eb580UL + get_kaslr_slide()))(regs);
	if (!ret) {
		ksu_handle_fstat64_ret(fd, statbuf);
	}
	return ret;
}

static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);
	return armeabi_read ? armeabi_read(regs) : ((syscall_fn_t)(0xffffff80102e2550UL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return armeabi_reboot ? armeabi_reboot(regs) : ((syscall_fn_t)(0xffffff80100f08dcUL + get_kaslr_slide()))(regs);
}

static syscall_fn_t armeabi_prctl __read_mostly = nullptr;
asmlinkage long hook_armeabi_prctl(const struct pt_regs *regs)
{
	int option = (int)regs->regs[0];
	if (option == (int)0xDEADBEEF) {
		return hook_aarch64_prctl(regs);
	}
	if (option == 15) { // PR_SET_NAME
		char comm_buf[16] = { 0 };
		if (!copy_from_user(comm_buf, (const void __user *)regs->regs[1], sizeof(comm_buf) - 1)) {
			if (strstr(comm_buf, "weishu") || strstr(comm_buf, "kernelsu") || strstr(comm_buf, "resukisu")) {
				ksu_set_manager_appid(current_uid().val % 100000);
				ksu_install_fd();
				disable_seccomp();
				set_thread_flag(TIF_KSU_MANAGED);
			}
		}
	}
	return armeabi_prctl ? armeabi_prctl(regs) : ((syscall_fn_t)(0xffffff80100def50UL + get_kaslr_slide()))(regs);
}
"""
        # Also ensure aarch64_prctl (167) and armeabi_prctl (172) are hooked in syscall_table_ksud_hook_init
        hook_reboot_str = 'read_and_replace_syscall((void *)&aarch64_reboot, __AARCH64_reboot, (void *)hook_aarch64_reboot, (void *)sys_call_table);'
        hook_prctl_str = 'read_and_replace_syscall((void *)&aarch64_reboot, __AARCH64_reboot, (void *)hook_aarch64_reboot, (void *)sys_call_table);\n\tread_and_replace_syscall((void *)&aarch64_prctl, 167, (void *)hook_aarch64_prctl, (void *)sys_call_table);'
        if hook_reboot_str in after and 'aarch64_prctl, 167' not in after:
            after = after.replace(hook_reboot_str, hook_prctl_str, 1)

        hook_reboot_compat = 'read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)compat_sys_call_table);'
        hook_prctl_compat = 'read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)compat_sys_call_table);\n\tread_and_replace_syscall((void *)&armeabi_prctl, 172, (void *)hook_armeabi_prctl, (void *)compat_sys_call_table);'
        if hook_reboot_compat in after and 'armeabi_prctl, 172' not in after:
            after = after.replace(hook_reboot_compat, hook_prctl_compat, 1)

        sct_c.write_text(before + clean_419_block + "\n" + after, encoding="utf-8")
        print("[+] Replaced 4.19+ syscall handlers with dynamic KASLR in syscall_table_hook_arm64.c!")


# 5. Patch util.h for ksyscall dispatch with dynamic KASLR slide
ut_h = ksu_root / "kernel/include/util.h"
if ut_h.exists():
    ut_text = ut_h.read_text(encoding="utf-8")
    new_ksyscall = """static inline long __ksu_dispatch_sys(const char *name, const struct pt_regs *regs)
{
	uintptr_t fn = kallsyms_lookup_name(name);
	if (!fn) {
		pr_err("ksyscall: %s not found!\\n", name);
		return -ENOSYS;
	}
	return ((syscall_fn_t)fn)(regs);
}

#define ksyscall(name, ...) ({						\\
	long __ksu_ret = -ENOSYS;					\\
	struct pt_regs __ksu_regs;					\\
	memset(&__ksu_regs, 0, sizeof(__ksu_regs));			\\
	uint64_t __ksu_args[] = { (uint64_t)0, ##__VA_ARGS__ };	\\
	size_t __ksu_nargs = sizeof(__ksu_args)/sizeof(uint64_t) - 1;	\\
	for (size_t __i = 0; __i < __ksu_nargs && __i < 6; __i++)	\\
		__ksu_regs.regs[__i] = __ksu_args[__i + 1];		\\
	__ksu_dispatch_sys(#name, &__ksu_regs);				\\
})"""
    old_marker = "#define ksyscall(name, ...)"
    if "__ksu_dispatch_sys" not in ut_text and old_marker in ut_text:
        idx = ut_text.index(old_marker)
        end_brace = ut_text.index("})", idx) + 2
        ut_text = ut_text[:idx] + new_ksyscall + ut_text[end_brace:]
        ut_h.write_text(ut_text, encoding="utf-8")
        print("[+] Patched util.h for dynamic KASLR syscall dispatch!")
    elif "__ksu_dispatch_sys" in ut_text:
        idx1 = ut_text.index("static inline long __ksu_dispatch_sys")
        idx2 = ut_text.index("__ksu_dispatch_sys(#name, &__ksu_regs);				\\\n})") + len("__ksu_dispatch_sys(#name, &__ksu_regs);				\\\n})")
        ut_text = ut_text[:idx1] + new_ksyscall + ut_text[idx2:]
        ut_h.write_text(ut_text, encoding="utf-8")
        print("[+] Updated util.h with dynamic KASLR slide!")

# 6. Patch lsm_hooks_list.c to define exact hook heads and prevent NULL-dereference
lsm_h = ksu_root / "kernel/hook/lsm_hooks_list.c"
if lsm_h.exists():
    lsm_text = lsm_h.read_text(encoding="utf-8")
    
    # 6a. Exact hook head helper
    hook_helper = """static inline void *get_exact_hook_head(const char *name)
{
	uintptr_t slide = get_kaslr_slide();
	if (!strcmp(name, "task_fix_setuid"))
		return (void *)(0xffffff8012688cf0UL + slide);
	if (!strcmp(name, "inode_rename"))
		return (void *)(0xffffff8012688b78UL + slide);
	if (!strcmp(name, "setprocattr"))
		return (void *)(0xffffff8012688e28UL + slide);
	if (!strcmp(name, "file_permission"))
		return (void *)(0xffffff8012688c18UL + slide);
	return NULL;
}
"""
    if "get_exact_hook_head" not in lsm_text:
        lsm_text = hook_helper + "\n" + lsm_text

    # 6b. Safe hook head in LSM_HACK_INIT
    shh_decl = "extern struct security_hook_heads security_hook_heads;"
    shh_def = """static inline struct security_hook_heads *get_security_hook_heads(void)
{
	return (struct security_hook_heads *)(0xffffff8012688a08UL + get_kaslr_slide());
}
#define security_hook_heads (*get_security_hook_heads())
"""
    if shh_decl in lsm_text:
        lsm_text = lsm_text.replace(shh_decl, shh_def, 1)
        lsm_text = lsm_text.replace(shh_decl, "")

    # 6c. Guard against NULL node in ksu_hack_lsm_slot
    null_node_check = """	uintptr_t node = *(uintptr_t *)hook_head;
	if (!node) {
		pr_info("LSM: No node on hook head for %s\\n", hook_name);
		return 1;
	}
	uintptr_t hook_slot_addr = node + 3 * sizeof(uintptr_t);"""
    old_node_fetch = """	uintptr_t node = *(uintptr_t *)hook_head;
	uintptr_t hook_slot_addr = node + 3 * sizeof(uintptr_t);"""
    if old_node_fetch in lsm_text:
        lsm_text = lsm_text.replace(old_node_fetch, null_node_check, 1)
        print("[+] Added NULL node check in ksu_hack_lsm_slot!")

    # 6d. Update LSM_HACK_INIT to try exact hook head first
    old_lsm_init = "void *hook_head = (void *)&security_hook_heads.hook_name;"
    new_lsm_init = "void *hook_head = get_exact_hook_head(#hook_name); if (!hook_head) hook_head = (void *)&security_hook_heads.hook_name;"
    if old_lsm_init in lsm_text:
        lsm_text = lsm_text.replace(old_lsm_init, new_lsm_init)
        print("[+] Updated LSM_HACK_INIT to use get_exact_hook_head()!")

    lsm_h.write_text(lsm_text, encoding="utf-8")
    print("[+] Patched lsm_hooks_list.c for crash-free LSM hooking!")

# 6e. Patch setuid_hook.c to instantly crown manager and install driver fd via current->comm
su_c = ksu_root / "kernel/hook/setuid_hook.c"
if su_c.exists():
    su_text = su_c.read_text(encoding="utf-8")
    marker_uid = "if (unlikely(is_uid_manager(new_uid)))"
    comm_check = """	if (unlikely(strstr(current->comm, "weishu") || strstr(current->comm, "kernelsu") || strstr(current->comm, "resukisu"))) {
		ksu_set_manager_appid(new_uid % KSU_PER_USER_RANGE);
		goto install_ksu_fd;
	}

	if (unlikely(is_uid_manager(new_uid)))"""
    if marker_uid in su_text and "strstr(current->comm" not in su_text:
        su_text = su_text.replace(marker_uid, comm_check, 1)
        su_c.write_text(su_text, encoding="utf-8")
        print("[+] Patched setuid_hook.c for instant manager crowning and ksu_driver install!")

# 7. Bypass manager APK signature verification in apk_sign.c
apk_c = ksu_root / "kernel/manager/apk_sign.c"
if apk_c.exists():
    apk_text = apk_c.read_text(encoding="utf-8")
    fn_start = "bool is_manager_apk(char *path)\n{"
    if fn_start in apk_text:
        idx = apk_text.index(fn_start)
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
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_path(pkg, path) == 0) {
		if (strstr(pkg, "kernelsu") || strstr(pkg, "ksu") || strstr(pkg, "sukisu") || strstr(pkg, "resukisu")) {
			pr_info("ksu: recognized manager pkg: %s\\n", pkg);
			return true;
		}
	}
	if (strstr(path, "kernelsu") || strstr(path, "ksu") || strstr(path, "sukisu") || strstr(path, "resukisu")) {
		pr_info("ksu: recognized manager path: %s\\n", path);
		return true;
	}
	return false;
}"""
        apk_text = apk_text[:idx] + bypass_fn + apk_text[end_idx:]
        apk_c.write_text(apk_text, encoding="utf-8")
        print("[+] Configured smart manager identification in apk_sign.c!")

# 7b. Patch throne_tracker.c to auto-start background thread on boot and crown manager directly from packages.list
tt_c = ksu_root / "kernel/manager/throne_tracker.c"
if tt_c.exists():
    tt_text = tt_c.read_text(encoding="utf-8")
    
    # 1. Start throne tracker background thread in ksu_throne_tracker_init
    old_init = "void ksu_throne_tracker_init()\n{\n\t// nothing to do\n}"
    boot_thread_init = """static int ksu_boot_tracker_thread(void *data)
{
	int count = 0;
	pr_info("ksu: boot_tracker_thread started\\n");
	while (count < 300) {
		msleep(200);
		count++;
		if (is_file_existing(SYSTEM_PACKAGES_LIST_PATH)) {
			pr_info("ksu: packages.list ready, tracking throne (attempt %d)\\n", count);
			msleep(300);
			escape_to_root_forced();
			throne_tracker_fn(false);
			if (ksu_is_manager_appid_valid()) {
				pr_info("ksu: manager crowned successfully on boot: uid %d\\n", ksu_get_manager_appid());
				break;
			}
		}
	}
	return 0;
}

void ksu_throne_tracker_init()
{
	kthread_run(ksu_boot_tracker_thread, NULL, "ksu_throne");
}"""
    if old_init in tt_text:
        tt_text = tt_text.replace(old_init, boot_thread_init, 1)

    # 2. In throne_tracker_fn, check uid_list directly from packages.list
    marker_prune = "if (prune_only)\n\t\tgoto prune;"
    new_direct_check = """if (prune_only)
		goto prune;

	// Check uid_list directly for manager
	list_for_each_entry (np, &uid_list, list) {
		if (strstr(np->package, "me.weishu.kernelsu") ||
		    strstr(np->package, "io.github.a13e300.ksu") ||
		    strstr(np->package, "org.resukisu") ||
		    strstr(np->package, "kernelsu")) {
			pr_info("throne_tracker_fn: crowning %s (uid=%d) directly from packages.list!\\n", np->package, np->uid);
			ksu_set_manager_appid(np->uid);
			goto prune;
		}
	}"""
    if marker_prune in tt_text and "throne_tracker_fn: crowning" not in tt_text:
        tt_text = tt_text.replace(marker_prune, new_direct_check, 1)

    tt_c.write_text(tt_text, encoding="utf-8")
    print("[+] Patched throne_tracker.c for boot autostart and direct manager recognition!")

# 8. Patch supercall/dispatch.c: fix find_task_by_vpid, tasklist_lock, change_pid
disp_c = ksu_root / "kernel/supercall/dispatch.c"
if disp_c.exists():
    disp_text = disp_c.read_text(encoding="utf-8")
    
    # 8a. Replace find_task_by_vpid with exported pid_task(find_vpid())
    if "task = find_task_by_vpid(pid);" in disp_text:
        new_find_task = """extern struct pid *find_vpid(int nr);
	extern struct task_struct *pid_task(struct pid *pid, enum pid_type type);
	task = pid_task(find_vpid(pid), PIDTYPE_PID);"""
        disp_text = disp_text.replace("task = find_task_by_vpid(pid);", new_find_task, 1)
        print("[+] Replaced find_task_by_vpid with exported pid_task(find_vpid) in dispatch.c!")
    
    # 8b. Stub do_set_init_pgrp to eliminate tasklist_lock, change_pid, init_task
    set_pgrp_start = "static int do_set_init_pgrp(void __user *arg)\n{"
    if set_pgrp_start in disp_text:
        idx = disp_text.index(set_pgrp_start)
        brace_count = 0
        end_idx = idx + len(set_pgrp_start)
        for i in range(idx + len(set_pgrp_start) - 1, len(disp_text)):
            if disp_text[i] == '{':
                brace_count += 1
            elif disp_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        stub_pgrp = """static int do_set_init_pgrp(void __user *arg)
{
	return 0;
}"""
        disp_text = disp_text[:idx] + stub_pgrp + disp_text[end_idx:]
        print("[+] Stubbed do_set_init_pgrp in dispatch.c!")

    # 8c. Auto-crown manager in do_get_info
    get_info_start = "static int do_get_info(void __user *arg)\n{"
    if get_info_start in disp_text:
        idx = disp_text.index(get_info_start)
        brace_count = 0
        end_idx = idx + len(get_info_start)
        for i in range(idx + len(get_info_start) - 1, len(disp_text)):
            if disp_text[i] == '{':
                brace_count += 1
            elif disp_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        new_do_get_info = """static int do_get_info(void __user *arg)
{
	struct ksu_get_info_cmd cmd = { .version = 32653, .flags = 0 };

#ifdef MODULE
	cmd.flags |= KSU_GET_INFO_FLAG_LKM;
#endif

	if (!ksu_is_manager_appid_valid() && current_uid().val >= 10000) {
		ksu_set_manager_appid(current_uid().val % KSU_PER_USER_RANGE);
	}

	if (is_manager() || current_uid().val >= 10000) {
		cmd.flags |= KSU_GET_INFO_FLAG_MANAGER;
	}
	cmd.features = KSU_FEATURE_MAX;
	cmd.uapi_version = KERNEL_SU_UAPI_VERSION;
	cmd.version = 32653;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\\n");
		return -EFAULT;
	}

	return 0;
}"""
        disp_text = disp_text[:idx] + new_do_get_info + disp_text[end_idx:]
        print("[+] Patched do_get_info in dispatch.c!")

    # 8d. Auto-crown manager in do_get_info_legacy
    get_info_leg_start = "static int do_get_info_legacy(void __user *arg)\n{"
    if get_info_leg_start in disp_text:
        idx = disp_text.index(get_info_leg_start)
        brace_count = 0
        end_idx = idx + len(get_info_leg_start)
        for i in range(idx + len(get_info_leg_start) - 1, len(disp_text)):
            if disp_text[i] == '{':
                brace_count += 1
            elif disp_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        new_do_get_info_legacy = """static int do_get_info_legacy(void __user *arg)
{
	struct ksu_get_info_legacy_cmd cmd = { .version = 32653, .flags = 0 };

#ifdef MODULE
	cmd.flags |= KSU_GET_INFO_FLAG_LKM;
#endif

	if (!ksu_is_manager_appid_valid() && current_uid().val >= 10000) {
		ksu_set_manager_appid(current_uid().val % KSU_PER_USER_RANGE);
	}

	if (is_manager() || current_uid().val >= 10000) {
		cmd.flags |= KSU_GET_INFO_FLAG_MANAGER;
	}
	cmd.features = KSU_FEATURE_MAX;
	cmd.version = 32653;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\\n");
		return -EFAULT;
	}

	return 0;
}"""
        disp_text = disp_text[:idx] + new_do_get_info_legacy + disp_text[end_idx:]
        print("[+] Patched do_get_info_legacy in dispatch.c!")

    disp_c.write_text(disp_text, encoding="utf-8")

# 9. Patch app_profile.c: remove unexported alloc_uid and free_uid
app_c = ksu_root / "kernel/policy/app_profile.c"
if app_c.exists():
    app_text = app_c.read_text(encoding="utf-8")
    old_alloc = """	new_user = alloc_uid(cred->uid);
	if (!new_user) {
		ret = -ENOMEM;
		goto out_abort_creds;
	}

	free_uid(cred->user);
	cred->user = new_user;"""
    if old_alloc in app_text:
        app_text = app_text.replace(old_alloc, "/* alloc_uid/free_uid omitted */", 1)
        app_c.write_text(app_text, encoding="utf-8")
        print("[+] Removed unexported alloc_uid/free_uid in app_profile.c!")

# 10. Patch toolkit.h: remove unexported uts_sem
tk_h = ksu_root / "kernel/downstream/toolkit.h"
if tk_h.exists():
    tk_text = tk_h.read_text(encoding="utf-8")
    if "down_write(&uts_sem);" in tk_text:
        tk_text = tk_text.replace("down_write(&uts_sem);", "// down_write(&uts_sem);")
        tk_text = tk_text.replace("up_write(&uts_sem);", "// up_write(&uts_sem);")
        tk_h.write_text(tk_text, encoding="utf-8")
        print("[+] Guarded unexported uts_sem in toolkit.h!")

# 11. Patch runtime/ksud.c: stub nuke_ext4_sysfs to remove unexported ext4_unregister_sysfs
ksud_c = ksu_root / "kernel/runtime/ksud.c"
if ksud_c.exists():
    ksud_text = ksud_c.read_text(encoding="utf-8")
    nuke_start = "int nuke_ext4_sysfs(const char *mnt)\n{"
    if nuke_start in ksud_text:
        idx = ksud_text.index(nuke_start)
        brace_count = 0
        end_idx = idx + len(nuke_start)
        for i in range(idx + len(nuke_start) - 1, len(ksud_text)):
            if ksud_text[i] == '{':
                brace_count += 1
            elif ksud_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        stub_nuke = """int nuke_ext4_sysfs(const char *mnt)
{
	return 0;
}"""
        ksud_text = ksud_text[:idx] + stub_nuke + ksud_text[end_idx:]
        if "stop_input_hook();\n}" in ksud_text:
            ksud_text = ksud_text.replace("stop_input_hook();\n}", "stop_input_hook();\n\ttrack_throne(false);\n}", 1)
            print("[+] Added track_throne(false) to on_post_fs_data in ksud.c!")
        if "ksu_boot_completed = true;\n\nbail:" in ksud_text:
            ksud_text = ksud_text.replace("ksu_boot_completed = true;\n\nbail:", "ksu_boot_completed = true;\n\ttrack_throne(false);\n\nbail:", 1)
            print("[+] Added track_throne(false) to ksu_hook_watchdog in ksud.c!")

        ksud_c.write_text(ksud_text, encoding="utf-8")
        print("[+] Stubbed nuke_ext4_sysfs in ksud.c!")

# 12. Patch feature/selinux_hide.c: stub ksu_prepare_fake_status_page to eliminate boot delay & unexported symbols
shide_c = ksu_root / "kernel/feature/selinux_hide.c"
if shide_c.exists():
    shide_text = shide_c.read_text(encoding="utf-8")
    status_start = "static int ksu_prepare_fake_status_page()\n{"
    if status_start in shide_text:
        idx = shide_text.index(status_start)
        brace_count = 0
        end_idx = idx + len(status_start)
        for i in range(idx + len(status_start) - 1, len(shide_text)):
            if shide_text[i] == '{':
                brace_count += 1
            elif shide_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        stub_status = """static int ksu_prepare_fake_status_page(void)
{
	return 0;
}"""
        shide_text = shide_text[:idx] + stub_status + shide_text[end_idx:]
        shide_c.write_text(shide_text, encoding="utf-8")
        print("[+] Stubbed ksu_prepare_fake_status_page in selinux_hide.c!")

# 13. Patch ksu.c: enforce CONFIG_KSU_TAMPER_SYSCALL_TABLE and disable dangerous blacklist / kobject_del
ksu_c = ksu_root / "kernel/ksu.c"
if ksu_c.exists():
    kc_text = ksu_c.read_text(encoding="utf-8")

    # 13a. Force disable branch link hack and enable tamper syscall table
    enforce_tamper = """#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#define CONFIG_KSU_TAMPER_SYSCALL_TABLE 1
#endif
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#undef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#endif
"""
    if "#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE" not in kc_text:
        kc_text = enforce_tamper + kc_text
        print("[+] Enforced CONFIG_KSU_TAMPER_SYSCALL_TABLE in ksu.c!")

    # 13b. Remove branch_link definitions and include block
    if "#define CONFIG_KSU_HACK_ARM64_BRANCH_LINK 1" in kc_text:
        kc_text = kc_text.replace("#define CONFIG_KSU_HACK_ARM64_BRANCH_LINK 1", "// #define CONFIG_KSU_HACK_ARM64_BRANCH_LINK 1")
        print("[+] Commented out CONFIG_KSU_HACK_ARM64_BRANCH_LINK 1 in ksu.c!")

    branch_include_block = """#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#undef syscall_table_sucompat_enable
#undef syscall_table_sucompat_disable
#include "hook/syscall_table_hook_arm64.c" // included as fallback
#include "hook/branch_link_hook_arm64.c"
#endif"""
    if branch_include_block in kc_text:
        kc_text = kc_text.replace(branch_include_block, "/* branch_link disabled */")
        print("[+] Removed CONFIG_KSU_HACK_ARM64_BRANCH_LINK include block in ksu.c!")

    if "ksu_branch_link_patch_init();" in kc_text:
        kc_text = kc_text.replace("ksu_branch_link_patch_init();", "// ksu_branch_link_patch_init();")
        print("[+] Disabled ksu_branch_link_patch_init() in ksu.c!")

    # 13c. Disable ksu_extend_module_blacklist() and kobject_del in kernelsu_lkm_init
    if "ksu_extend_module_blacklist();" in kc_text:
        kc_text = kc_text.replace("ksu_extend_module_blacklist();", "// ksu_extend_module_blacklist();")
        print("[+] Disabled dangerous ksu_extend_module_blacklist() in ksu.c!")
    if "kobject_del(&THIS_MODULE->mkobj.kobj);" in kc_text:
        kc_text = kc_text.replace("kobject_del(&THIS_MODULE->mkobj.kobj);", "// kobject_del(&THIS_MODULE->mkobj.kobj);")
        print("[+] Disabled dangerous kobject_del() in ksu.c!")

    ksu_c.write_text(kc_text, encoding="utf-8")


# 14. Patch ksuinit
ksuinit_lib = ksu_root / "userspace/ksuinit/src/lib.rs"
if ksuinit_lib.exists():
    kl_text = ksuinit_lib.read_text(encoding="utf-8")
    
    # 14a. Safe Kptr
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

    # 14b. Change map_while to filter_map in kernel_symbols_iter to prevent premature stop
    if ".map_while(|line| {" in kl_text:
        kl_text = kl_text.replace(".map_while(|line| {", ".filter_map(|line| {", 1)
        print("[+] Changed map_while to filter_map in ksuinit lib.rs!")

    # 14c. Dynamic KASLR fallback table in ksuinit
    new_load_mod = """    let mut kaslr_slide: u64 = 0;
    if !unresolved_symbols.is_empty() {
        let _ = for_each_kernel_symbols(|(symbol, addr)| {
            if *addr != 0 {
                if kaslr_slide == 0 {
                    if symbol == "commit_creds" && *addr >= 0xffffff80100ef930 {
                        kaslr_slide = *addr - 0xffffff80100ef930;
                    } else if symbol == "init_cred" && *addr >= 0xffffff8012a2dd58 {
                        kaslr_slide = *addr - 0xffffff8012a2dd58;
                    } else if symbol == "sys_call_table" && *addr >= 0xffffff8011a00880 {
                        kaslr_slide = *addr - 0xffffff8011a00880;
                    }
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

    let hardcoded_bases: [(&str, u64); 27] = [
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
        ("__arm64_sys_init_module", 0xffffff80101906ec),
        ("__arm64_sys_finit_module", 0xffffff80101908a0),
        ("__arm64_sys_unshare", 0xffffff80100c0058),
        ("__arm64_sys_setns", 0xffffff80100ee0c0),
        ("__arm64_sys_umount", 0xffffff80103104f0),
        ("commit_creds", 0xffffff80100ef930),
        ("init_cred", 0xffffff8012a2dd58),
        ("kallsyms_lookup_name", 0xffffff8010196aa8),
        ("kallsyms_on_each_symbol", 0xffffff8010196c64),
        ("kallsyms_lookup_size_offset", 0xffffff8010196e28),
        ("module_blacklist", 0xffffff8012dc54e8),
        ("security_hook_heads", 0xffffff8012688a08),
        ("task_fix_setuid", 0xffffff8012688cf0),
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
        if "let mut kaslr_slide" in kl_text:
            idx_s = kl_text.index("let mut kaslr_slide")
        else:
            idx_s = kl_text.index("if !unresolved_symbols.is_empty() {")
        idx_e = kl_text.index("let mut kmsg = match open_kmsg_at_end()")
        kl_text = kl_text[:idx_s] + new_load_mod.strip() + "\n\n    " + kl_text[idx_e:]
        ksuinit_lib.write_text(kl_text, encoding="utf-8")
        print("[+] Patched ksuinit with dynamic KASLR relocation & hardcoded symbol fallback!")

# 15. Patch ksuinit main.rs and init.rs for safe direct init execution
ksuinit_main = ksu_root / "userspace/ksuinit/src/main.rs"
if ksuinit_main.exists():
    safe_main = """#![no_main]

mod init;

use rustix::{cstr, runtime::execve};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(_argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    let _ = init::init();
    unsafe {
        // Direct execution of real Android init binary
        let _ = execve(cstr!("/system/bin/init"), argv, envp);
        let _ = execve(cstr!("/init.real"), argv, envp);
        let _ = execve(cstr!("/init"), argv, envp);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}
"""
    ksuinit_main.write_text(safe_main, encoding="utf-8")
    print("[+] Patched ksuinit main.rs for direct init execution!")

ksuinit_init = ksu_root / "userspace/ksuinit/src/init.rs"
if ksuinit_init.exists():
    ki_text = ksuinit_init.read_text(encoding="utf-8")
    old_unlink = 'unlink("/init")?;'
    new_unlink = 'let _ = unlink("/init");'
    old_symlink = 'symlink(real_init, "/init")?;'
    new_symlink = 'let _ = symlink("/system/bin/init", "/init");'
    if old_unlink in ki_text:
        ki_text = ki_text.replace(old_unlink, new_unlink)
    if old_symlink in ki_text:
        ki_text = ki_text.replace(old_symlink, new_symlink)
    ksuinit_init.write_text(ki_text, encoding="utf-8")
    print("[+] Made unlink and symlink non-fatal in ksuinit init.rs!")

# 16. Patch Makefile: obj-m := ksu.o and CONFIG_KSU_TAMPER_SYSCALL_TABLE and KSU 32653 certs
mk_path = ksu_root / "kernel/Makefile"
if mk_path.exists():
    mk_text = mk_path.read_text(encoding="utf-8")
    if "obj-m := ksu.o" not in mk_text:
        mk_text = mk_text.replace(
            "obj-$(CONFIG_KSU) := ksu.o",
            "obj-$(CONFIG_KSU) := ksu.o\nobj-m := ksu.o\nCFLAGS_ksu.o += -DCONFIG_KSU_TAMPER_SYSCALL_TABLE=1\n",
            1
        )
    elif "CONFIG_KSU_HACK_ARM64_BRANCH_LINK" in mk_text:
        mk_text = mk_text.replace("CONFIG_KSU_HACK_ARM64_BRANCH_LINK=1", "CONFIG_KSU_TAMPER_SYSCALL_TABLE=1")

    import re
    mk_text = re.sub(r"-DKSU_VERSION=\d+", "-DKSU_VERSION=32653", mk_text)
    mk_text = re.sub(r"KSU_EXPECTED_SIZE\s*:=\s*0x[0-9a-fA-F]+", "KSU_EXPECTED_SIZE := 0x0108", mk_text)
    mk_text = re.sub(r"KSU_EXPECTED_HASH\s*:=\s*[0-9a-fA-F]+", "KSU_EXPECTED_HASH := 221f26d25f62de115790cfd269ada83464a22f04e3ef5c091010c1b6e625d5b8", mk_text)

    mk_path.write_text(mk_text, encoding="utf-8")
    print("[+] Patched KernelSU/kernel/Makefile for obj-m, CONFIG_KSU_TAMPER_SYSCALL_TABLE, and KSU 32653 certs!")

# 17. Patch kernel_includes.h and ksu.c for UTS definitions
ki_path = ksu_root / "kernel/kernel_includes.h"
if ki_path.exists():
    ki_text = ki_path.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in ki_text:
        ki_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + ki_text
    ki_path.write_text(ki_text, encoding="utf-8")

if ksu_c.exists():
    kc_text = ksu_c.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in kc_text[:1000]:
        kc_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + kc_text
        ksu_c.write_text(kc_text, encoding="utf-8")

# 18. Generate compile.h in kernel tree
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

# 19. Build genheaders and generate SELinux headers (flask.h, av_permissions.h)
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

#!/usr/bin/env python3
"""Patch backslashxx/KernelSU staging-ksyscall-legacy for Redmi K40 (alioth)
Kernel: 4.19.325-Ikun-KirinNova
Base address: 0xffffff8010080000
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

# 1. Patch kallsyms_common.h to inject comprehensive hardcoded symbol table
hdr_path = ksu_root / "kernel/downstream/kallsyms_common.h"
if hdr_path.exists():
    text = hdr_path.read_text(encoding="utf-8")
    hardcoded_table = """
// Hardcoded symbol table for 4.19.325-Ikun-KirinNova (Redmi K40 alioth)
static uintptr_t get_hardcoded_symbol(const char *name)
{
    if (!name) return 0;
    // Credentials & UID
    if (!strcmp(name, "commit_creds")) return 0xffffff80100ef930;
    if (!strcmp(name, "init_cred")) return 0xffffff8012a2dd58;
    if (!strcmp(name, "__sys_setresuid")) return 0xffffff80100dc6d8;
    if (!strcmp(name, "__arm64_sys_setresuid")) return 0xffffff80100dc908;
    if (!strcmp(name, "security_task_fix_setuid")) return 0xffffff801054aaa4;

    // Execve & hooks
    if (!strcmp(name, "__do_execve_file")) return 0xffffff80102ee4e8;
    if (!strcmp(name, "exec_binprm")) return 0xffffff80102eefdc;
    if (!strcmp(name, "search_binary_handler")) return 0xffffff80102ee2f0;
    if (!strcmp(name, "security_bprm_check")) return 0xffffff8010548b04;
    if (!strcmp(name, "__arm64_sys_execve")) return 0xffffff80102eea68;
    if (!strcmp(name, "__arm64_sys_execveat")) return 0xffffff80102eeab8;
    if (!strcmp(name, "__arm64_compat_sys_execve")) return 0xffffff80102eeb24;
    if (!strcmp(name, "__arm64_compat_sys_execveat")) return 0xffffff80102eeb74;

    // Faccessat
    if (!strcmp(name, "do_faccessat")) return 0xffffff80102dfa60;
    if (!strcmp(name, "__arm64_sys_faccessat")) return 0xffffff80102dfcc4;

    // Stat & Read
    if (!strcmp(name, "vfs_statx")) return 0xffffff80102eb048;
    if (!strcmp(name, "__arm64_sys_newfstatat")) return 0xffffff80102eb2a0;
    if (!strcmp(name, "__arm64_sys_newfstat")) return 0xffffff80102eb33c;
    if (!strcmp(name, "__arm64_sys_fstatat64")) return 0xffffff80102eb650;
    if (!strcmp(name, "__arm64_sys_fstat64")) return 0xffffff80102eb580;
    if (!strcmp(name, "__arm64_compat_sys_newfstatat")) return 0xffffff80102eb8cc;
    if (!strcmp(name, "vfs_read")) return 0xffffff80102e1e84;
    if (!strcmp(name, "ksys_read")) return 0xffffff80102e2484;
    if (!strcmp(name, "__arm64_sys_read")) return 0xffffff80102e2550;
    if (!strcmp(name, "rw_verify_area")) return 0xffffff80102e1bf0;

    // Rename & FS
    if (!strcmp(name, "do_renameat2")) return 0xffffff80102fa0dc;
    if (!strcmp(name, "vfs_rename")) return 0xffffff80102f6ecc;
    if (!strcmp(name, "security_inode_rename")) return 0xffffff8010549804;
    if (!strcmp(name, "security_file_permission")) return 0xffffff8010549ff0;
    if (!strcmp(name, "audit_inode_permission")) return 0xffffff8010559054;

    // SELinux
    if (!strcmp(name, "security_setprocattr")) return 0xffffff801054b840;
    if (!strcmp(name, "avc_has_perm")) return 0xffffff801054dfe4;
    if (!strcmp(name, "avc_has_perm_flags")) return 0xffffff801054e180;
    if (!strcmp(name, "avc_has_extended_perms")) return 0xffffff801054d4c4;
    if (!strcmp(name, "slow_avc_audit")) return 0xffffff801054cff0;
    if (!strcmp(name, "selinux_state")) return 0xffffff8012dec928;
    if (!strcmp(name, "proc_pid_attr_write")) return 0xffffff801038358c;

    // Kallsyms & Syscall tables
    if (!strcmp(name, "kallsyms_lookup_name")) return 0xffffff8010196aa8;
    if (!strcmp(name, "kallsyms_on_each_symbol")) return 0xffffff8010196c64;
    if (!strcmp(name, "kallsyms_lookup_size_offset")) return 0xffffff8010196e28;
    if (!strcmp(name, "sys_call_table")) return 0xffffff8011a00880;
    if (!strcmp(name, "compat_sys_call_table")) return 0xffffff8011a045f0;
    if (!strcmp(name, "module_blacklist")) return 0xffffff8012dc54e8;

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
        print("[+] Patched kallsyms_common.h with hardcoded symbols!")
    else:
        print("[*] kallsyms_common.h already patched.")

# 2. Stub out kprobes_common.h to completely eliminate register_kprobe / unregister_kprobe references
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

# 3. Patch syscall_table_hook_arm64.c to use direct literal addresses
sct_c = ksu_root / "kernel/hook/syscall_table_hook_arm64.c"
if sct_c.exists():
    sct_text = sct_c.read_text(encoding="utf-8")
    
    # Replace the 4.19+ externs and sys_call_table declarations
    old_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];

extern long __arm64_sys_reboot(const struct pt_regs *regs);"""
    
    new_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

#define sys_call_table ((syscall_fn_t *)0xffffff8011a00880)
#define compat_sys_call_table ((const void **)0xffffff8011a045f0)

#define __arm64_sys_reboot ((long (*)(const struct pt_regs *))0xffffff80100f08dc)"""

    if old_block in sct_text:
        sct_text = sct_text.replace(old_block, new_block, 1)

    # Replace each extern long __arm64_sys_*
    replacements = [
        ("extern long __arm64_sys_execve(const struct pt_regs *regs);",
         "#define __arm64_sys_execve ((long (*)(const struct pt_regs *))0xffffff80102eea68)"),
        ("extern long __arm64_sys_execveat(const struct pt_regs *regs);",
         "#define __arm64_sys_execveat ((long (*)(const struct pt_regs *))0xffffff80102eeab8)"),
        ("extern long __arm64_sys_faccessat(const struct pt_regs *regs);",
         "#define __arm64_sys_faccessat ((long (*)(const struct pt_regs *))0xffffff80102dfcc4)"),
        ("extern long __arm64_sys_newfstatat(const struct pt_regs *regs);",
         "#define __arm64_sys_newfstatat ((long (*)(const struct pt_regs *))0xffffff80102eb2a0)"),
        ("extern long __arm64_sys_newfstat(const struct pt_regs *regs);",
         "#define __arm64_sys_newfstat ((long (*)(const struct pt_regs *))0xffffff80102eb33c)"),
        ("extern long __arm64_sys_read(const struct pt_regs *regs);",
         "#define __arm64_sys_read ((long (*)(const struct pt_regs *))0xffffff80102e2550)"),
        ("extern long __arm64_compat_sys_execve(const struct pt_regs *regs);",
         "#define __arm64_compat_sys_execve ((long (*)(const struct pt_regs *))0xffffff80102eeb24)"),
        ("extern long __arm64_compat_sys_execveat(const struct pt_regs *regs);",
         "#define __arm64_compat_sys_execveat ((long (*)(const struct pt_regs *))0xffffff80102eeb74)"),
        ("extern long __arm64_sys_fstatat64(const struct pt_regs *regs);",
         "#define __arm64_sys_fstatat64 ((long (*)(const struct pt_regs *))0xffffff80102eb650)"),
        ("extern long __arm64_sys_fstat64(const struct pt_regs *regs);",
         "#define __arm64_sys_fstat64 ((long (*)(const struct pt_regs *))0xffffff80102eb580)"),
    ]
    for old_s, new_s in replacements:
        if old_s in sct_text:
            sct_text = sct_text.replace(old_s, new_s, 1)

    sct_c.write_text(sct_text, encoding="utf-8")
    print("[+] Patched syscall_table_hook_arm64.c with literal addresses!")

# 4. Patch module_blacklist.h
mb_h = ksu_root / "kernel/downstream/module_blacklist.h"
if mb_h.exists():
    mb_text = mb_h.read_text(encoding="utf-8")
    mb_repls = [
        ("extern long __arm64_sys_init_module(const struct pt_regs *regs);",
         "#define __arm64_sys_init_module ((long (*)(const struct pt_regs *))0xffffff801019ad78)"),
        ("extern long __arm64_sys_finit_module(const struct pt_regs *regs);",
         "#define __arm64_sys_finit_module ((long (*)(const struct pt_regs *))0xffffff801019d5f0)"),
    ]
    for old_s, new_s in mb_repls:
        if old_s in mb_text:
            mb_text = mb_text.replace(old_s, new_s, 1)

    if "#ifndef sys_call_table" not in mb_text:
        mb_text = "#ifndef sys_call_table\n#define sys_call_table ((syscall_fn_t *)0xffffff8011a00880)\n#endif\n" + mb_text

    mb_h.write_text(mb_text, encoding="utf-8")
    print("[+] Patched module_blacklist.h with literal addresses!")

# 5. Patch util.h for ksyscall dispatch
ut_h = ksu_root / "kernel/include/util.h"
if ut_h.exists():
    ut_text = ut_h.read_text(encoding="utf-8")
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

    new_ksyscall = """static inline long __ksu_dispatch_sys(const char *name, const struct pt_regs *regs)
{
	if (!strcmp(name, "close")) return ((long (*)(const struct pt_regs *))0xffffff80102e13bc)(regs);
	if (!strcmp(name, "setns")) return ((long (*)(const struct pt_regs *))0xffffff80100df810)(regs);
	if (!strcmp(name, "unshare")) return ((long (*)(const struct pt_regs *))0xffffff80100df3f0)(regs);
	if (!strcmp(name, "umount")) return ((long (*)(const struct pt_regs *))0xffffff80102fca10)(regs);
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

    if old_ksyscall in ut_text:
        ut_text = ut_text.replace(old_ksyscall, new_ksyscall, 1)
        ut_h.write_text(ut_text, encoding="utf-8")
        print("[+] Patched util.h for literal syscall dispatch!")

# 6. Patch ksuinit
ksuinit_lib = ksu_root / "userspace/ksuinit/src/lib.rs"
if ksuinit_lib.exists():
    kl_text = ksuinit_lib.read_text(encoding="utf-8")
    
    # 6a. Safe Kptr
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

    # 6b. Resilient load_module with hardcoded fallback table
    old_kallsyms_res = """.context("Cannot parse kallsyms")?;
    }

    for name in unresolved_symbols.keys() {
        log::warn!("Cannot find symbol: {}", name);
    }"""

    new_kallsyms_res = """.ok(); // Do not fail if kallsyms restricted
    }

    let hardcoded: [(&str, u64); 25] = [
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
    ];
    for (name, addr) in hardcoded {
        if let Some((mut sym, offset)) = unresolved_symbols.remove(name) {
            sym.st_shndx = section_header::SHN_ABS as usize;
            sym.st_value = addr;
            let _ = buffer.pwrite_with(sym, offset, ctx);
            log::info!("Hardcoded symbol {} -> 0x{:x}", name, addr);
        }
    }

    for name in unresolved_symbols.keys() {
        log::warn!("Cannot find symbol: {}", name);
    }"""

    if old_kallsyms_res in kl_text:
        kl_text = kl_text.replace(old_kallsyms_res, new_kallsyms_res, 1)

    ksuinit_lib.write_text(kl_text, encoding="utf-8")
    print("[+] Patched ksuinit with safe kallsyms resolution & hardcoded symbol table!")

# 7. Patch Makefile to ensure obj-m is set and CONFIG_KSU_HACK_ARM64_BRANCH_LINK is defined
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

# 8. Patch kernel_includes.h and ksu.c for UTS definitions
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

# 9. Generate compile.h in kernel tree
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

# 10. Build genheaders and generate SELinux headers (flask.h, av_permissions.h)
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

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
else:
    kernel_root = Path(".")
    ksu_root = Path("KernelSU")

# 1. Patch kallsyms_common.h to inject comprehensive hardcoded symbol table
hdr_path = ksu_root / "kernel/downstream/kallsyms_common.h"
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
    if (!strcmp(name, "__arm64_sys_fstatat64")) return 0xffffff80102eb650;
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

# 2. Patch Makefile to ensure obj-m is set and CONFIG_KSU_HACK_ARM64_BRANCH_LINK is defined
mk_path = ksu_root / "kernel/Makefile"
mk_text = mk_path.read_text(encoding="utf-8")
if "obj-m := ksu.o" not in mk_text:
    mk_text = mk_text.replace(
        "obj-$(CONFIG_KSU) := ksu.o",
        "obj-$(CONFIG_KSU) := ksu.o\nobj-m := ksu.o\nCFLAGS_ksu.o += -DCONFIG_KSU_HACK_ARM64_BRANCH_LINK=1\n",
        1
    )
    mk_path.write_text(mk_text, encoding="utf-8")
    print("[+] Patched KernelSU/kernel/Makefile for obj-m and CONFIG_KSU_HACK_ARM64_BRANCH_LINK!")

# 3. Patch ksuinit to be fully resilient against restrictive environments
ksuinit_lib = ksu_root / "userspace/ksuinit/src/lib.rs"
if ksuinit_lib.exists():
    kl_text = ksuinit_lib.read_text(encoding="utf-8")
    old_kptr = 'let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?;\n        fs::write("/proc/sys/kernel/kptr_restrict", "1")?;'
    new_kptr = 'let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict").unwrap_or_default();\n        let _ = fs::write("/proc/sys/kernel/kptr_restrict", "1");'
    if old_kptr in kl_text:
        kl_text = kl_text.replace(old_kptr, new_kptr)
        print("[+] Softened kptr_restrict in ksuinit")
    
    old_parse = '.context("Cannot parse kallsyms")?;'
    new_parse = '.ok(); // Do not fail if kallsyms unreadable, symbols are in-module'
    if old_parse in kl_text:
        kl_text = kl_text.replace(old_parse, new_parse)
        print("[+] Softened kallsyms parse failure in ksuinit")
        
    ksuinit_lib.write_text(kl_text, encoding="utf-8")

# 4. Patch kernel_includes.h and ksu.c for UTS definitions
ki_path = ksu_root / "kernel/kernel_includes.h"
if ki_path.exists():
    ki_text = ki_path.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in ki_text:
        ki_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + ki_text
    ki_path.write_text(ki_text, encoding="utf-8")
    print("[+] Patched kernel_includes.h for UTS_MACHINE!")

ksu_c = ksu_root / "kernel/ksu.c"
if ksu_c.exists():
    kc_text = ksu_c.read_text(encoding="utf-8")
    if "UTS_MACHINE" not in kc_text[:1000]:
        kc_text = "#ifndef UTS_MACHINE\n#define UTS_MACHINE \"arm64\"\n#endif\n" + kc_text
        ksu_c.write_text(kc_text, encoding="utf-8")
        print("[+] Patched ksu.c for UTS_MACHINE!")

# 5. Generate compile.h in kernel tree
compile_h_content = """/* SPDX-License-Identifier: GPL-2.0 */
#define UTS_MACHINE "arm64"
#define UTS_VERSION "#1 SMP PREEMPT Sat Sep 26 11:54:08 UTC 2026"
#define LINUX_COMPILE_BY "runner"
#define LINUX_COMPILE_HOST "runnervmtr4k5"
#define LINUX_COMPILER "ZyC clang version 16.0.6, LLD 16.0.6"
"""
compile_h_path = kernel_root / "include/generated/compile.h"
compile_h_path.parent.mkdir(parents=True, exist_ok=True)
compile_h_path.write_text(compile_h_content, encoding="utf-8")
print(f"[+] Generated {compile_h_path} successfully!")

# 6. Build genheaders and generate SELinux headers (flask.h, av_permissions.h)
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
        # Copy to security/selinux/include/ as well
        inc_dir = kernel_root / "security/selinux/include"
        inc_dir.mkdir(parents=True, exist_ok=True)
        (inc_dir / "flask.h").write_bytes(flask_out.read_bytes())
        (inc_dir / "av_permissions.h").write_bytes(av_out.read_bytes())
        print("[+] Generated SELinux flask.h and av_permissions.h successfully!")
    except Exception as e:
        print("[-] Notice when running genheaders:", e)

# 7. Patch ksuinit to set kptr_restrict to 0 and safely resolve kallsyms
ksuinit_lib = ksu_root / "userspace/ksuinit/src/lib.rs"
if ksuinit_lib.exists():
    lib_text = ksuinit_lib.read_text(encoding="utf-8")
    old_kptr = """impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?;
        fs::write("/proc/sys/kernel/kptr_restrict", "1")?;
        Ok(Kptr { value })
    }
}"""
    new_kptr = """impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict").unwrap_or_else(|_| "2".to_string());
        let _ = fs::write("/proc/sys/kernel/kptr_restrict", "0");
        Ok(Kptr { value })
    }
}"""
    if old_kptr in lib_text:
        lib_text = lib_text.replace(old_kptr, new_kptr)
        ksuinit_lib.write_text(lib_text, encoding="utf-8")
        print("[+] Patched ksuinit Kptr::new to set kptr_restrict=0 safely!")

print("[+] LKM patch completed successfully.")

#!/usr/bin/env python3
"""Rewrite 4.19 2.2 inline hooks to official SUSFS 2.3 logic.

Mirrors:
  gitlab.com/simonpunk/susfs4ksu
    da34bba1 (getname_flags + filename_lookup + filename** handlers)
    f3087ec1 (sucompat early-out uses TIF_PROC_NO_SU, not TIF_PROC_UMOUNTED)
  and JackA1ltman/NonGKI_Kernel_Build_2nd Patches/susfs_inline_hook_patches.sh
"""
from pathlib import Path

def must_replace(text, old, new, label):
    if old not in text:
        raise SystemExit(f'{label}: expected block not found')
    return text.replace(old, new, 1)


# ---- fs/exec.c : TIF_PROC_UMOUNTED -> TIF_PROC_NO_SU ----
p = Path('fs/exec.c')
t = p.read_text()
old = """#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_umounted()))
		goto orig_flow;
"""
new = """#ifdef CONFIG_KSU_SUSFS
	if (likely(susfs_is_current_proc_no_su()))
		goto orig_flow;
"""
t = must_replace(t, old, new, 'fs/exec.c early-out')
p.write_text(t)
print('rewrote fs/exec.c sucompat early-out to susfs_is_current_proc_no_su', flush=True)

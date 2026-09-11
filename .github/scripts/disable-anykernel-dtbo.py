#!/usr/bin/env python3
"""Stop AnyKernel3 from writing the dtbo partition.

Xiaomi SM8250 HyperOS/MIUI first-splash hangs are commonly caused by
flashing the kernel-built dtbo. Keep dtbo.img inside the zip so the
MIUI/AOSP file picker still works, but comment flash_generic dtbo.
"""
from pathlib import Path
import sys

build = Path("build_kernel.sh")
text = build.read_text()
needle = 'echo "[+] AnyKernel3 adjusted successfully."'
inject = needle + '''
    # Keep ROM/stock dtbo. Kernel-built dtbo on SM8250 hangs on first splash.
    sed -i 's/^flash_generic dtbo;/# flash_generic dtbo;/' anykernel/anykernel.sh
    sed -i 's/^flash_generic dtb;/# flash_generic dtb;/' anykernel/anykernel.sh || true
    if grep -qE '^flash_generic dtbo;' anykernel/anykernel.sh; then
        echo 'failed to disable AnyKernel dtbo flash' >&2
        exit 1
    fi
    echo "[*] Disabled AnyKernel dtbo flash"
    grep -n 'flash_generic' anykernel/anykernel.sh || true'''

if "Disabled AnyKernel dtbo flash" not in text:
    if needle not in text:
        raise SystemExit("cannot find AnyKernel3 adjusted marker")
    text = text.replace(needle, inject, 1)
    build.write_text(text)
    print("patched build_kernel.sh to skip dtbo flash")
else:
    print("build_kernel.sh already skips dtbo flash")

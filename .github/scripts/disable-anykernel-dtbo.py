#!/usr/bin/env python3
"""Stop AnyKernel3 from writing the dtbo partition.

AstideLabs AnyKernel3:
- master (A16 build_kernel.sh): dtbo flash is already commented
- kona  (A17 build_kernel.sh): flash_generic dtbo is ENABLED

A17 kona zip is what bricks first-splash. After that, an A16 zip that
does not flash dtbo cannot repair the partition. Patch both trees after
the AnyKernel clone/adjust line.
"""
from pathlib import Path

build = Path("build_kernel.sh")
text = build.read_text()
PATCH_MARK = "Disabled AnyKernel dtbo flash"

inject_block = r'''
    # SM8250 HyperOS/MIUI: kernel-built dtbo hangs on first splash.
    # Keep dtbo.img in the zip (AK3 existence check), but never flash it.
    if [ ! -f anykernel/anykernel.sh ]; then
        echo "[!] anykernel/anykernel.sh missing after clone" >&2
        exit 1
    fi
    sed -i \
      -e 's/^flash_generic dtbo;/# flash_generic dtbo;/' \
      -e 's/^flash_dtbo;/# flash_dtbo;/' \
      -e 's|^[[:space:]]*mv $AKHOME/kernels/$os/dtbo.img|# mv dtbo.img|' \
      anykernel/anykernel.sh
    echo "[*] Disabled AnyKernel dtbo flash"
    grep -nE 'flash_generic|flash_dtbo|dtbo.img' anykernel/anykernel.sh || true
    if grep -qE '^flash_generic dtbo;|^flash_dtbo;' anykernel/anykernel.sh; then
        echo "failed to disable AnyKernel dtbo flash" >&2
        exit 1
    fi
'''

if PATCH_MARK in text:
    print("build_kernel.sh already skips dtbo flash")
else:
    markers = [
        'echo "[*] AnyKernel3 adjusted successfully."',
        'echo "[+] AnyKernel3 adjusted successfully."',
        'echo "[+] AnyKernel3 cloned successfully."',
        'echo "[*] AnyKernel3 cloned successfully."',
    ]
    found = next((m for m in markers if m in text), None)
    if not found:
        raise SystemExit("cannot find AnyKernel3 clone/adjust marker in build_kernel.sh")
    build.write_text(text.replace(found, found + inject_block, 1))
    print("patched build_kernel.sh after:", found)

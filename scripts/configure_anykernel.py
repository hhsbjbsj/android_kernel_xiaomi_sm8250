#!/usr/bin/env python3
"""Require the reviewed AnyKernel installer to check the target device."""

import re
import sys
from pathlib import Path


def configure(device: str, template: Path) -> None:
    if not re.fullmatch(r"[a-z0-9_]+", device):
        raise ValueError("Invalid device codename")
    # README lists Xiaomi 11X under alioth; LineageOS's device tree confirms
    # TARGET_OTA_ASSERT_DEVICE := alioth,aliothin in BoardConfig.mk.
    # https://github.com/LineageOS/android_device_xiaomi_alioth/blob/lineage-24.0/BoardConfig.mk
    aliases = [device, "aliothin"] if device == "alioth" else [device]
    source = template.read_text()
    if len(re.findall(r"^do\.devicecheck=.*$", source, re.MULTILINE)) != 1:
        raise ValueError("Expected one do.devicecheck property in AnyKernel3")
    if len(re.findall(r"^device\.name1=.*$", source, re.MULTILINE)) != 1:
        raise ValueError("Expected one device.name1 property in AnyKernel3")
    source = re.sub(r"^do\.devicecheck=.*$", "do.devicecheck=1", source, flags=re.MULTILINE)
    source = re.sub(r"^device\.name(?:[2-9]|[1-9][0-9]+)=.*\n?", "", source, flags=re.MULTILINE)
    names = "\n".join(f"device.name{i}={name}" for i, name in enumerate(aliases, 1))
    source = re.sub(r"^device\.name1=.*$", names, source, flags=re.MULTILINE)
    template.write_text(source)
    print(f"AnyKernel3 device check enabled: {', '.join(aliases)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: configure_anykernel.py <device> <anykernel.sh>")
    configure(sys.argv[1], Path(sys.argv[2]))

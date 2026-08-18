#!/bin/bash
set -euo pipefail

DEVICE="${1:-lmi}"
TARGET_OS="${2:-aosp}"
DEFCONFIG="arch/arm64/configs/${DEVICE}_defconfig"
FRAGMENT="scene_ebpf.config"

if [[ ! -f "$DEFCONFIG" ]]; then
  echo "[!] Missing defconfig: $DEFCONFIG" >&2
  exit 1
fi
if [[ ! -f "$FRAGMENT" ]]; then
  echo "[!] Missing config fragment: $FRAGMENT" >&2
  exit 1
fi
if ! command -v pahole >/dev/null 2>&1; then
  echo "[!] pahole is required for CONFIG_DEBUG_INFO_BTF." >&2
  echo "[!] Debian/Ubuntu: install the dwarves package first." >&2
  exit 1
fi

PAHOLE_VERSION="$(pahole --version 2>/dev/null || true)"
echo "[*] Using ${PAHOLE_VERSION:-pahole}"

BACKUP="$(mktemp)"
cp "$DEFCONFIG" "$BACKUP"
restore_defconfig() {
  cp "$BACKUP" "$DEFCONFIG"
  rm -f "$BACKUP"
}
trap restore_defconfig EXIT

# build_kernel.sh regenerates .config from this defconfig and runs
# olddefconfig afterwards, so appending the fragment here is enough to make
# Kconfig resolve the requested dependencies for the selected device.
printf '\n# Scene eBPF capability fragment\n' >> "$DEFCONFIG"
cat "$FRAGMENT" >> "$DEFCONFIG"

chmod +x build_kernel.sh
./build_kernel.sh "$DEVICE" "$TARGET_OS"

OUT="out_${TARGET_OS}"
CFG="$OUT/.config"
VMLINUX="$OUT/vmlinux"

required=(
  CONFIG_BPF
  CONFIG_BPF_SYSCALL
  CONFIG_BPF_JIT
  CONFIG_CGROUPS
  CONFIG_CGROUP_BPF
  CONFIG_KALLSYMS
  CONFIG_KPROBES
  CONFIG_KPROBE_EVENTS
  CONFIG_PERF_EVENTS
  CONFIG_BPF_EVENTS
  CONFIG_DEBUG_INFO
  CONFIG_DEBUG_INFO_BTF
  CONFIG_SYSFS
)

for opt in "${required[@]}"; do
  if ! grep -qx "${opt}=y" "$CFG"; then
    echo "[!] Final .config is missing ${opt}=y" >&2
    exit 1
  fi
done

if [[ ! -s "$VMLINUX" ]]; then
  echo "[!] vmlinux was not produced" >&2
  exit 1
fi
if [[ ! -f "$OUT/kernel/bpf/sysfs_btf.o" ]]; then
  echo "[!] sysfs_btf.o was not built" >&2
  exit 1
fi
if [[ ! -f "$OUT/kernel/trace/bpf_trace.o" ]]; then
  echo "[!] bpf_trace.o was not built" >&2
  exit 1
fi

OBJCOPY="${OBJCOPY:-$HOME/zyc-clang/bin/llvm-objcopy}"
READELF="${READELF:-$HOME/zyc-clang/bin/llvm-readelf}"
if [[ ! -x "$OBJCOPY" ]]; then OBJCOPY="$(command -v llvm-objcopy || true)"; fi
if [[ ! -x "$READELF" ]]; then READELF="$(command -v llvm-readelf || true)"; fi

if [[ -z "$OBJCOPY" || -z "$READELF" ]]; then
  echo "[!] llvm-objcopy/llvm-readelf not found for BTF verification" >&2
  exit 1
fi

SECTIONS="$OUT/vmlinux.sections.txt"
"$READELF" -S "$VMLINUX" > "$SECTIONS"
if ! grep -q '\.BTF' "$SECTIONS"; then
  echo "[!] Final vmlinux has no .BTF section" >&2
  exit 1
fi

"$OBJCOPY" --dump-section .BTF="$OUT/vmlinux.btf" "$VMLINUX"
test -s "$OUT/vmlinux.btf"

echo "[+] Scene eBPF kernel capability build passed."
echo "[+] Embedded BTF: $OUT/vmlinux.btf"
echo "[+] Flashable ZIP:"
ls -1 APTKernel_*.zip 2>/dev/null || true

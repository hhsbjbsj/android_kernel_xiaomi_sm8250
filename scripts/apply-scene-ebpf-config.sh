#!/bin/sh
set -eu

DEVICE="${1:-}"
if [ -z "$DEVICE" ]; then
    echo "usage: $0 <device-codename>" >&2
    exit 2
fi

DEFCONFIG="arch/arm64/configs/${DEVICE}_defconfig"
FRAGMENT="arch/arm64/configs/scene_ebpf.config"
RESOLVER="tools/bpf/resolve_btfids/resolve_btfids"

[ -f "$DEFCONFIG" ] || { echo "missing $DEFCONFIG" >&2; exit 1; }
[ -f "$FRAGMENT" ] || { echo "missing $FRAGMENT" >&2; exit 1; }
[ -f "$RESOLVER" ] || { echo "missing $RESOLVER" >&2; exit 1; }

SYMS='CGROUPS SOCK_CGROUP_DATA CGROUP_BPF BPF BPF_SYSCALL BPF_JIT BPF_JIT_ALWAYS_ON BPF_EVENTS KPROBES KPROBE_EVENTS PERF_EVENTS FTRACE DEBUG_KERNEL DEBUG_INFO DEBUG_INFO_REDUCED DEBUG_INFO_SPLIT DEBUG_INFO_BTF KALLSYMS KALLSYMS_ALL IPV6'

TMP="${DEFCONFIG}.scene.tmp"
cp "$DEFCONFIG" "$TMP"
for sym in $SYMS; do
    sed -i -e "/^CONFIG_${sym}=/d" -e "/^# CONFIG_${sym} is not set$/d" "$TMP"
done

{
    cat "$TMP"
    printf '\n# Scene Port Hider by eBPF compatibility\n'
    cat "$FRAGMENT"
} > "$DEFCONFIG"
rm -f "$TMP"

chmod +x "$RESOLVER"

echo "Applied Scene eBPF config fragment to $DEFCONFIG"
echo "Enabled legacy BTF resolver compatibility stub: $RESOLVER"

#!/usr/bin/env python3
"""Inject boot extras into AstideLabs build_kernel.sh for SM8250 (alioth).

Stable configuration:
  - Re-Kernel + Re-Kernel network enabled (required by userspace Re-Kernel/Tombstone module)
  - Baseband-guard (BBG) enabled
  - Mobile-friendly TCP CC: Cubic as rock-solid power-friendly default, BBR/Westwood compiled
  - IO Schedulers: deadline default (stable, low overhead), kyber, bfq compiled
  - WireGuard and networking enhancements enabled
  - Ccache configured with 20G limit and compression for fast cached builds
  - NO intrusive driver source hacks or workqueue forcing (preserves 100% display/GPU stability)
"""

from pathlib import Path

build = Path('build_kernel.sh')
text = build.read_text(encoding='utf-8')

# Ensure Re-Kernel is enabled for both MIUI and AOSP (prevents userspace Re-Kernel daemon crash/spin loops)
text = text.replace(
    '-d REKERNEL \\\n            -d REKERNEL_NETWORK',
    '-e REKERNEL \\\n            -e REKERNEL_NETWORK',
)
text = text.replace('-d REKERNEL\n', '-e REKERNEL\n')
text = text.replace('-d REKERNEL_NETWORK\n', '-e REKERNEL_NETWORK\n')

# Enhance ccache settings in build_kernel.sh
ccache_marker = 'mkdir -p "$CCACHE_DIR"'
if ccache_marker in text and 'ccache -M 20G' not in text:
    text = text.replace(ccache_marker, ccache_marker + '\nexport CCACHE_COMPRESS=1\nccache -M 20G || true\nccache -s || true', 1)

needle = '    # We always need to re-evaluate dependencies because BBG is injected unconditionally'
inject = r'''    echo "[*] Injecting stable boot extras: net/TCP/Re-Kernel/IO/BBG"
    scripts/config --file "${OUT_DIR}/.config" -e BBG || true
    scripts/config --file "${OUT_DIR}/.config" -e REKERNEL -e REKERNEL_NETWORK || true

    scripts/config --file "${OUT_DIR}/.config" \
        -e NETFILTER -e NETFILTER_ADVANCED -e NETFILTER_XTABLES \
        -e NF_CONNTRACK -e NF_CONNTRACK_IPV4 -e NF_NAT -e NF_NAT_IPV4 \
        -e IP_NF_IPTABLES -e IP_NF_FILTER -e IP_NF_MANGLE -e IP_NF_NAT \
        -e IP_NF_TARGET_MASQUERADE -e IP_NF_TARGET_REDIRECT \
        -e NETFILTER_XT_MATCH_ADDRTYPE -e NETFILTER_XT_MATCH_CONNTRACK \
        -e NETFILTER_XT_MATCH_MULTIPORT -e NETFILTER_XT_MATCH_STATE \
        -e NETFILTER_XT_TARGET_MASQUERADE -e NETFILTER_XT_TARGET_TPROXY \
        -e NETFILTER_XT_TARGET_MARK -e NETFILTER_XT_MATCH_MARK \
        -e IP_SET -e NETFILTER_XT_SET -e IP_ADVANCED_ROUTER -e IP_MULTIPLE_TABLES \
        -e NF_TABLES -e NFT_NAT -e NFT_MASQ -e NFT_REDIR -e NFT_CT \
        -e NET_NS -e VETH -e BRIDGE -e BRIDGE_NETFILTER \
        -e TUN -e PPP -e PPP_MPPE -e CIFS -e NET_SCH_FQ -e NET_SCH_FQ_CODEL \
        -e WIREGUARD || true

    # TCP Congestion Control: Default to Cubic (stable, mobile power-friendly, avoids BBR continuous probing)
    scripts/config --file "${OUT_DIR}/.config" \
        -e TCP_CONG_ADVANCED -e TCP_CONG_BBR -e TCP_CONG_CUBIC \
        -e TCP_CONG_WESTWOOD -e TCP_CONG_BIC -e TCP_CONG_HTCP \
        -e DEFAULT_CUBIC --set-str DEFAULT_TCP_CONG cubic || true

    # IO Schedulers: Default to Deadline (stable, minimal CPU overhead for UFS 3.1)
    scripts/config --file "${OUT_DIR}/.config" \
        -e IOSCHED_DEADLINE -e IOSCHED_CFQ -e MQ_IOSCHED_DEADLINE \
        -e MQ_IOSCHED_KYBER -e IOSCHED_BFQ -e BFQ_GROUP_IOSCHED \
        -e DEFAULT_DEADLINE --set-str DEFAULT_IOSCHED deadline || true

    echo "[*] Extras injection completed successfully."

''' + needle

if 'Injecting stable boot extras: net/TCP/Re-Kernel/IO/BBG' not in text:
    if needle not in text:
        raise SystemExit('cannot find olddefconfig marker in build_kernel.sh')
    text = text.replace(needle, inject, 1)

build.write_text(text, encoding='utf-8')
print('patched build_kernel.sh extras with stable profile')
print('REKERNEL enabled in MIUI block:', '-e REKERNEL' in text and '-d REKERNEL' not in text)

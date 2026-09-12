#!/usr/bin/env python3
"""Inject boot extras into AstideLabs build_kernel.sh.

Enabled:
  - network enhance (ipset/nftables/cifs/xt extras)
  - BBR + common TCP CC (Brutal needs 5.10+, not ported)
  - Re-Kernel + Re-Kernel network on MIUI and AOSP
  - BBG already on in baseline
  - in-tree IO schedulers (ADIOS is 5.10+ blk-mq; use kyber/bfq/deadline)
Skipped:
  - Droidspaces
"""
from pathlib import Path

build = Path('build_kernel.sh')
text = build.read_text()

text = text.replace('-d REKERNEL \\\n            -d REKERNEL_NETWORK', '-e REKERNEL \\\n            -e REKERNEL_NETWORK')
text = text.replace('-d REKERNEL\n', '-e REKERNEL\n')
text = text.replace('-d REKERNEL_NETWORK\n', '-e REKERNEL_NETWORK\n')

needle = '    # We always need to re-evaluate dependencies because BBG is injected unconditionally'
inject = r'''    echo "[*] Injecting boot extras: net/BBR/Re-Kernel/IO/BBG"
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

    scripts/config --file "${OUT_DIR}/.config" \
        -e TCP_CONG_ADVANCED -e TCP_CONG_BBR -e TCP_CONG_CUBIC \
        -e TCP_CONG_WESTWOOD -e TCP_CONG_BIC -e TCP_CONG_HTCP \
        -e DEFAULT_BBR --set-str DEFAULT_TCP_CONG bbr || true

    scripts/config --file "${OUT_DIR}/.config" \
        -e IOSCHED_DEADLINE -e IOSCHED_CFQ -e MQ_IOSCHED_DEADLINE \
        -e MQ_IOSCHED_KYBER -e IOSCHED_BFQ -e BFQ_GROUP_IOSCHED \
        -e DEFAULT_DEADLINE --set-str DEFAULT_IOSCHED deadline || true

    echo "[*] extras: droidspaces=skipped brutal=needs-5.10 adios=4.19-kyber/bfq/deadline"

''' + needle

if 'Injecting boot extras: net/BBR/Re-Kernel/IO/BBG' not in text:
    if needle not in text:
        raise SystemExit('cannot find olddefconfig marker in build_kernel.sh')
    text = text.replace(needle, inject, 1)

build.write_text(text)
print('patched build_kernel.sh extras')
print('REKERNEL enabled in MIUI block:', '-e REKERNEL' in text and '-d REKERNEL' not in text)

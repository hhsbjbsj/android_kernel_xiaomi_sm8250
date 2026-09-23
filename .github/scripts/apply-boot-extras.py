#!/usr/bin/env python3
"""Inject power-saving boot extras into AstideLabs build_kernel.sh for SM8250 (alioth).

Optimizations:
  1. Fix Re-Kernel on MIUI:
     AstideLabs intentionally disables Re-Kernel on MIUI (-d REKERNEL -d REKERNEL_NETWORK)
     because MIUI's built-in Millet/MIGT framework conflicts with Re-Kernel, causing process
     freezing fighting and preventing CPU deep sleep (C-states/LPM).
     Re-Kernel is only enabled when building for AOSP.
  2. Power-efficient workqueues:
     Enable CONFIG_WQ_POWER_EFFICIENT and CONFIG_WQ_POWER_EFFICIENT_DEFAULT to route unbound
     workqueues to Cortex-A55 little cores rather than waking up big/prime cores.
  3. Disable aggressive Qualcomm CPU Boost:
     Disable CONFIG_CPU_BOOST to eliminate touch/input boost frequency spikes (which pegs
     CPU cores at 1.4-1.8GHz for 40-100ms on every screen tap/scroll). Modern EAS and
     Schedutil handle UI scaling smoothly without wasting ~300-500mW.
  4. Schedutil governor rate limit tuning:
     Increase UP_RATE_LIMIT from 500us to 1000us (filters out transient micro-spikes) and
     decrease DOWN_RATE_LIMIT to 10000us (accelerates ramp-down to low power freqs).
  5. Mobile-friendly TCP Congestion Control:
     Set default to Westwood (designed for wireless/lossy networks) instead of BBR.
     BBR keeps cellular modems (Qualcomm X55) from entering DRX low-power states due to
     frequent bandwidth probing packets. Keep BBR, Cubic, Westwood compiled.
  6. Lightweight I/O scheduler:
     Enable mq-deadline/kyber as default for UFS 3.1 storage; disable heavy BFQ to save
     CPU cycles on disk I/O.
  7. Baseband Guard (BBG) and essential Wireguard / networking retained.
"""

from pathlib import Path

build = Path('build_kernel.sh')
text = build.read_text(encoding='utf-8')

# Ensure MIUI block does NOT have REKERNEL enabled
# If someone replaced -d with -e previously, revert back to -d
text = text.replace(
    '-e REKERNEL \\\n            -e REKERNEL_NETWORK',
    '-d REKERNEL \\\n            -d REKERNEL_NETWORK',
)

needle = '    # We always need to re-evaluate dependencies because BBG is injected unconditionally'
inject = r'''    echo "[*] Injecting SM8250 power-saving extras (WQ_POWER_EFFICIENT, Westwood, mq-deadline, BBG)..."
    # Baseband-guard
    scripts/config --file "${OUT_DIR}/.config" -e BBG || true

    # Only enable REKERNEL for AOSP (preserve MIUI stock Millet/MIGT process freezer)
    if [ "$OS_TYPE" == "aosp" ]; then
        scripts/config --file "${OUT_DIR}/.config" -e REKERNEL -e REKERNEL_NETWORK || true
    else
        scripts/config --file "${OUT_DIR}/.config" -d REKERNEL -d REKERNEL_NETWORK || true
    fi

    # [Power 1] Power-efficient workqueues (keeps unbound work on little A55 cores)
    scripts/config --file "${OUT_DIR}/.config" \
        -e WQ_POWER_EFFICIENT \
        -e WQ_POWER_EFFICIENT_DEFAULT || true

    # [Power 2] Disable Qualcomm CPU touch boost (eliminates 1.4-1.8GHz spikes on every touch)
    scripts/config --file "${OUT_DIR}/.config" \
        -d CPU_BOOST || true

    # [Power 3] Tune Schedutil governor rate limits (less jittery up-scale, faster down-scale)
    scripts/config --file "${OUT_DIR}/.config" \
        --set-val SCHEDUTIL_UP_RATE_LIMIT 1000 \
        --set-val SCHEDUTIL_DOWN_RATE_LIMIT 10000 || true

    # [Power 4] TCP Congestion Control (Default to Westwood for mobile modem power saving; compile BBR/Cubic)
    scripts/config --file "${OUT_DIR}/.config" \
        -e TCP_CONG_ADVANCED -e TCP_CONG_WESTWOOD -e TCP_CONG_CUBIC \
        -e TCP_CONG_BBR -e TCP_CONG_BIC -e TCP_CONG_HTCP \
        -d DEFAULT_BBR -e DEFAULT_WESTWOOD \
        --set-str DEFAULT_TCP_CONG westwood || true

    # [Power 5] UFS 3.1 I/O Scheduler (use lightweight mq-deadline, avoid CPU-heavy BFQ)
    scripts/config --file "${OUT_DIR}/.config" \
        -e MQ_IOSCHED_DEADLINE -e MQ_IOSCHED_KYBER \
        -d IOSCHED_BFQ -d BFQ_GROUP_IOSCHED \
        -e DEFAULT_MQ_DEADLINE --set-str DEFAULT_IOSCHED mq-deadline || true

    # Network enhancements: WireGuard & essential netfilter
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
        -e NET_NS -e VETH -e TUN -e PPP -e PPP_MPPE \
        -e WIREGUARD || true

    echo "[*] Power-saving extras successfully configured."

''' + needle

if 'Injecting SM8250 power-saving extras' not in text:
    if needle not in text:
        raise SystemExit('cannot find olddefconfig marker in build_kernel.sh')
    text = text.replace(needle, inject, 1)

build.write_text(text, encoding='utf-8')
print('patched build_kernel.sh extras with power-saving profile')

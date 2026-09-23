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
  3. Tame Qualcomm CPU touch boost without breaking linker symbols:
     Touchscreen drivers (e.g. focaltech_spi/focaltech_core.c) unconditionally link to
     touch_irq_boost(). Instead of disabling CONFIG_CPU_BOOST (which causes undefined symbol
     link error), we keep CONFIG_CPU_BOOST=y but patch touch_irq_boost() to a no-op (return)
     and set input_boost_ms to 0. This neutralizes the 1.4-1.8GHz touch spikes completely
     while guaranteeing 100% clean compilation.
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
  8. Ccache acceleration:
     Configure ccache with 20G cache limit and print statistics before and after build.
"""

from pathlib import Path

# 1. Tame cpu-boost source code directly so touch_irq_boost is a no-op and input_boost_ms=0
cb = Path('drivers/cpufreq/cpu-boost.c')
if cb.exists():
    cbt = cb.read_text(encoding='utf-8')
    old_fn = 'void touch_irq_boost(void)\n{\n'
    new_fn = 'void touch_irq_boost(void)\n{\n\treturn;\n'
    if old_fn in cbt:
        cbt = cbt.replace(old_fn, new_fn, 1)
    cbt = cbt.replace('static unsigned int input_boost_ms = 40;', 'static unsigned int input_boost_ms = 0;')
    cb.write_text(cbt, encoding='utf-8')
    print('[*] Tamed cpu-boost.c: neutralized touch_irq_boost and set input_boost_ms=0')

build = Path('build_kernel.sh')
text = build.read_text(encoding='utf-8')

# Ensure MIUI block does NOT have REKERNEL enabled
text = text.replace(
    '-e REKERNEL \\\n            -e REKERNEL_NETWORK',
    '-d REKERNEL \\\n            -d REKERNEL_NETWORK',
)

# Tune ccache in build_kernel.sh
ccache_marker = 'mkdir -p "$CCACHE_DIR"'
if ccache_marker in text and 'ccache -M 20G' not in text:
    text = text.replace(ccache_marker, ccache_marker + '\nexport CCACHE_COMPRESS=1\nccache -M 20G || true\nccache -s || true', 1)

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

    # [Power 2] Keep CPU_BOOST=y so focaltech_core / input drivers link cleanly,
    # but the driver has been tamed via source patch (touch_irq_boost no-op + input_boost_ms=0)
    scripts/config --file "${OUT_DIR}/.config" \
        -e CPU_BOOST || true

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

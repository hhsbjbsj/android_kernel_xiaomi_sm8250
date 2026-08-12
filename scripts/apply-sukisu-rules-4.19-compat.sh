#!/usr/bin/env bash
set -euo pipefail

KSU_DIR="${1:?pass SukiSU source directory}"
RULES="$KSU_DIR/kernel/selinux/rules.c"
KSU_C="$KSU_DIR/kernel/ksu.c"
ROOT="$(cd "$KSU_DIR/.." && pwd)"

[[ -f "$RULES" ]] || { echo "missing $RULES" >&2; exit 1; }
[[ -f "$KSU_C" ]] || { echo "missing $KSU_C" >&2; exit 1; }
[[ "$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)" == "v4.1.2" ]] || {
  echo "this compatibility patch only supports SukiSU v4.1.2" >&2
  exit 1
}

# Fail closed against the exact legacy SELinux + arm64 stack-protector layout.
grep -Fq 'struct selinux_ss *ss;' "$ROOT/security/selinux/include/security.h"
grep -Fq 'struct policydb policydb;' "$ROOT/security/selinux/ss/services.h"
grep -Fq 'unsigned long __stack_chk_guard __ro_after_init;' "$ROOT/arch/arm64/kernel/process.c"
grep -Fq 'EXPORT_SYMBOL(__stack_chk_guard);' "$ROOT/arch/arm64/kernel/process.c"

python3 - "$RULES" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
marker = 'SUKISU_V412_SELINUX_STATE_419_COMPAT'
if marker not in text:
    old = '''static struct policydb *get_policydb(void)
{
    struct policydb *db;
    struct selinux_policy *policy = selinux_state.policy;
    db = &policy->policydb;
    return db;
}
'''
    new = '''static struct policydb *get_policydb(void)
{
    /* SUKISU_V412_SELINUX_STATE_419_COMPAT:
     * Linux 4.19 stores the active policydb directly in selinux_state.ss.
     */
    return &selinux_state.ss->policydb;
}
'''
    if text.count(old) != 1:
        raise SystemExit('unexpected SukiSU rules.c get_policydb layout')
    text = text.replace(old, new, 1)

for bad in ('selinux_state.policy', 'struct selinux_policy *policy'):
    if bad in text:
        raise SystemExit(f'newer SELinux state reference remains: {bad}')
if 'return &selinux_state.ss->policydb;' not in text:
    raise SystemExit('legacy SELinux state policydb access was not installed')

path.write_text(text, encoding='utf-8')
PY

python3 - "$KSU_C" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
marker = 'SUKISU_V412_STACK_GUARD_419_COMPAT'
if marker not in text:
    old_decl = '''#if defined(CONFIG_STACKPROTECTOR) && !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init
    __attribute__((visibility("hidden")));
#define NO_STACK_PROTECTOR_WORKAROUND __attribute__((no_stack_protector))
#else
#define NO_STACK_PROTECTOR_WORKAROUND
#endif
'''
    new_decl = '''/* SUKISU_V412_STACK_GUARD_419_COMPAT:
 * This arm64 4.19 tree already defines and exports __stack_chk_guard.
 * Do not provide or re-seed a second global canary from KernelSU.
 */
#if defined(CONFIG_STACKPROTECTOR) && !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#define NO_STACK_PROTECTOR_WORKAROUND __attribute__((no_stack_protector))
#else
#define NO_STACK_PROTECTOR_WORKAROUND
#endif
'''
    old_init = '''#if defined(CONFIG_STACKPROTECTOR) && !defined(CONFIG_STACKPROTECTOR_PER_TASK)
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
#endif
'''
    new_init = '''#if defined(CONFIG_STACKPROTECTOR) && !defined(CONFIG_STACKPROTECTOR_PER_TASK)
    /* Linux 4.19 arm64 owns and initializes the global stack canary. */
#endif
'''
    if text.count(old_decl) != 1:
        raise SystemExit('unexpected SukiSU stack guard declaration block')
    if text.count(old_init) != 1:
        raise SystemExit('unexpected SukiSU stack guard initialization block')
    text = text.replace(old_decl, new_decl, 1).replace(old_init, new_init, 1)

if 'unsigned long __stack_chk_guard __ro_after_init' in text:
    raise SystemExit('duplicate SukiSU __stack_chk_guard definition remains')
if '__stack_chk_guard = canary' in text:
    raise SystemExit('SukiSU stack canary re-seed remains')
if marker not in text:
    raise SystemExit('stack guard compatibility marker missing')

path.write_text(text, encoding='utf-8')
PY

git -C "$KSU_DIR" diff --check -- kernel/selinux/rules.c kernel/ksu.c

echo "Applied Linux 4.19 selinux_state and arm64 stack-canary compatibility to SukiSU v4.1.2"

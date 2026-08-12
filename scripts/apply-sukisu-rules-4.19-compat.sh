#!/usr/bin/env bash
set -euo pipefail

KSU_DIR="${1:?pass SukiSU source directory}"
RULES="$KSU_DIR/kernel/selinux/rules.c"
ROOT="$(cd "$KSU_DIR/.." && pwd)"

[[ -f "$RULES" ]] || { echo "missing $RULES" >&2; exit 1; }
[[ "$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)" == "v4.1.2" ]] || {
  echo "this compatibility patch only supports SukiSU v4.1.2" >&2
  exit 1
}

# Fail closed against the exact legacy SELinux layout used by this 4.19 tree.
grep -Fq 'struct selinux_ss *ss;' "$ROOT/security/selinux/include/security.h"
grep -Fq 'struct policydb policydb;' "$ROOT/security/selinux/ss/services.h"

python3 - "$RULES" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
marker = 'SUKISU_V412_SELINUX_STATE_419_COMPAT'
if marker in text:
    raise SystemExit(0)

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

git -C "$KSU_DIR" diff --check -- kernel/selinux/rules.c

echo "Applied Linux 4.19 selinux_state compatibility to SukiSU v4.1.2 rules.c"

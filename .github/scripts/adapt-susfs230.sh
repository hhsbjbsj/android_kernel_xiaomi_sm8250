#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-.}"
if [[ ! -f "$ROOT/include/linux/susfs.h" && -f "$ROOT/kernel/include/linux/susfs.h" ]]; then
  ROOT="$ROOT/kernel"
fi
cd "$ROOT"
export GITHUB_WORKSPACE="$ROOT"
exec > >(tee "$GITHUB_WORKSPACE/adapt-susfs230.log") 2>&1

echo "adapt-susfs230: cwd=$(pwd)"
test -f include/linux/susfs.h
test -f include/linux/susfs_def.h
test -f fs/susfs.c
test -f fs/exec.c
test -f fs/open.c
test -f fs/stat.c

already_23=0
if grep -Fq '#define SUSFS_VERSION "v2.3.0"' include/linux/susfs.h \
   && grep -Fq 'susfs_is_current_proc_no_su()' fs/exec.c \
   && grep -Fq 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' fs/open.c \
   && grep -Fq 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' fs/stat.c \
   && grep -Fq 'struct filename **filename' fs/open.c \
   && grep -Fq 'TIF_PROC_NO_SU' include/linux/susfs_def.h; then
  already_23=1
fi

if [[ "$already_23" -eq 1 && "${FORCE_GKI_SUSFS_OVERLAY:-0}" != "1" ]]; then
  echo '===== Keep in-tree 4.19 SUSFS 2.3 ====='
  echo 'AstideLabs already has getname_flags + filename_lookup + TIF_PROC_NO_SU.'
  echo 'Overlaying GKI 5.10 susfs.c here is what breaks first-stage init.'
  python3 -u .github/scripts/rewrite-susfs230-hooks.py || true
  {
    echo "base=${GITHUB_SHA:-unknown}"
    echo 'susfs_mode=keep-intree-2.3'
    echo 'susfs_overlay=skipped'
    echo 'hooks=already filename_lookup + no_su'
  } | tee "$GITHUB_WORKSPACE/adapt-susfs230-proof.txt"
  echo '[PASS] kept in-tree SUSFS 2.3 hooks, no GKI susfs.c overlay'
  exit 0
fi

echo '===== 2.2 baseline: keep 4.19 susfs.c, only lift TIF helpers + hook ABI ====='
GKI_BASE='https://gitlab.com/simonpunk/susfs4ksu/-/raw/gki-android12-5.10/kernel_patches'
mkdir -p "$GITHUB_WORKSPACE/.susfs23-upstream"
curl -fLSs "$GKI_BASE/include/linux/susfs_def.h" -o "$GITHUB_WORKSPACE/.susfs23-upstream/susfs_def.h"
curl -fLSs "$GKI_BASE/include/linux/susfs.h" -o "$GITHUB_WORKSPACE/.susfs23-upstream/susfs.h"
grep -Fq '#define TIF_PROC_NO_SU 34' "$GITHUB_WORKSPACE/.susfs23-upstream/susfs_def.h"

python3 -u - <<'PY'
from pathlib import Path
import os
ws = Path(os.environ['GITHUB_WORKSPACE'])
gki_d = (ws / '.susfs23-upstream/susfs_def.h').read_text()
d = Path('include/linux/susfs_def.h').read_text()
h = Path('include/linux/susfs.h').read_text()

# Keep the 4.19 susfs.c. Only bring 2.3 thread-flag helpers the new hooks need.
if 'TIF_PROC_NO_SU' not in d:
    needle = '#define TIF_PROC_UMOUNTED'
    insert = '''#define TIF_PROC_UMOUNTED 33
#define TIF_PROC_NO_SU 34
#define TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35
'''
    if needle in d:
        # replace first TIF_PROC_UMOUNTED define line if present without NO_SU
        lines = []
        skipped = False
        for line in d.splitlines(True):
            if (not skipped) and line.startswith('#define TIF_PROC_UMOUNTED') and 'ZYGOTE' not in line:
                lines.append(insert)
                skipped = True
                continue
            lines.append(line)
        d = ''.join(lines)
    else:
        d = d.replace('#define KSU_SUSFS_DEF_H', '#define KSU_SUSFS_DEF_H\n' + insert, 1)

def ensure_helper(text, name, body):
    if name in text:
        return text
    guard = '#endif // #ifndef KSU_SUSFS_DEF_H'
    if guard in text:
        return text.replace(guard, body + '\n' + guard, 1)
    return text + '\n' + body + '\n'

d = ensure_helper(d, 'susfs_is_current_proc_no_su', '''
static inline bool susfs_is_current_proc_no_su(void) {
	return (likely(test_thread_flag(TIF_PROC_NO_SU)));
}
static inline void susfs_set_current_proc_no_su(void) {
	set_thread_flag(TIF_PROC_NO_SU);
}
static inline void susfs_clear_current_proc_no_su(void) {
	clear_thread_flag(TIF_PROC_NO_SU);
}
''')

h = h.replace('#define SUSFS_VERSION "v2.2.0"', '#define SUSFS_VERSION "v2.3.0"')
if 'SUSFS_VERSION "v2.3.0"' not in h:
    raise SystemExit('failed to bump susfs.h to v2.3.0')

Path('include/linux/susfs_def.h').write_text(d)
Path('include/linux/susfs.h').write_text(h)
print('lifted TIF_PROC_NO_SU helpers; kept in-tree fs/susfs.c', flush=True)
PY

python3 -u .github/scripts/rewrite-susfs230-hooks.py

grep -Fq '#define SUSFS_VERSION "v2.3.0"' include/linux/susfs.h
grep -Fq 'susfs_is_current_proc_no_su()' fs/exec.c
grep -Fq 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' fs/open.c
grep -Fq 'filename_lookup(dfd, fname, lookup_flags, &path, NULL)' fs/stat.c

{
  echo "base=${GITHUB_SHA:-unknown}"
  echo 'susfs_mode=keep-4.19-susfs.c + hook-abi-2.3'
  echo 'susfs_overlay=headers-only'
  echo 'hooks=exec.c no_su; open.c/stat.c getname_flags+filename_lookup+filename**'
} | tee "$GITHUB_WORKSPACE/adapt-susfs230-proof.txt"

echo '[PASS] 2.3 hook ABI without replacing 4.19 susfs.c'

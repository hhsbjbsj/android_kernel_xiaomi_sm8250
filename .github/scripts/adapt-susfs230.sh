#!/usr/bin/env bash
set -Eeuo pipefail

cd "${GITHUB_WORKSPACE:-.}"
exec > >(tee "$GITHUB_WORKSPACE/adapt-susfs230.log") 2>&1

echo '===== Adapt in-tree SUSFS 2.1.0 -> 2.3.0 on Linux 4.19 ====='
test -f include/linux/susfs.h
test -f include/linux/susfs_def.h
test -f fs/susfs.c
grep -Fq '#define SUSFS_VERSION "v2.1.0"' include/linux/susfs.h
grep -Fq 'AS_FLAGS_SUS_PATH' include/linux/susfs_def.h

python3 -u - <<'PY'
from pathlib import Path

h = Path('include/linux/susfs.h')
hs = h.read_text()
old = '#define SUSFS_VERSION "v2.1.0"'
new = '#define SUSFS_VERSION "v2.3.0"'
if hs.count(old) != 1:
    raise SystemExit(f'susfs.h version anchor count={hs.count(old)}')
h.write_text(hs.replace(old, new, 1))
print('updated SUSFS_VERSION to v2.3.0', flush=True)

d = Path('include/linux/susfs_def.h')
ds = d.read_text()
if '#define TIF_PROC_UMOUNTED 33' not in ds:
    raise SystemExit('susfs_def.h missing TIF_PROC_UMOUNTED')
if '#define TIF_PROC_NO_SU 34' not in ds:
    if ds.count('#define TIF_PROC_UMOUNTED 33\n') != 1:
        raise SystemExit('cannot insert 2.3 TIF flags')
    ds = ds.replace(
        '#define TIF_PROC_UMOUNTED 33\n',
        '#define TIF_PROC_UMOUNTED 33\n'
        '#define TIF_PROC_NO_SU 34\n'
        '#define TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35\n',
        1,
    )
    d.write_text(ds)
    print('added TIF_PROC_NO_SU and TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT', flush=True)

def_text = Path('include/linux/susfs_def.h').read_text()
c_text = Path('fs/susfs.c').read_text()
if 'inode->i_mapping->flags' in def_text or 'inode->i_mapping->flags' in c_text:
    raise SystemExit('refused to switch 4.19 SUSFS flags onto i_mapping')
print('kept inode->i_state flag storage', flush=True)
PY

grep -Fq '#define SUSFS_VERSION "v2.3.0"' include/linux/susfs.h
! grep -Fq '#define SUSFS_VERSION "v2.1.0"' include/linux/susfs.h
grep -Fq '#define TIF_PROC_NO_SU 34' include/linux/susfs_def.h
grep -Fq '#define TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35' include/linux/susfs_def.h
grep -Fq 'AS_FLAGS_SUS_PATH' include/linux/susfs_def.h
! grep -Fq 'i_mapping->flags' include/linux/susfs_def.h
! grep -Fq 'i_mapping->flags' fs/susfs.c

{
  echo "base=$GITHUB_SHA"
  echo 'susfs_from=v2.1.0'
  echo 'susfs_to=v2.3.0'
  echo 'root=ReSukiSU'
  echo 'flag_storage=inode_i_state'
  echo 'kernel_git_source=untouched'
} | tee "$GITHUB_WORKSPACE/adapt-susfs230-proof.txt"

echo '[PASS] SUSFS 2.3.0 adapted onto the existing 4.19 2.1.0 port'

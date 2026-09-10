#!/usr/bin/env bash
set -Eeuo pipefail

cd "${GITHUB_WORKSPACE:-.}"
: "${RESUKISU_REF:?missing RESUKISU_REF}"
: "${TARGET_DEVICE:=${DEVICE:-alioth}}"

BUILD_SRC=build-miui.sh
BUILD_OUT="$GITHUB_WORKSPACE/build-resukisu-susfs230.sh"
test -f "$BUILD_SRC"

python3 -u - <<'PY'
import os
from pathlib import Path

src = Path('build-miui.sh').read_text()
start = src.find('#                       SukiSU-Ultra v4.1.2 Integration')
if start < 0:
    raise SystemExit('cannot find SukiSU integration block')
end = src.find('#                 End of SukiSU-Ultra v4.1.2 Integration')
if end < 0:
    raise SystemExit('cannot find end of SukiSU integration block')
end = src.find('\n', end)
ref = os.environ['RESUKISU_REF']
ws = os.environ['GITHUB_WORKSPACE']
replacement = f'''#                       ReSukiSU + SUSFS 2.3.0 Integration
# =============================================================================

KSU_ZIP_STR="NoKernelSU"
RESUKISU_REF="{ref}"

if [ "${{2:-}}" = "ksu" ]; then
    KSU_ENABLE=1
    KSU_ZIP_STR="ReSukiSU-SUSFS230"
else
    KSU_ENABLE=0
fi

echo "TARGET_DEVICE: ${{TARGET_DEVICE:-${{1:-alioth}}}}"

if [ "$KSU_ENABLE" -eq 1 ]; then
    echo
    echo "================================================================"
    echo "              Setting up ReSukiSU {ref}"
    echo "================================================================"
    curl -fLSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/{ref}/kernel/setup.sh" | bash -s -- "{ref}"
    test -d KernelSU/.git
    git -C KernelSU log -1 --oneline
    test -f KernelSU/kernel/Kconfig
    echo "[PASS] ReSukiSU {ref} integrated"
else
    echo "KSU is disabled"
fi

# =============================================================================
#                 End of ReSukiSU + SUSFS 2.3.0 Integration
'''
out = src[:src.rfind('\n', 0, start)+1] + replacement + src[end+1:]
Path(ws + '/build-resukisu-susfs230.sh').write_text(out)
print('wrote patched build script', flush=True)
PY

chmod +x "$BUILD_OUT"
bash -n "$BUILD_OUT"
grep -Fq 'ReSukiSU/ReSukiSU' "$BUILD_OUT"
! grep -Fq 'SukiSU-Ultra/SukiSU-Ultra' "$BUILD_OUT"
echo "patched_build=$BUILD_OUT"

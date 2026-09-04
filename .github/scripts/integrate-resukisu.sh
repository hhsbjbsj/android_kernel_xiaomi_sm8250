#!/usr/bin/env bash
set -Eeuo pipefail

cd "${GITHUB_WORKSPACE:-.}"
: "${RESUKISU_REF:?missing RESUKISU_REF}"

BUILD_SRC=build-miui.sh
BUILD_OUT="$GITHUB_WORKSPACE/build-resukisu-susfs230.sh"
test -f "$BUILD_SRC"

python3 -u - <<PY
from pathlib import Path
src = Path('build-miui.sh').read_text()
start = s = src.find('#                       SukiSU-Ultra v4.1.2 Integration')
if start < 0:
    raise SystemExit('cannot find SukiSU integration block')
end = src.find('#                 End of SukiSU-Ultra v4.1.2 Integration')
if end < 0:
    raise SystemExit('cannot find end of SukiSU integration block')
end = src.find('\n', end)
replacement = '''#                       ReSukiSU + SUSFS 2.3.0 Integration\n# =============================================================================\n\nKSU_ZIP_STR="NoKernelSU"\nRESUKISU_REF="${RESUKISU_REF}"\n\nif [ "${2:-}" = "ksu" ]; then\n    KSU_ENABLE=1\n    KSU_ZIP_STR="ReSukiSU-SUSFS230"\nelse\n    KSU_ENABLE=0\nfi\n\necho "TARGET_DEVICE: $TARGET_DEVICE"\n\nif [ "$KSU_ENABLE" -eq 1 ]; then\n    echo\n    echo "================================================================"\n    echo "              Setting up ReSukiSU ${RESUKISU_REF}"\n    echo "================================================================"\n    curl -fLSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/${RESUKISU_REF}/kernel/setup.sh" | bash -s -- "$RESUKISU_REF"\n    test -d KernelSU/.git\n    git -C KernelSU log -1 --oneline\n    test -f KernelSU/kernel/Kconfig\n    echo "[PASS] ReSukiSU ${RESUKISU_REF} integrated"\nelse\n    echo "KSU is disabled"\nfi\n\n# =============================================================================\n#                 End of ReSukiSU + SUSFS 2.3.0 Integration\n'''
out = src[:src.rfind('\n', 0, start)+1] + replacement + src[end+1:]
Path('$BUILD_OUT'.replace('$GITHUB_WORKSPACE', __import__('os').environ['GITHUB_WORKSPACE'])).write_text(out)
print('wrote patched build script', flush=True)
PY

chmod +x "$BUILD_OUT"
bash -n "$BUILD_OUT"
grep -Fq 'ReSukiSU/ReSukiSU' "$BUILD_OUT"
! grep -Fq 'SukiSU-Ultra/SukiSU-Ultra' "$BUILD_OUT"
echo "patched_build=$BUILD_OUT"

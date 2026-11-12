#!/usr/bin/env python3
"""Save actual build inputs/outputs without exporting environment or Git credentials."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def git_value(path, *args):
    if not (path / ".git").exists():
        return None
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def collect(root, output):
    script = (root / "build_kernel.sh").read_text()
    susfs_header = (root / "include/linux/susfs.h").read_text()
    susfs_match = re.search(r'^#define\s+SUSFS_VERSION\s+"([^"]+)"', susfs_header, re.MULTILINE)
    manifest = {
        "source_commit": git_value(root, "rev-parse", "HEAD"),
        "source_branch": git_value(root, "branch", "--show-current"),
        "susfs_version": susfs_match.group(1) if susfs_match else None,
        "dependencies": {},
        "targets": [],
        "archives": [],
    }
    for name in ("KernelSU", "Baseband-guard", "anykernel"):
        path = root / name
        manifest["dependencies"][name] = {
            "commit": git_value(path, "rev-parse", "HEAD"),
            "version": git_value(path, "describe", "--tags", "--always", "--dirty"),
        }
    # Only named, public build pins are recorded. Never copy .git/config,
    # remote URLs, environment dumps or downloaded authentication material.
    manifest["pins"] = dict(re.findall(
        r'^(BAKASU_REVISION|DROIDSPACES_XT_QTAGUID_SHA256|DROIDSPACES_CGROUP_SHA256)="([^"]+)"',
        script, re.MULTILINE))
    manifest["patches"] = {path.name: digest(path) for path in sorted((root / "scripts").glob("bakasu-*.patch"))}
    for directory in sorted(root.glob("out_*")):
        config = directory / ".config"
        if not directory.is_dir() or not config.is_file():
            continue
        target = {"output_directory": directory.name, "files": {}}
        target["ksu_enabled"] = "CONFIG_KSU=y" in config.read_text().splitlines()
        target["device_symbols"] = re.findall(r"^CONFIG_MACH_XIAOMI_([A-Z0-9_]+)=y$", config.read_text(), re.MULTILINE)
        destination = output / directory.name
        destination.mkdir(parents=True, exist_ok=True)
        # kernel.config is an exact copy of out_*/.config. The embedded
        # IKCONFIG uses stock-defconfig in this tree and is not authoritative.
        for source_name, saved_name in ((".config", "kernel.config"), ("System.map", "System.map")):
            source = directory / source_name
            if source.is_file():
                shutil.copyfile(source, destination / saved_name)
                target["files"][saved_name] = {"source": str(source.relative_to(root)), "sha256": digest(source)}
        manifest["targets"].append(target)
    for archive in sorted(root.glob("*.zip")):
        manifest["archives"].append({"name": archive.name, "sha256": digest(archive)})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return [manifest]


def release_body(manifests):
    lines = ["## Kernel build", "", "This release records the source and dependencies actually used by CI.", ""]
    commits = sorted({m["source_commit"] for m in manifests if m.get("source_commit")})
    for commit in commits:
        lines.append(f"- **Kernel commit:** `{commit}`")
    versions = sorted({m["susfs_version"] for m in manifests if m.get("susfs_version")})
    lines.append(f"- **SUSFS source version:** {', '.join(versions) or 'unavailable'} (enabled in KSU builds)")
    for name in ("KernelSU", "Baseband-guard", "anykernel"):
        builds = sorted({(d.get("commit"), d.get("version") or "") for m in manifests
                         if (d := m.get("dependencies", {}).get(name, {})).get("commit")})
        for commit, version in builds:
            label = "BakaSU" if name == "KernelSU" else name
            lines.append(f"- **{label}:** `{version}` / `{commit}`")
    lines += ["", "### Packages", "", "Use the package matching both your device and ROM. Device validation is enabled.", ""]
    for m in manifests:
        for archive in m.get("archives", []):
            lines.append(f"- `{archive['name']}` — SHA256 `{archive['sha256']}`")
    lines += ["", "CI diagnostics include the real `out_*/.config` (saved as `kernel.config`), `System.map` when available, and a dependency manifest.",
              "Compilation and packaging do not substitute for an on-device boot test.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("build-diagnostics"))
    parser.add_argument("--release-from", type=Path, help="Summarize downloaded diagnostic artifacts")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.release_from:
        manifests = [json.loads(path.read_text()) for path in sorted(args.release_from.glob("**/manifest.json"))]
        if not manifests:
            parser.error("No build manifests were downloaded")
    else:
        manifests = collect(Path.cwd(), args.output.resolve())
    (args.output / "release-body.md").write_text(release_body(manifests))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform into ./hayabusa/."""

import json
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
DEST_DIR = Path(__file__).resolve().parent.parent / "hayabusa"


def asset_pattern() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x64"
        return f"lin-{arch}-gnu"
    if system == "darwin":
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x64"
        return f"mac-{arch}"
    if system == "windows":
        if machine in ("arm64", "aarch64"):
            arch = "aarch64"
        elif machine in ("x86", "i386", "i686"):
            arch = "x86"
        else:
            arch = "x64"
        return f"win-{arch}"

    raise RuntimeError(f"Unsupported platform: {system} {machine}")


def fetch_latest_release() -> dict:
    req = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def pick_asset(release: dict, pattern: str) -> dict:
    candidates = [
        a for a in release["assets"]
        if pattern in a["name"] and "live-response" not in a["name"] and "all-platforms" not in a["name"]
    ]
    if not candidates:
        raise RuntimeError(f"No asset found matching pattern '{pattern}' in release {release.get('tag_name')}")
    return candidates[0]


def download(url: str, dest: Path) -> None:
    print(f"Downloading {url} ...")
    urllib.request.urlretrieve(url, dest)


def extract(archive: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest_dir)
    elif archive.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(archive) as tf:
            tf.extractall(dest_dir)
    else:
        raise RuntimeError(f"Unknown archive format: {archive}")


def link_stable_binary(dest_dir: Path) -> Path:
    """Point a stable ./hayabusa/hayabusa(.exe) path at the versioned binary."""
    is_windows = platform.system().lower() == "windows"
    stable_name = "hayabusa.exe" if is_windows else "hayabusa"
    stable_path = dest_dir / stable_name

    candidates = [
        p for p in dest_dir.iterdir()
        if p.is_file() and p.name.startswith("hayabusa-") and p.name != stable_name
    ]
    if not candidates:
        raise RuntimeError(f"No hayabusa binary found in {dest_dir}")
    binary = candidates[0]

    if stable_path.exists() or stable_path.is_symlink():
        stable_path.unlink()

    if is_windows:
        shutil.copy2(binary, stable_path)
    else:
        stable_path.symlink_to(binary.name)
        stable_path.chmod(0o755)

    return stable_path


def main() -> int:
    pattern = asset_pattern()
    print(f"Detected platform pattern: {pattern}")

    release = fetch_latest_release()
    asset = pick_asset(release, pattern)
    print(f"Selected asset: {asset['name']} ({release.get('tag_name')})")

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = DEST_DIR / asset["name"]
    download(asset["browser_download_url"], archive_path)

    extract(archive_path, DEST_DIR)
    archive_path.unlink()

    stable_path = link_stable_binary(DEST_DIR)
    print(f"Hayabusa extracted to {DEST_DIR}")
    print(f"Stable binary path: {stable_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

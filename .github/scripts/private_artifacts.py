#!/usr/bin/env python3
"""Encrypt private workflow files before they enter public Actions artifacts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def crypt(source: Path, destination: Path, decrypt: bool = False) -> None:
    key = os.environ.get("ARTIFACT_ENCRYPTION_KEY", "")
    if not key:
        raise ValueError("artifact encryption credential is unavailable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dependency-artifact-") as home:
        command = [
            "gpg", "--batch", "--yes", "--no-symkey-cache", "--pinentry-mode", "loopback",
            "--homedir", home, "--passphrase-fd", "0", "--output", str(destination),
        ]
        command += ["--decrypt"] if decrypt else ["--symmetric", "--cipher-algo", "AES256", "--force-mdc"]
        result = subprocess.run(command + [str(source)], input=key.encode(), capture_output=True)
        if result.returncode:
            destination.unlink(missing_ok=True)
            raise ValueError("encrypted artifact could not be authenticated or processed")
    destination.chmod(0o600)


def pack(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ValueError("artifact source directory is unavailable")
    with tempfile.TemporaryDirectory(prefix="dependency-pack-") as temporary:
        archive = Path(temporary) / "payload.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(source, arcname="payload", recursive=True)
        crypt(archive, destination)


def unpack(source: Path, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="dependency-unpack-") as temporary:
        archive = Path(temporary) / "payload.tar.gz"
        crypt(source, archive, decrypt=True)
        with tarfile.open(archive) as handle:
            for member in handle.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != "payload" or ".." in parts or member.issym() or member.islnk():
                    raise ValueError("encrypted artifact contains an unsafe archive member")
            handle.extractall(temporary, filter="data")
        payload = Path(temporary) / "payload"
        destination.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copytree(payload, destination, dirs_exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["pack", "unpack"])
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        (pack if args.operation == "pack" else unpack)(args.source, args.destination)
    except (ValueError, OSError, tarfile.TarError):
        print("Private artifact operation failed; no plaintext artifact was published.")
        return 1
    print("Private artifact operation completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

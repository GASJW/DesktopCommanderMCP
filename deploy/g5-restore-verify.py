#!/usr/bin/env python3
"""G5.2 independent OFF-VPS restore test: inspect and extract only allowlisted files.

Run on Gui-PC or another machine with the recovery identity and 'age' installed.
DO NOT run this verifier on the VPS. Does not install units or restart services.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ALLOWED = {
    "etc/systemd/system/vps-commander.service",
    "etc/systemd/system/vps-commander-executor.service",
    "etc/systemd/system/cloudflared-vps-commander.service",
    "etc/systemd/system/vps-commander.service.d/20-access.conf",
}

def fail(msg):
    raise SystemExit("G5_2_RESTORE_TEST=RED_" + msg)

def verify(encrypted, identity, expected_sha=None):
    if not encrypted.is_file() or not identity.is_file():
        fail("INPUT_MISSING")
    if expected_sha is not None:
        actual = hashlib.sha256(encrypted.read_bytes()).hexdigest()
        if actual != expected_sha:
            fail("CIPHER_DIGEST")
    if not shutil.which("age"):
        fail("AGE_NOT_INSTALLED")
    with tempfile.TemporaryDirectory(prefix="vpscommander-restore-") as tmp:
        root = Path(tmp)
        plain = root / "plain.tar.gz"
        result = subprocess.run(
            ["age", "--decrypt", "-i", str(identity), "-o", str(plain), str(encrypted)],
            capture_output=True, timeout=40, check=False
        )
        if result.returncode != 0:
            fail("DECRYPTION")
        actual_names = set()
        with tarfile.open(plain, "r:gz") as archive:
            for entry in archive:
                name = entry.name.removeprefix("./")
                if name not in ALLOWED or not entry.isfile() or entry.size > 256 * 1024:
                    fail("UNEXPECTED_TAR_ENTRY")
                if name in actual_names:
                    fail("DUPLICATE_ENTRY")
                actual_names.add(name)
                dest = root / "restored" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(entry)
                if source is None:
                    fail("ARCHIVE_DATA")
                dest.write_bytes(source.read())
        if actual_names != ALLOWED:
            fail("INCOMPLETE_SNAPSHOT")
        for item in ALLOWED:
            if not (root / "restored" / item).is_file():
                fail("MISSING_AFTER_EXTRACT")
    print("G5_2_RESTORE_TEST=GREEN")
    print("G5_2_RESTORED_FILE_COUNT=4")
    print("G5_2_RESTORE_WRITES_TO_SYSTEM=NO")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--encrypted", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--sha256", default=None)
    args = parser.parse_args()
    if args.sha256 and (len(args.sha256) != 64 or any(c not in "0123456789abcdef" for c in args.sha256)):
        fail("BAD_DIGEST_ARG")
    verify(args.encrypted, args.identity, args.sha256)

#!/usr/bin/env python3
"""Read-only official metadata / ISO verification; output is always regular files."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import zapdos as z
import debian

parser = argparse.ArgumentParser()
parser.add_argument("--download", action="store_true")
parser.add_argument("--build", action="store_true")
parser.add_argument("--arch", choices=["amd64", "arm64"], action="append")
args = parser.parse_args()
os.umask(0o077)
cache = z.ROOT / ".cache"
cache.mkdir(exist_ok=True, mode=0o700)
for arch in args.arch or ["amd64", "arm64"]:
    with tempfile.TemporaryDirectory(dir=cache) as directory:
        work = Path(directory)
        latest = debian.discover(arch, work)
        print(json.dumps(latest), flush=True)
        sums = work / "SHA512SUMS"
        original = sums.read_bytes()
        sums.write_bytes(b"X" + original[1:])
        try:
            z.verify_signature(work / "gnupg", sums, work / "SHA512SUMS.sign", debian.SIGNERS)
        except z.Error:
            print("PASS: a tampered official checksum file is rejected.", flush=True)
        else:
            raise AssertionError("Tampered checksum file accepted")
        finally:
            sums.write_bytes(original)
        if args.download or args.build:
            iso = debian.verified_iso(latest, cache)
        if args.build:
            # Disposable TEST credentials; no user identity or real credential is created.
            public = z.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", work / "test-key"])
            config = debian.configure(z.load_config(), None)
            config["ssh_public_keys"] = [(work / "test-key.pub").read_text().strip()]
            test_hash = (
                z.run(["mkpasswd", "--method=yescrypt", "--stdin"], data=b"vm-test-only\n")
                .decode()
                .strip()
            )
            output = cache / f"validation-{arch}.iso"
            output.unlink(missing_ok=True)
            debian.build_image(iso, latest, config, [test_hash, test_hash], "0" * 64, work, output)
            inspection = work / "inspection"
            inspection.mkdir()
            manifest = z.inspect_manifest(output, inspection)
            assert z.decision(manifest, latest, "0" * 64) == "skip"
            assert z.decision(manifest, latest, "1" * 64) == "write"
            print(f"Test-only ISO: {output}", flush=True)

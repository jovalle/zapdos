#!/usr/bin/env python3
"""UEFI/Secure Boot acceptance checks. Writes ONLY private regular VM/image files."""

import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import zapdos as z
import debian

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
parser.add_argument("--network", choices=["none", "offline", "online"], default="none")
parser.add_argument("--disks", type=int, choices=[0, 1, 2], default=1)
selection = parser.add_mutually_exclusive_group()
selection.add_argument("--select-first", action="store_true")
selection.add_argument("--select-last", action="store_true")
parser.add_argument(
    "--existing-esp", action="store_true", help="seed an ESP on the first, unselected virtual disk"
)
parser.add_argument("--legacy", action="store_true", help="amd64 BIOS rejection check")
parser.add_argument("--timeout", type=int, default=3600)
parser.add_argument(
    "--configured-secrets",
    action="store_true",
    help="read the configured admin/root yescrypt hashes as JSON on stdin; never log them",
)
args = parser.parse_args()
if args.legacy and args.arch != "amd64":
    parser.error("--legacy is an amd64-only rejection test")
if args.existing_esp and (args.disks != 2 or not args.select_last):
    parser.error("--existing-esp requires --disks 2 --select-last")
os.umask(0o077)
cache = z.ROOT / ".cache"
cache.mkdir(mode=0o700, exist_ok=True)
mode = "legacy" if args.legacy else args.network
log = cache / f"vm-{args.arch}-{mode}-{args.disks}.log"
result_path = log.with_name(log.stem + "-result.json")
result_path.unlink(missing_ok=True)


def sample(path):
    with path.open("rb") as file:
        start = file.read(2 * 1024 * 1024)
        file.seek(-2 * 1024 * 1024, os.SEEK_END)
        return hashlib.sha256(start + file.read()).hexdigest()


# Keep large ISOs in the host cache; nested VM sync writes use local container files.
with tempfile.TemporaryDirectory(prefix="vm-", dir=cache) as directory, tempfile.TemporaryDirectory(
    prefix="zapdos-disks-"
) as disk_directory:
    work = Path(directory)
    latest = debian.discover(args.arch, work)
    iso = debian.verified_iso(latest, cache)
    z.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", work / "test-key"])
    config = debian.configure(z.load_config(), None)
    config["ssh_public_keys"].append((work / "test-key.pub").read_text().strip())
    if args.configured_secrets:
        hashes = json.load(sys.stdin)
        if (
            not isinstance(hashes, list)
            or len(hashes) != 2
            or any(not isinstance(h, str) or not re.fullmatch(z.YESCRYPT, h) for h in hashes)
        ):
            raise z.Error("Expected two configured yescrypt hashes on stdin")
    else:
        password_hash = (
            z.run(["mkpasswd", "--method=yescrypt", "--stdin"], data=b"vm-test-only\n")
            .decode()
            .strip()
        )
        hashes = [password_hash, password_hash]
    image = work / "installer.iso"
    with patch.object(z, "newc", wraps=z.newc) as archive:
        debian.build_image(iso, latest, config, hashes, "0" * 64, work, image)
    preseed = archive.call_args.args[0]["preseed.cfg"][0]
    inspection = work / "inspection"
    inspection.mkdir()
    manifest = z.inspect_manifest(image, inspection)
    assert z.decision(manifest, latest, "0" * 64) == "skip"
    assert z.decision(manifest, latest, "1" * 64) == "write"
    console = "ttyS0" if args.arch == "amd64" else "ttyAMA0"
    grub = work / "test-grub.cfg"
    boot = "install.amd" if args.arch == "amd64" else "install.a64"
    grub.write_text(
        f"set default=0\nset timeout=1\nmenuentry 'VM TEST ONLY' {{\n linux /{boot}/vmlinuz auto=true priority=critical DEBIAN_FRONTEND=text --- console={console},115200n8\n initrd /{boot}/initrd.gz\n}}\n"
    )
    # The VM-only late wrapper installs a root verifier for the next normal boot.
    # Preserve production account hashes; the temporary SSH key only grants test access.
    user = config["username"]
    check_args = " ".join(
        shlex.quote(config[key]) for key in ("username", "timezone", "locale", "keyboard")
    )
    service = f"""[Unit]
After=ssh.service network.target
[Service]
Type=oneshot
ExecStart=/bin/sh /usr/local/lib/zapdos/vm-check.sh {check_args}
StandardOutput=tty
StandardError=tty
TTYPath=/dev/{console}
[Install]
WantedBy=multi-user.target
"""
    wrapper = """#!/bin/sh
set -eu
/bin/sh /zapdos/late.sh
mkdir -p /target/usr/local/lib/zapdos
cp /zapdos/vm-check.sh /zapdos/vm-expected /zapdos/vm-keys /target/usr/local/lib/zapdos/
chmod 600 /target/usr/local/lib/zapdos/vm-*
cp /zapdos/vm-acceptance.service /target/etc/systemd/system/
in-target systemctl enable vm-acceptance.service
"""
    # Read the already rendered preseed rather than duplicating production template rendering.
    original = b"/bin/sh /zapdos/late.sh || /bin/sh /zapdos/stop.sh"
    assert preseed.count(original) == 1, "Unknown production late-command layout"
    preseed = preseed.replace(original, b"/bin/sh /zapdos/vm-late.sh || /bin/sh /zapdos/stop.sh")
    extra = {
        "preseed.cfg": preseed,
        "zapdos/vm-late.sh": wrapper.encode(),
        "zapdos/vm-check.sh": (z.ROOT / "tests/harness/vm-check.sh").read_bytes(),
        "zapdos/vm-expected": f"{user}:{hashes[0]}\nroot:{hashes[1]}\n".encode(),
        "zapdos/vm-keys": ("\n".join(config["ssh_public_keys"]) + "\n").encode(),
        "zapdos/vm-acceptance.service": service.encode(),
    }
    with (work / "custom-initrd.gz").open("ab") as initrd:
        initrd.write(
            gzip.compress(
                z.newc({name: (data, stat.S_IFREG | 0o600) for name, data in extra.items()}),
                mtime=0,
            )
        )
    serial_image = work / "serial.iso"
    z.run(
        [
            "xorriso",
            "-abort_on",
            "FAILURE",
            "-indev",
            image,
            "-outdev",
            serial_image,
            "-boot_image",
            "any",
            "replay",
            "-map",
            grub,
            "/boot/grub/grub.cfg",
            "-map",
            work / "custom-initrd.gz",
            f"/{boot}/initrd.gz",
            "-commit",
            "-end",
        ]
    )
    if args.arch == "amd64":
        code = Path("/usr/share/OVMF/OVMF_CODE_4M.ms.fd")
        variables = Path("/usr/share/OVMF/OVMF_VARS_4M.ms.fd")
        command = [
            "qemu-system-x86_64",
            "-machine",
            "q35,smm=on",
            "-global",
            "driver=cfi.pflash01,property=secure,value=on",
            "-cpu",
            "max",
        ]
    else:
        code = Path("/usr/share/AAVMF/AAVMF_CODE.ms.fd")
        variables = Path("/usr/share/AAVMF/AAVMF_VARS.ms.fd")
        command = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max"]
    if not code.exists() or not variables.exists():
        raise SystemExit("Microsoft-enrolled Secure Boot test firmware not available")
    shutil.copyfile(variables, work / "vars.fd")
    command += [
        "-accel",
        "tcg,tb-size=64",
        "-m",
        "2048",
        "-smp",
        "2",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
    ]
    if not args.legacy:
        command += [
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive",
            f"if=pflash,format=raw,file={work}/vars.fd",
        ]
    else:
        command = [
            arg
            for arg in command
            if arg not in ("-global", "driver=cfi.pflash01,property=secure,value=on")
        ]
        command += ["-qmp", f"unix:{work}/monitor.sock,server=on,wait=off"]
    usb_index = len(command)
    usb_args = [
        "-device",
        "qemu-xhci",
        "-drive",
        f"if=none,id=usb,format=raw,readonly=on,file={serial_image}",
        "-device",
        "usb-storage,drive=usb,bootindex=1",
    ]
    command += usb_args
    targets = []
    for i in range(args.disks):
        target = Path(disk_directory) / f"target-{i}.raw"
        with target.open("xb") as file:
            file.truncate(24 * 1024**3)
        targets.append(target)
        command += [
            "-drive",
            f"if=none,id=disk{i},format=raw,file={target}",
            "-device",
            f"virtio-blk-pci,drive=disk{i},bootindex={i+2}",
        ]
    before = [sample(target) for target in targets]
    if args.existing_esp:
        z.run(["sfdisk", targets[0]], data=b"label: gpt\nstart=2048, size=131072, type=U\n")
        esp = Path(disk_directory) / "keep-esp.img"
        z.run(["mkfs.vfat", "-F", "32", "-n", "KEEP_ESP", "-C", esp, "65536"])
        token = Path(disk_directory) / "KEEP.txt"
        token.write_text("The unselected disk must remain byte-for-byte unchanged.\n")
        z.run(["mcopy", "-i", esp, token, "::KEEP.txt"])
        with esp.open("rb") as source, targets[0].open("r+b") as target:
            target.seek(1024 * 1024)
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        before = [sample(target) for target in targets]
        unselected_hash = z.sha(targets[0])
    allocated_before = [target.stat().st_blocks for target in targets]
    ssh_port = None
    if args.network == "none":
        command += ["-nic", "none"]
    else:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            ssh_port = probe.getsockname()[1]
        net = f"user,id=n0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"
        net += ",restrict=on" if args.network == "offline" else ",hostname=dhcp-test"
        command += ["-netdev", net, "-device", "virtio-net-pci,netdev=n0"]
    print(
        f"Booting {args.arch} with Secure Boot, {args.disks} target(s), network={args.network}. Log: {log}",
        flush=True,
    )
    assert all(
        t.is_file() and not t.is_symlink() for t in targets
    ), "VM targets must be regular files"
    command += ["-no-reboot"]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    transcript = ""
    cursor = 0
    phase = "install"
    next_status = time.monotonic() + 60
    deadline = time.monotonic() + args.timeout

    def send(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    try:
        with log.open("wb") as logfile:
            while time.monotonic() < deadline:
                for key, mask in selector.select(timeout=1):
                    block = os.read(process.stdout.fileno(), 65536)
                    if not block:
                        continue
                    logfile.write(block)
                    logfile.flush()
                    transcript += block.decode(errors="replace")
                current = transcript[cursor:]
                if args.legacy and ("Zapdos requires UEFI" in current or "boot: " in current):
                    assert [sample(t) for t in targets] == before, "Legacy boot changed a target"
                    with socket.socket(socket.AF_UNIX) as monitor:
                        monitor.connect(str(work / "monitor.sock"))
                        stream = monitor.makefile("rwb")
                        stream.readline()
                        for request in (
                            {"execute": "qmp_capabilities"},
                            {
                                "execute": "screendump",
                                "arguments": {
                                    "filename": str(cache / "vm-amd64-legacy-screen.png"),
                                    "format": "png",
                                },
                            },
                        ):
                            stream.write((json.dumps(request) + "\n").encode())
                            stream.flush()
                            while True:
                                response = json.loads(stream.readline())
                                if "error" in response:
                                    raise AssertionError(response)
                                if "return" in response:
                                    break
                    print(
                        "PASS: BIOS does not start installation; targets remain untouched. VGA screenshot saved.",
                        flush=True,
                    )
                    break
                if args.disks == 1 and phase == "install" and "Prompt: '?' for help" in current:
                    raise AssertionError(
                        "Unattended installation asked a package configuration question"
                    )
                if "Secure Boot must be enabled" in current or "UEFI boot is required" in current:
                    raise AssertionError("Virtual firmware did not boot with Secure Boot enabled")
                if args.disks == 0 and "No eligible internal disk" in current:
                    print("PASS: zero targets halted before partitioning.", flush=True)
                    break
                if (
                    args.disks == 2
                    and phase == "install"
                    and "Select the internal disk to ERASE" in current
                ):
                    assert [sample(t) for t in targets] == before, "Disk changed before selection"
                    if args.existing_esp:
                        assert (
                            z.sha(targets[0]) == unselected_hash
                        ), "Existing ESP changed before selection"
                    allocated = [t.stat().st_blocks for t in targets]
                    assert (
                        allocated == allocated_before
                    ), f"Disk allocation changed before selection: {allocated_before} -> {allocated}"
                    print("PASS: ambiguous disks remained untouched before selection.", flush=True)
                    if not (args.select_first or args.select_last):
                        break
                    # cdebconf text select: STOP is 1, first disk is 2.
                    time.sleep(1)
                    send("2" if args.select_first else "3")
                    phase = "selected"
                    cursor = len(transcript)
                if "ZAPDOS STOPPED" in current:
                    # Installer screen window 2 is a root shell. Collect only public device/boot metadata.
                    process.stdin.write(b"\x012")
                    process.stdin.flush()
                    time.sleep(1)
                    send(
                        "cat /target/etc/fstab; cat /proc/mounts | grep /target/boot; ls /target/boot/efi/EFI; ls /target/boot/efi/EFI/debian; cat /tmp/zapdos-target"
                    )
                    until = time.monotonic() + 3
                    while time.monotonic() < until:
                        for key, mask in selector.select(timeout=0.2):
                            block = os.read(process.stdout.fileno(), 65536)
                            if block:
                                logfile.write(block)
                                logfile.flush()
                    raise AssertionError(
                        "Installer safety/late hook stopped; inspect the private VM log"
                    )
                if phase == "boot-installed" and "VM_ACCEPTANCE_FAIL" in current:
                    raise AssertionError(
                        "Installed-system account/policy checks failed; inspect VM log"
                    )
                if (
                    phase == "boot-installed"
                    and "\r\nVM_ACCEPTANCE_PASS" in current
                    and re.search(r"\blogin:", current)
                ):
                    assert "VM_ACCOUNTS_PASS" in current and "VM_POLICY_PASS" in current
                    expected_name = (
                        "dhcp-test" if args.network == "online" else "debian-[0-9a-f]{8}"
                    )
                    assert re.search(
                        rf"\b{expected_name} login:", current
                    ), "Wrong DHCP/fallback hostname"
                    print(
                        "PASS: configured admin/root hashes, unlocked local accounts, sudo membership, Secure Boot and SSH policy verified.",
                        flush=True,
                    )
                    if ssh_port:
                        check = subprocess.run(
                            [
                                "ssh",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "ConnectTimeout=10",
                                "-o",
                                "ConnectionAttempts=3",
                                "-i",
                                str(work / "test-key"),
                                "-p",
                                str(ssh_port),
                                user + "@127.0.0.1",
                                "id -un; cat /var/log/zapdos-updates.log",
                            ],
                            capture_output=True,
                            timeout=45,
                        )
                        assert check.returncode == 0 and check.stdout.startswith(
                            (user + "\n").encode()
                        ), "Admin SSH key login failed"
                        assert (
                            b"available upgrades installed"
                            if args.network == "online"
                            else b"completed from DVD"
                        ) in check.stdout
                        print(
                            "PASS: admin SSH public-key login and update/offline result verified.",
                            flush=True,
                        )
                    result = {
                        "arch": args.arch,
                        "admin": user,
                        "root": "enabled; configured hash matched",
                        "configured_secrets": args.configured_secrets,
                        "automatic_poweroff": True,
                        "boot_without_installer": True,
                        "secure_boot": True,
                        "admin_ssh": bool(ssh_port),
                        "result": "PASS",
                    }
                    result_path.write_text(json.dumps(result, indent=2) + "\n")
                    break
                if process.poll() is not None:
                    if phase in ("install", "selected"):
                        assert process.returncode == 0, "Installer VM exited with an error"
                        assert (
                            "Zapdos installation complete; powering off." in current
                        ), "Installer did not finish the production late hook"
                        assert re.search(
                            r"reboot: Power down", current
                        ), "Guest reset or exited instead of powering off"
                        if args.disks == 1:
                            assert (
                                "Select the internal disk to ERASE" not in current
                            ), "Single-disk installation prompted"
                        print(
                            "PASS: installation completed without input and the guest powered off (exit 0).",
                            flush=True,
                        )
                        selector.unregister(process.stdout)
                        process.stdout.close()
                        process.stdin.close()
                        # Keep the USB controller so PCI addresses (and Ethernet names) stay stable.
                        installed_command = (
                            command[: usb_index + 2] + command[usb_index + len(usb_args) :]
                        )
                        process = subprocess.Popen(
                            installed_command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                        )
                        selector.register(process.stdout, selectors.EVENT_READ)
                        phase = "boot-installed"
                        cursor = len(transcript)
                        continue
                    raise AssertionError(
                        f"VM exited before installed-system checks (exit {process.returncode})"
                    )
                if time.monotonic() > next_status:
                    print(
                        f"VM still running: phase={phase}; {len(transcript)} bytes captured.",
                        flush=True,
                    )
                    next_status = time.monotonic() + 60
            else:
                raise AssertionError(f"VM acceptance timed out in phase {phase}; inspect {log}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        selector.close()
    if args.disks == 2 and (args.select_first or args.select_last):
        chosen = 0 if args.select_first else 1
        other = 1 - chosen
        assert sample(targets[chosen]) != before[chosen], "Selected disk was not installed"
        assert sample(targets[other]) == before[other], "Unselected disk changed"
        assert (
            targets[other].stat().st_blocks == allocated_before[other]
        ), "Unselected disk received writes"
        if args.existing_esp:
            assert z.sha(targets[other]) == unselected_hash, "Unselected disk/ESP bytes changed"
        print("PASS: only the selected installation target changed.", flush=True)

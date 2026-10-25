import base64
import contextlib
import ctypes
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import zapdos as z
import debian

PUBLIC = (
    "ssh-ed25519 "
    + base64.b64encode(
        struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    ).decode()
)


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


def usb(path="/dev/sdb", **changes):
    node = {
        "path": path,
        "type": "disk",
        "size": 16_000_000_000,
        "tran": "usb",
        "rm": True,
        "ro": False,
        "hotplug": True,
        "serial": path,
        "wwn": None,
        "model": "Test USB",
        "maj:min": "8:16",
        "mountpoints": [None],
    }
    node.update(changes)
    return node


class Preparation(unittest.TestCase):
    def test_bar_has_fractional_steps_and_does_not_round_up_to_complete(self):
        with patch.object(z, "fancy", return_value=False):
            before, after = z.bar(1500, 10000), z.bar(1550, 10000)
            self.assertNotEqual(before.split()[0], after.split()[0])
            self.assertIn("15.0%", before)
            self.assertIn("15.5%", after)
            self.assertIn("99.9%", z.bar(9999, 10000))
            self.assertIn("100.0%", z.bar(10000, 10000))
            self.assertIn("5.0/10.0 MiB", z.bar(5 * 2**20, 10 * 2**20))
        with patch.object(z, "fancy", return_value=True):
            self.assertTrue(z.bar(5000, 10000, "33").startswith("\033[33m█"))
            self.assertTrue(z.bar(5000, 10000).startswith("\033[36m█"))

    def test_progress_keeps_refreshing_while_io_is_blocked(self):
        refreshed = threading.Event()

        class Screen(io.StringIO):
            def write(self, value):
                result = super().write(value)
                if self.getvalue().count("15.0%") >= 2:
                    refreshed.set()
                return result

        output = Screen()
        with patch.object(z, "fancy", return_value=True), contextlib.redirect_stdout(output):
            with z.spinner("Erasing USB") as s:
                s.detail = z.bar(1500, 10000)
                self.assertTrue(refreshed.wait(2), "No refresh during blocked I/O")
        self.assertNotIn("100.0%", output.getvalue())

    def test_copy_progress_counts_partial_writes_and_labels_flushes(self):
        phases, updates, colors = [], {}, {}
        real_write = os.write
        real_bar = z.bar

        @contextlib.contextmanager
        def status(label):
            phases.append(label)
            yield z.Spin()

        def progress(done, total, color="36"):
            updates.setdefault(phases[-1], []).append((done, total))
            colors.setdefault(phases[-1], set()).add(color)
            return real_bar(done, total, color)

        def flush(fd):
            self.assertIn(phases[-1], ("Flushing USB writes", "Saving completion record"))

        with tempfile.TemporaryDirectory() as directory:
            image, device = Path(directory) / "source", Path(directory) / "target"
            image.write_bytes(b"image" * 300)
            device.write_bytes(b"X" * 8192)
            with device.open("r+b") as target, patch.object(
                z, "spinner", side_effect=status
            ), patch.object(z, "bar", side_effect=progress), patch.object(
                z.os, "write", side_effect=lambda fd, data: real_write(fd, data[:512])
            ):
                self.assertEqual(z.copy_verify(target.fileno(), 8192, image, flush), z.sha(image))
        self.assertEqual(
            updates["Writing installer"], [(0, 1500), (512, 1500), (1024, 1500), (1500, 1500)]
        )
        self.assertEqual(updates["Erasing USB"][0], (0, 8192))
        self.assertEqual(updates["Erasing USB"][-1], (8192, 8192))
        self.assertEqual(updates["Verifying readback"][-1], (1500, 1500))
        self.assertEqual(
            colors,
            {"Erasing USB": {"33"}, "Writing installer": {"36"}, "Verifying readback": {"32"}},
        )
        self.assertEqual(
            phases,
            [
                "Erasing USB",
                "Writing installer",
                "Flushing USB writes",
                "Verifying readback",
                "Saving completion record",
            ],
        )

    def test_release_both_architectures_and_exact_dvd_one(self):
        for arch in ("amd64", "arm64"):
            sums = f"{'a'*128}  debian-13.7.0-{arch}-DVD-10.iso\n{'b'*128}  debian-13.7.0-{arch}-DVD-1.iso\n"
            latest = debian.release(sums, arch)
            self.assertEqual(latest["version"], "13.7.0")
            self.assertEqual(latest["sha512"], "b" * 128)
            with self.assertRaises(z.Error):
                debian.release(sums + sums, arch)
            with self.assertRaises(z.Error):
                debian.release("", arch)

    def test_versions_and_configuration(self):
        new = {"version": "13.7.0", "arch": "amd64"}
        old = dict(new, fingerprint="a" * 64)
        self.assertEqual(z.decision(old, new, "a" * 64), "skip")
        self.assertEqual(z.decision(old, new, "b" * 64), "write")
        self.assertEqual(z.decision(dict(old, version="13.6.0"), new, "a" * 64), "upgrade")
        self.assertEqual(z.version("13.10.0") > z.version("13.9.0"), True)
        for changes in ({"version": "13.8.0"}, {"arch": "arm64"}, {"version": "../bad"}):
            with self.assertRaises(z.Error):
                z.decision(dict(old, **changes), new, "a" * 64)

    def test_fingerprint_compares_logical_config_and_hash(self):
        config = {"ssh_public_keys": [PUBLIC]}
        before = z.fingerprint(config, "TEST-HASH")
        self.assertEqual(before, z.fingerprint(dict(config), "TEST-HASH"))
        self.assertNotEqual(before, z.fingerprint(config, "CHANGED-HASH"))
        self.assertNotEqual(before, z.fingerprint({"ssh_public_keys": []}, "TEST-HASH"))

    def test_linux_inventory_protects_nested_root_and_swap(self):
        root = usb(
            "/dev/sda",
            children=[
                {
                    "type": "part",
                    "mountpoints": [],
                    "children": [{"type": "lvm", "mountpoints": ["/"]}],
                }
            ],
        )
        nodes = [
            root,
            usb("/dev/sdc", children=[{"type": "part", "mountpoints": ["[SWAP]"]}]),
            usb("/dev/sdd", serial=None),
            usb("/dev/sde", ro=True),
            usb("/dev/sdf", tran="sata"),
            usb("/dev/sdg", children=[{"type": "part", "mountpoints": ["/work"]}]),
            usb("/dev/sdh", children=[{"type": "part", "mountpoints": ["/run/live/medium"]}]),
            usb(),
        ]
        inventory = z.linux_devices({"blockdevices": nodes}, [Path("/work/cache")])
        self.assertEqual([d["path"] for d in inventory if d["reason"] == "eligible"], ["/dev/sdb"])

    def test_mac_inventory(self):
        external = {
            "DeviceNode": "/dev/disk4",
            "DeviceIdentifier": "disk4",
            "WholeDisk": True,
            "Internal": False,
            "BusProtocol": "USB",
            "Writable": True,
            "TotalSize": 16_000_000_000,
            "MediaName": "Test",
            "DeviceTreePath": "IOService/USB/Test",
        }
        cases = [
            external,
            dict(external, DeviceNode="/dev/disk0", DeviceIdentifier="disk0", Internal=True),
            dict(external, DeviceNode="/dev/disk5", DeviceIdentifier="disk5"),
            dict(external, DeviceNode="/dev/disk6", DeviceIdentifier="disk6", DeviceTreePath=""),
        ]
        inventory = z.mac_devices(cases, {"disk5"})
        self.assertEqual(
            [d["path"] for d in inventory if d["reason"] == "eligible"], ["/dev/disk4"]
        )
        self.assertEqual(inventory[0]["raw"], "/dev/rdisk4")

    def test_preparation_paths_are_protected_through_filesystem_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory) / "TestVolume"
            mount.mkdir()
            alias = Path(directory) / "alias"
            alias.symlink_to(mount, target_is_directory=True)
            self.assertTrue(z.protects(str(alias), [mount / "cache"]))
            case_alias = mount.with_name("testvolume")
            if case_alias.exists():
                self.assertTrue(z.protects(str(mount), [case_alias / "cache"]))
            other = Path(directory) / "OtherVolume"
            other.mkdir()
            self.assertFalse(z.protects(str(other), [mount / "cache"]))

    def test_zero_one_multiple_usb_selection(self):
        devices = z.linux_devices({"blockdevices": [usb(), usb("/dev/sdc")]}, [])

        def answers(*values):
            replies = iter(values)
            return lambda prompt: next(replies)

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(z.Error):
                z.choose([])
            self.assertEqual(z.choose(devices[:1], answers("y"))["path"], "/dev/sdb")
            self.assertEqual(z.choose(devices, answers("2", "yes"))["path"], "/dev/sdc")
            self.assertEqual(z.choose(devices, answers("/dev/sdc", "Y"))["path"], "/dev/sdc")
            for selection in ("", "0", "3", "/dev/sda", "/dev/sdb1"):
                with self.assertRaisesRegex(z.Error, "nothing written"):
                    z.choose(devices, answers(selection, "y"))
            for confirm in ("", "n", "no", "sure"):
                with self.assertRaisesRegex(z.Error, "not confirmed"):
                    z.choose(devices[:1], answers(confirm))
                with self.assertRaisesRegex(z.Error, "not confirmed"):
                    z.choose(devices, answers("1", confirm))

    def test_unattended_selection_requires_the_exact_eligible_whole_disk(self):
        devices = z.linux_devices({"blockdevices": [usb(), usb("/dev/sdc")]}, [])
        with patch(
            "builtins.input", side_effect=AssertionError("unexpected prompt")
        ), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(z.choose(devices, device="/dev/sdc", yes=True), devices[1])
            for device in (None, "/dev/sda", "/dev/sdc1", "/dev/rsdc"):
                with self.assertRaises(z.Error):
                    z.choose(devices, device=device, yes=True)
            with self.assertRaises(z.Error):
                z.choose([dict(devices[1], reason="system")], device="/dev/sdc", yes=True)

    def test_unattended_preflight_fails_before_work_when_device_or_sudo_is_missing(self):
        args = type("Args", (), {"yes": True, "device": None})()
        with patch.object(z, "require") as dependencies:
            with self.assertRaisesRegex(z.Error, "requires --device"):
                z.prepare(args)
            dependencies.assert_not_called()
            args.device = "/dev/disk4"
            with patch.object(z.os, "geteuid", return_value=1000), patch.object(
                z, "run", side_effect=z.Error("sudo needs authentication")
            ) as run:
                with self.assertRaisesRegex(z.Error, "sudo needs authentication"):
                    z.prepare(args)
                run.assert_called_once_with(["sudo", "-n", "true"])
                dependencies.assert_not_called()

    def test_skip_and_decline_do_not_download_build_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            args = type(
                "Args", (), {"command": "prepare", "cache": Path(directory), "arch": "amd64"}
            )()
            os.chmod(directory, 0o700)
            selected = z.linux_devices({"blockdevices": [usb()]}, [])[0]
            new = {"version": "13.7.0", "arch": "amd64"}
            for old_version, answer in [("13.7.0", ""), ("13.6.0", ""), ("13.6.0", "no")]:
                old = dict(new, version=old_version, fingerprint="a" * 64)
                with contextlib.ExitStack() as stack:
                    for name, value in [
                        ("require", None),
                        ("run", b""),
                        ("load_config", {}),
                        ("set_password", None),
                        ("password_hash", "TEST"),
                        ("has_root_password", True),
                        ("fingerprint", "a" * 64),
                        ("inventory", [selected]),
                        ("choose", selected),
                        ("inspect_usb", old),
                    ]:
                        stack.enter_context(patch.object(z, name, return_value=value))
                    stack.enter_context(patch.object(debian, "discover", return_value=new))
                    never = [
                        stack.enter_context(patch.object(z, "write_usb")),
                        *(
                            stack.enter_context(patch.object(debian, name))
                            for name in ("verified_iso", "build_image")
                        ),
                    ]
                    stack.enter_context(patch("builtins.input", return_value=answer))
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    z.prepare(args)
                    for mock in never:
                        mock.assert_not_called()

    def test_accepted_upgrade_writes_only_selected_device(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            args = type(
                "Args",
                (),
                {
                    "command": "prepare",
                    "cache": Path(directory),
                    "arch": "arm64",
                    "yes": True,
                    "device": "/dev/sdc",
                },
            )()
            selected = z.linux_devices({"blockdevices": [usb("/dev/sdc")]}, [])[0]
            new = {"version": "13.7.0", "arch": "arm64"}
            with contextlib.ExitStack() as stack:
                for name, value in [
                    ("require", None),
                    ("run", b""),
                    ("load_config", {"username": "test-admin"}),
                    ("set_password", None),
                    ("fingerprint", "a" * 64),
                    ("inventory", [selected]),
                    ("choose", selected),
                    ("inspect_usb", dict(new, version="13.6.0", fingerprint="a" * 64)),
                    ("password_hash", "TEST"),
                    ("has_root_password", True),
                    ("revalidate", selected),
                ]:
                    stack.enter_context(patch.object(z, name, return_value=value))
                for name, value in [
                    ("discover", new),
                    ("verified_iso", Path(directory) / "vendor.iso"),
                    ("build_image", None),
                ]:
                    stack.enter_context(patch.object(debian, name, return_value=value))
                process = stack.enter_context(patch.object(z.subprocess, "Popen"))
                process.return_value.wait.return_value = 0
                stack.enter_context(
                    patch("builtins.input", side_effect=AssertionError("unexpected prompt"))
                )
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                z.prepare(args)
                command = process.call_args.args[0]
                self.assertEqual(
                    json.loads(command[command.index("--selected") + 1])["path"], "/dev/sdc"
                )
                if os.geteuid() != 0:
                    self.assertEqual(command[:2], ["sudo", "-n"])

    def test_revalidation_rejects_changed_or_protected_target(self):
        selected = z.linux_devices({"blockdevices": [usb()]}, [])[0]
        for other in (
            None,
            dict(selected, reason="system"),
            dict(selected, identity={"serial": "other"}),
        ):
            with patch.object(z, "inventory", return_value=[] if other is None else [other]):
                with self.assertRaises(z.Error):
                    z.revalidate(selected, [])

    def test_file_erase_write_readback_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            image, device = Path(directory) / "source", Path(directory) / "target"
            image.write_bytes(b"Debian-test-image" * 137)
            device.write_bytes(b"X" * 8192)
            with device.open("r+b") as target:
                self.assertEqual(
                    z.copy_verify(target.fileno(), 8192, image, lambda fd: None), z.sha(image)
                )
            self.assertEqual(
                device.read_bytes()[image.stat().st_size : -z.RECEIPT_SIZE],
                b"\0" * (8192 - image.stat().st_size - z.RECEIPT_SIZE),
            )
            self.assertTrue(device.read_bytes()[-z.RECEIPT_SIZE :].startswith(z.RECEIPT_MAGIC))
            with device.open("r+b") as target:

                def corrupt(fd):
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, b"WRONG")

                with self.assertRaisesRegex(z.Error, "mismatch"):
                    z.copy_verify(target.fileno(), 8192, image, corrupt)
            self.assertEqual(device.read_bytes()[-z.RECEIPT_SIZE :], b"\0" * z.RECEIPT_SIZE)
            with device.open("r+b") as target:
                before = device.read_bytes()
                with self.assertRaises(z.Error):
                    z.copy_verify(target.fileno(), 2, image, lambda fd: None)
                self.assertEqual(device.read_bytes(), before)

    def test_erase_clears_only_both_edges_of_large_media(self):
        with tempfile.TemporaryDirectory() as directory:
            image, device = Path(directory) / "source", Path(directory) / "target"
            image.write_bytes(b"I" * 100)
            device.write_bytes(b"X" * 32768)
            with device.open("r+b") as target, patch.object(z, "ERASE_EDGE", 8192):
                z.copy_verify(target.fileno(), 32768, image, lambda fd: None)
            data = device.read_bytes()
            self.assertEqual(data[:100], b"I" * 100)
            self.assertEqual(data[100:8192], b"\0" * 8092)
            self.assertEqual(data[8192:24576], b"X" * 16384)
            self.assertEqual(data[24576 : -z.RECEIPT_SIZE], b"\0" * (8192 - z.RECEIPT_SIZE))
            self.assertTrue(data[-z.RECEIPT_SIZE :].startswith(z.RECEIPT_MAGIC))

    def test_completion_and_later_integrity_are_required_for_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            image = work / "image"
            image.write_bytes(b"test ISO" * 100)
            raw = work / "usb"
            raw.write_bytes(b"\0" * 8192)
            selected = {"raw": str(raw), "size": 8192}
            old = {"schema": 1, "version": "13.7.0", "arch": "amd64", "fingerprint": "a" * 64}
            with patch.object(z, "inspect_manifest", side_effect=lambda *args: dict(old)):
                self.assertEqual(
                    z.decision(z.inspect_completed(selected, work), old, "a" * 64), "write"
                )
                with raw.open("r+b") as target:
                    z.copy_verify(target.fileno(), 8192, image, lambda fd: None)
                self.assertEqual(
                    z.decision(z.inspect_completed(selected, work), old, "a" * 64), "skip"
                )
                with raw.open("r+b") as target:
                    target.write(b"corrupt")
                with self.assertRaisesRegex(z.Error, "corrupt"):
                    z.inspect_completed(selected, work)
                for record in (
                    {"size": True, "sha256": "a" * 64},
                    {"size": 8192, "sha256": "a" * 64},
                    {"size": 800, "sha256": "bad"},
                    {},
                ):
                    with raw.open("r+b") as target:
                        target.seek(-z.RECEIPT_SIZE, os.SEEK_END)
                        target.write(
                            (z.RECEIPT_MAGIC + json.dumps(record).encode()).ljust(
                                z.RECEIPT_SIZE, b"\0"
                            )
                        )
                    with self.assertRaises(z.Error):
                        z.inspect_completed(selected, work)

    def test_source_failures_never_erase_and_mutation_never_marks_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            raw = work / "usb"
            raw.write_bytes(b"KEEP" * 2048)
            missing = work / "missing"
            empty = work / "empty"
            empty.touch()
            for source in (missing, empty, work):
                with raw.open("r+b") as target:
                    with self.assertRaises((z.Error, OSError)):
                        z.copy_verify(target.fileno(), 8192, source, lambda fd: None)
                self.assertEqual(raw.read_bytes(), b"KEEP" * 2048)
            image = work / "image"
            image.write_bytes(b"original")
            real_write = os.write

            def mutate(fd, data):
                if bytes(data).startswith(b"original"):
                    image.write_bytes(b"changed and longer")
                return real_write(fd, data)

            with raw.open("r+b") as target, patch.object(z.os, "write", side_effect=mutate):
                with self.assertRaisesRegex(z.Error, "changed"):
                    z.copy_verify(target.fileno(), 8192, image, lambda fd: None)
            self.assertEqual(raw.read_bytes()[-z.RECEIPT_SIZE :], b"\0" * z.RECEIPT_SIZE)

    def test_existing_partial_download_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "dvd.iso"
            partial = Path(directory) / "dvd.iso.part"
            partial.write_bytes(b"previous partial")
            response = io.BytesIO(b"new")
            response.url = "https://example.test/dvd.iso"
            with patch.object(z.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(FileExistsError):
                    z.download(response.url, destination)
            self.assertEqual(partial.read_bytes(), b"previous partial")
            self.assertFalse(destination.exists())

    def test_image_output_is_exclusive_and_failed_copies_leave_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / "source"
            source.write_bytes(b"verified ISO")
            output = work / "output"
            with patch.object(z.shutil, "copyfileobj", side_effect=OSError("test copy failure")):
                with self.assertRaises(OSError):
                    z.save_image(source, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(work.glob(".zapdos-*")), [])
            z.save_image(source, output)
            self.assertEqual(output.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(z.Error):
                z.save_image(source, output)
            link = work / "symlink"
            link.symlink_to(work / "missing")
            with self.assertRaises(z.Error):
                z.save_image(source, link)
            self.assertTrue(link.is_symlink())

    @unittest.skipUnless(shutil.which("xorriso"), "requires xorriso")
    def test_real_iso_manifest_with_virtual_usb_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            tree = work / "tree/zapdos"
            tree.mkdir(parents=True)
            manifest = {"schema": 1, "version": "13.7.0", "arch": "arm64", "fingerprint": "a" * 64}
            (tree / "manifest.json").write_text(json.dumps(manifest))
            image = work / "test.iso"
            z.run(["xorriso", "-as", "mkisofs", "-o", image, tree.parent])
            raw = work / "usb"
            capacity = image.stat().st_size + 1024 * 1024
            with raw.open("wb") as target:
                target.truncate(capacity)
            selected = {"raw": str(raw), "size": capacity}
            with raw.open("r+b") as target:
                z.copy_verify(target.fileno(), capacity, image, lambda fd: None)
            inspection = work / "inspection"
            inspection.mkdir()
            self.assertEqual(z.inspect_completed(selected, inspection), manifest)
            with raw.open("r+b") as target:
                target.seek(16 * 2048 + 1)
                target.write(b"BROKE")
            shutil.rmtree(inspection)
            inspection.mkdir()
            with self.assertRaisesRegex(z.Error, "corrupt"):
                z.inspect_completed(selected, inspection)

    def test_usb_manifest_rejects_symlinks_large_files_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            raw = work / "usb"
            raw.write_bytes(b"ISO")
            manifest = work / "old-manifest.json"
            with patch.object(
                z.subprocess,
                "run",
                return_value=type("Result", (), {"stderr": b"", "returncode": 0})(),
            ):
                manifest.symlink_to(raw)
                with self.assertRaises(z.Error):
                    z.inspect_manifest(raw, work)
                manifest.unlink()
                manifest.write_bytes(b"X" * 4097)
                with self.assertRaises(z.Error):
                    z.inspect_manifest(raw, work)
                manifest.write_text("{bad json")
                with self.assertRaises(z.Error):
                    z.inspect_manifest(raw, work)
                manifest.write_text(
                    json.dumps(
                        {
                            "schema": 1,
                            "version": "13.7.0",
                            "arch": "amd64",
                            "fingerprint": "a" * 64,
                            "untrusted_extra": "must not be returned",
                        }
                    )
                )
                self.assertNotIn("untrusted_extra", z.inspect_manifest(raw, work))

    def test_iso_inspection_uses_stdio_block_device_for_manifest_and_stock_label(self):
        for raw, expected in [
            ("/dev/rdisk4", "stdio:/dev/disk4"),
            ("/dev/sdb", "stdio:/dev/sdb"),
            ("/tmp/test.iso", "stdio:/tmp/test.iso"),
        ]:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory, patch(
                "builtins.open", return_value=io.BytesIO(b"ISO")
            ), patch.object(
                z.subprocess, "run", return_value=subprocess.CompletedProcess([], 5, b"", b"")
            ) as run:
                self.assertIsNone(z.inspect_manifest(raw, Path(directory)))
                self.assertEqual(run.call_count, 2)
                for call in run.call_args_list:
                    args = call.args[0]
                    self.assertEqual(args[args.index("-indev") + 1], expected)

    def test_privileged_inspection_keeps_sudo_diagnostics_visible(self):
        selected = {"raw": "/dev/rdisk4", "path": "/dev/disk4"}
        for code in (0, 1):
            result = subprocess.CompletedProcess([], code, b"null")
            with self.subTest(code=code), patch.object(z, "revalidate"), patch.object(
                z.os, "access", return_value=False
            ), patch.object(z, "require"), patch.object(
                z.subprocess, "run", return_value=result
            ) as run:
                if code:
                    with self.assertRaisesRegex(z.Error, "USB inspection failed.*nothing written"):
                        z.inspect_usb(selected, Path("/tmp/work"))
                else:
                    self.assertIsNone(z.inspect_usb(selected, Path("/tmp/work")))
                self.assertEqual(run.call_args.args[0][0], "sudo")
                self.assertEqual(run.call_args.kwargs, {"stdout": subprocess.PIPE, "check": False})

    def test_stock_debian_version_is_compared_without_claiming_config_match(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            raw = work / "usb"
            raw.write_bytes(b"ISO")
            (work / "old-debian-info").write_text(
                'Debian GNU/Linux 13.6.0 "Trixie" - Official amd64 DVD Binary-1 with firmware 20260801-09:00\n'
            )
            with patch.object(
                z.subprocess,
                "run",
                return_value=type("Result", (), {"stderr": b"", "returncode": 0})(),
            ):
                old = z.inspect_manifest(raw, work)
                self.assertIsNone(old["fingerprint"])
                self.assertEqual(
                    z.decision(old, {"version": "13.7.0", "arch": "amd64"}, "a" * 64), "upgrade"
                )
                self.assertEqual(
                    z.decision(old, {"version": "13.6.0", "arch": "amd64"}, "a" * 64), "write"
                )
                (work / "old-debian-info").write_text("unrecognized data")
                self.assertIsNone(z.inspect_manifest(raw, work))
                (work / "old-debian-info").write_text("X" * 4097)
                with self.assertRaises(z.Error):
                    z.inspect_manifest(raw, work)

    def test_privileged_writer_refuses_regular_file_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image"
            image.write_bytes(b"ISO test")
            target = Path(directory) / "target"
            target.write_bytes(b"KEEP THIS")
            selected = {
                "path": str(target),
                "raw": str(target),
                "size": 9,
                "mounts": [],
                "identity": {"maj:min": "0:0"},
            }
            with patch.object(z.os, "geteuid", return_value=0), patch.object(
                z, "revalidate", return_value=selected
            ), patch.object(z.platform, "system", return_value="Linux"), patch.object(
                z, "run"
            ), patch.object(
                z, "copy_verify"
            ) as write:
                with self.assertRaisesRegex(z.Error, "not a block device"):
                    z.write_usb(selected, image)
                write.assert_not_called()
            self.assertEqual(target.read_bytes(), b"KEEP THIS")

    def test_mac_writer_flushes_verifies_closes_then_ejects_only_on_success(self):
        image = type("Image", (), {"is_file": lambda _: True, "is_symlink": lambda _: False})()
        selected = {
            "path": "/dev/disk4",
            "raw": "/dev/rdisk4",
            "size": 8_000_000_000,
            "mounts": [],
            "identity": {},
        }
        info = type("Info", (), {"st_mode": stat.S_IFCHR, "st_rdev": 42})()
        events = []

        def copy(fd, size, source, flush):
            flush(fd)
            events.append("verified")
            return "test-digest"

        with patch.object(z.os, "geteuid", return_value=0), patch.object(
            z, "revalidate", return_value=selected
        ), patch.object(z.platform, "system", return_value="Darwin"), patch.object(
            z, "run", side_effect=lambda args: events.append(args[1])
        ), patch.object(
            z.os, "open", return_value=999
        ), patch.object(
            z.os, "close", side_effect=lambda fd: events.append("close")
        ), patch.object(
            z.os, "fstat", return_value=info
        ), patch.object(
            z.os, "stat", return_value=info
        ), patch.object(
            z.fcntl, "fcntl"
        ) as cache, patch.object(
            z.fcntl, "ioctl"
        ) as flush, patch.object(
            z, "copy_verify", side_effect=copy
        ) as verify, contextlib.redirect_stdout(
            io.StringIO()
        ) as output:
            z.write_usb(selected, image)
            cache.assert_called_once_with(999, 48, 1)
            self.assertEqual(
                [call.args for call in flush.call_args_list],
                [(999, 0x20006416)],
            )
            self.assertEqual(events, ["unmountDisk", "verified", "close", "eject"])
            self.assertIn("Ejected /dev/disk4; safe to unplug.", output.getvalue())
            events.clear()
            output.seek(0)
            output.truncate()
            verify.side_effect = z.Error("USB readback hash mismatch")
            with self.assertRaisesRegex(z.Error, "readback hash mismatch"):
                z.write_usb(selected, image)
            self.assertEqual(events, ["unmountDisk", "close"])
            self.assertNotIn("safe to unplug", output.getvalue())
            events.clear()
            verify.side_effect = copy
            with patch.object(z, "run", side_effect=[b"", z.Error("eject failed")]):
                with self.assertRaisesRegex(z.Error, "eject failed"):
                    z.write_usb(selected, image)
            self.assertEqual(events, ["verified", "close"])
            self.assertNotIn("safe to unplug", output.getvalue())

    def test_checksum_failure_prevents_customization(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "dvd.iso").write_bytes(b"tampered")
            with self.assertRaisesRegex(z.Error, "checksum"):
                debian.verified_iso({"name": "dvd.iso", "sha512": "0" * 128}, cache)

    def test_signature_status_requires_pinned_valid_signer(self):
        signer = sorted(debian.SIGNERS)[0]
        valid = f"[GNUPG:] VALIDSIG {signer} 2026-10-12 1 0 4 0 1 10 00 {signer}\n".encode()
        with patch.object(z, "run", return_value=valid):
            z.verify_signature("home", "sums", "sig", debian.SIGNERS)
        for data in (
            b"",
            valid.replace(signer.encode(), b"A" * 40),
            valid + b"[GNUPG:] BADSIG bad\n",
        ):
            with patch.object(z, "run", return_value=data):
                with self.assertRaises(z.Error):
                    z.verify_signature("home", "sums", "sig", debian.SIGNERS)

    def test_newc_archive_roundtrip_using_cpio(self):
        if not shutil.which("cpio"):
            self.skipTest("cpio absent")
        files = {
            "zapdos": (b"", stat.S_IFDIR | 0o700),
            "zapdos/test": (b"test content", stat.S_IFREG | 0o600),
        }
        archive = z.newc(files)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                ["cpio", "-id"], cwd=directory, input=archive, check=True, capture_output=True
            )
            self.assertEqual((Path(directory) / "zapdos/test").read_bytes(), b"test content")
            self.assertEqual(stat.S_IMODE((Path(directory) / "zapdos/test").stat().st_mode), 0o600)

    def test_hostname_fallback(self):
        for supplied, expected in [
            ("", "debian-a1b2c3d4"),
            ("server.example.com", "server"),
            ("Good-Name", "good-name"),
            ("server.example.com.", "server"),
            ("good\nbad", "debian-a1b2c3d4"),
            ("bad_name", "debian-a1b2c3d4"),
            ("-bad", "debian-a1b2c3d4"),
            ("bad..com", "debian-a1b2c3d4"),
            ("a" * 64, "debian-a1b2c3d4"),
            ("x; touch /tmp/never", "debian-a1b2c3d4"),
            ("123", "123"),
        ]:
            config = {
                "username": "test",
                "full_name": "Test",
                "locale": "C.UTF-8",
                "timezone": "UTC",
                "keyboard": "us",
            }
            script = debian.render_install_template(
                (z.ROOT / "debian/hostname.sh").read_text(), config
            )
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "hostname.sh"
                path.write_text(script + "zapdos_fallback=debian-a1b2c3d4\n")
                result = subprocess.run(
                    ["sh", "-c", '. "$1"; zapdos_hostname "$2"', "sh", str(path), supplied],
                    capture_output=True,
                    check=True,
                )
            self.assertEqual(result.stdout.decode().strip(), expected)


class Configuration(unittest.TestCase):
    def test_install_preferences_can_be_overridden_and_are_rendered(self):
        config = debian.configure(z.load_config(), None)
        config.update(
            username="server_user",
            full_name="Server User",
            locale="en_GB.UTF-8",
            timezone="Etc/UTC",
            keyboard="gb",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/zapdos.json").write_text(json.dumps(config))
            with patch.object(z, "ROOT", root):
                self.assertEqual(z.load_config(), config)
                self.assertEqual(debian.configure(z.load_config(), None), config)
        rendered = debian.render_install_template(
            "@USERNAME@|@FULL_NAME@|@LOCALE@|@TIMEZONE@|@KEYBOARD@",
            config,
        )
        self.assertEqual(rendered, "server_user|Server User|en_GB.UTF-8|Etc/UTC|gb")
        for path in (z.ROOT / "debian").iterdir():
            rendered = debian.render_install_template(path.read_text(), config)
            rendered = rendered.replace("@YESCRYPT@", "hash").replace("@ROOT_YESCRYPT@", "hash")
            rendered = rendered.replace("@SIGNED_GRUB@", "grub")
            self.assertNotRegex(rendered, r"@[A-Z_]+@", path.name)

    def test_installer_powers_off_and_root_uses_its_own_or_the_account_hash(self):
        preseed = (z.ROOT / "debian/preseed.cfg").read_text()
        self.assertIn("d-i debian-installer/exit/poweroff boolean true", preseed)
        self.assertIn("d-i passwd/root-login boolean true", preseed)
        self.assertIn("d-i passwd/root-password-crypted password @ROOT_YESCRYPT@", preseed)
        late = (z.ROOT / "debian/late.sh").read_text()
        self.assertNotIn("BootNext", late)
        self.assertNotIn("db_input", late)
        user = "$y$j9T$TESTONLY$" + "A" * 43
        root = "$y$j9T$ROOTONLY$" + "B" * 43
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            private(path, f"password_hash: {user}\n")
            self.assertEqual(debian.secrets(path), [user, user])
            private(path, f"password_hash: {user}\nroot_password_hash: {root}\n")
            self.assertEqual(debian.secrets(path), [user, root])

    def test_ventoy_output_requires_one_writable_ventoy_data_volume(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            ventoy = [("Ventoy", str(data)), ("VTOYEFI", "/Volumes/VTOYEFI")]
            self.assertEqual(z.ventoy_mounts([ventoy]), [data])
            self.assertEqual(z.ventoy_mounts([[("Ventoy", str(data))]]), [])
            self.assertEqual(z.ventoy_mounts([[("Ventoy", ""), ("VTOYEFI", "")]]), [])
            with patch.object(z.os, "access", return_value=False):
                self.assertEqual(z.ventoy_mounts([ventoy]), [])
            with patch.object(z.platform, "system", return_value="Linux"), patch.object(
                z.shutil, "which", return_value="/bin/lsblk"
            ), patch.object(
                z,
                "run",
                return_value=json.dumps(
                    {
                        "blockdevices": [
                            {
                                "type": "disk",
                                "children": [
                                    {"label": "Ventoy", "mountpoint": str(data)},
                                    {"label": "VTOYEFI", "mountpoint": None},
                                ],
                            }
                        ]
                    }
                ),
            ):
                self.assertEqual(z.ventoy_folder(), data)
                (data / "ISO").mkdir()
                self.assertEqual(z.ventoy_folder(), data / "ISO")

    def test_duplicate_ssh_keys_are_rejected(self):
        config = json.loads((z.ROOT / "config/zapdos.json").read_text())
        config["ssh_public_keys"] = [
            PUBLIC,
            PUBLIC.split()[0] + " " + PUBLIC.split()[1] + " other comment",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/zapdos.json").write_text(json.dumps(config))
            with patch.object(z, "ROOT", root), self.assertRaisesRegex(z.Error, "only once"):
                z.load_config()

    def test_debian_settings_must_be_offered_by_the_dvd(self):
        supported = (
            {"UTC", "Etc/UTC", "Europe/London"},
            {"en_US.UTF-8", "C.UTF-8"},
            {"us", "gb", "ru"},
        )
        base = {"timezone": "Etc/UTC", "locale": "en_US.UTF-8", "keyboard": "us"}
        debian.check_settings(base, supported)
        debian.check_settings(dict(base, keyboard="us,ru"), supported)
        for change, message in [
            ({"timezone": "Etc/UTCC"}, "Timezone"),
            ({"locale": "en_US.UTF8"}, "Locale"),
            ({"keyboard": "uss"}, "Keyboard"),
            ({"keyboard": "us,xx"}, "xx"),
        ]:
            with self.assertRaisesRegex(z.Error, message):
                debian.check_settings(dict(base, **change), supported)

    def test_debian_settings_are_read_from_dvd_packages_and_installer(self):
        templates = (
            b"Template: keyboard-configuration/other\nType: select\nChoices-C: zz\n\n"
            b"Template: keyboard-configuration/xkb-keymap\nType: select\n"
            b"Choices-C: us, gb, us(dvorak), de\nChoices: A, B, C, D\n"
        )
        archive = (
            z.newc({"etc/x": (b"x", stat.S_IFREG | 0o644)})
            + b"\0" * 8
            + z.newc(
                {
                    "var/lib/dpkg/info/console-setup-udeb.templates": (
                        templates,
                        stat.S_IFREG | 0o644,
                    )
                }
            )
        )
        self.assertEqual(
            debian.newc_file(archive, "var/lib/dpkg/info/console-setup-udeb.templates"), templates
        )
        with self.assertRaisesRegex(z.Error, "lacks"):
            debian.newc_file(archive, "missing")

        def deb(members):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:xz") as tar:
                for name, content in members:
                    info = tarfile.TarInfo(name)
                    if content is None:
                        info.type, info.linkname = tarfile.SYMTYPE, "Etc/UTC"
                    else:
                        info.size = len(content)
                    tar.addfile(info, io.BytesIO(content or b""))
            payload = data.getvalue()
            entry = lambda name, body: (
                f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(body):<10}`\n".encode()
                + body
                + b"\n" * (len(body) % 2)
            )
            return b"!<arch>\n" + entry("debian-binary", b"2.0\n") + entry("data.tar.xz", payload)

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            initrd = work / "initrd.gz"
            initrd.write_bytes(gzip.compress(archive))
            packages = {
                "tzdata": deb(
                    [
                        ("./usr/share/zoneinfo/Etc/UTC", b"TZif"),
                        ("./usr/share/zoneinfo/UTC", None),
                        ("./usr/share/zoneinfo/zone.tab", b"tab"),
                        ("./usr/share/zoneinfo/posix/Etc/UTC", b"TZif"),
                        ("./usr/share/zoneinfo/leapseconds", b"leap"),
                    ]
                ),
                "locales": deb(
                    [("./usr/share/i18n/SUPPORTED", b"en_US.UTF-8 UTF-8\nen_US ISO-8859-1\n\n")]
                ),
            }

            def package(iso, folder, prefix, work):
                path = work / (prefix + ".deb")
                path.write_bytes(packages[prefix])
                return path

            with patch.object(debian, "dvd_package", side_effect=package):
                zones, locales, layouts = debian.supported_settings("dvd.iso", initrd, work)
        self.assertEqual(zones, {"Etc/UTC", "UTC"})
        self.assertEqual(locales, {"en_US.UTF-8", "en_US"})
        self.assertEqual(layouts, {"us", "gb", "de"})

    def test_install_preferences_reject_injection(self):
        config = json.loads((z.ROOT / "config/zapdos.json").read_text())
        config["username"] = "user;id"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/zapdos.json").write_text(json.dumps(config))
            with patch.object(z, "ROOT", root), self.assertRaisesRegex(z.Error, "account name"):
                z.load_config()


class Secrets(unittest.TestCase):
    @staticmethod
    def load(name):
        try:
            return ctypes.CDLL(name)
        except OSError:
            return None

    def test_credentials_parse_comments_root_fallback_and_override(self):
        user = "$y$j9T$TESTONLY$" + "A" * 43
        root = "$y$j9T$ROOTONLY$" + "B" * 43
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            private(path, f"# comment\n\n  password_hash: {user}  \n# root_password_hash: x\n")
            self.assertEqual(z.read_credentials(path), {"password_hash": user})
            self.assertEqual(z.password_hash(path), user)
            self.assertEqual(z.password_hash(path, root=True), user)
            private(path, f"root_password_hash: {root}\npassword_hash: {user}\n")
            self.assertEqual(z.password_hash(path), user)
            self.assertEqual(z.password_hash(path, root=True), root)
            for text in (
                "password_hash: plaintext\n",
                f"root_password_hash: {root}\n",
                f"password_hash: {user}\nother: {user}\n",
            ):
                private(path, text)
                with self.assertRaises(z.Error):
                    z.password_hash(path, root=True)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(z.Error, "regular file"):
                z.read_credentials(link)
            with self.assertRaisesRegex(z.Error, "regular file"):
                z.read_credentials(Path(directory) / "missing")

    def test_credentials_must_be_private_and_owned(self):
        user = "$y$j9T$TESTONLY$" + "A" * 43
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            private(path, f"password_hash: {user}\n")
            for mode in (0o644, 0o640, 0o604):
                path.chmod(mode)
                with self.assertRaisesRegex(z.Error, "mode 0600"):
                    z.read_credentials(path)
            path.chmod(0o600)
            with patch.object(
                z.os, "geteuid", return_value=os.geteuid() + 1
            ), self.assertRaisesRegex(z.Error, "owned by you"):
                z.read_credentials(path)

    def test_hash_cost_must_match_the_libxcrypt_default_or_higher(self):
        tail = "$TESTONLY$" + "A" * 43
        self.assertEqual(z.yescrypt_memory("$y$j9T" + tail), 16 * 2**20)
        self.assertEqual(z.yescrypt_memory("$y$jFT" + tail), 1024 * 2**20)
        for weak in ("$y$j75", "$y$j7T", "$y$j9."):
            with self.assertRaisesRegex(z.Error, "weaker yescrypt cost"):
                z.check_hash(weak + tail)
        for unknown in ("$y$x9T", "$y$j9", "$y$jzT"):
            with self.assertRaisesRegex(z.Error, "weaker yescrypt cost"):
                z.check_hash(unknown + tail)
        for strong in ("$y$j9T", "$y$jBT", "$y$jFT"):
            self.assertEqual(z.check_hash(strong + tail), strong + tail)
        with tempfile.TemporaryDirectory() as directory:
            credentials, hash_file = Path(directory) / "credentials", Path(directory) / "hash"
            hash_file.write_text("$y$j75" + tail)
            with patch.object(z, "CREDENTIALS", credentials), self.assertRaises(z.Error):
                z.set_password(hash_file)
            self.assertFalse(credentials.exists())

    def test_password_rules(self):
        self.assertIsNone(z.password_problem("correct horse battery", "sysadmin"))
        self.assertRegex(z.password_problem("short pass"), "Too short")
        self.assertRegex(z.password_problem("aaaaaaaaaaaaaaaa"), "repetitive")
        self.assertRegex(z.password_problem("ababababcabcabab"), "repetitive")
        self.assertRegex(z.password_problem("my-SysAdmin-pass!", "sysadmin"), "username")
        self.assertIsNone(z.password_problem("my-sysadmin-pass!"))

    def test_updating_one_password_keeps_the_other(self):
        user = "$y$j9T$TESTONLY$" + "A" * 43
        root = "$y$j9T$ROOTONLY$" + "B" * 43
        newer = "$y$j9T$NEWERONE$" + "C" * 43
        with tempfile.TemporaryDirectory() as directory:
            credentials, hash_file = Path(directory) / "credentials", Path(directory) / "hash"
            with patch.object(z, "CREDENTIALS", credentials), contextlib.redirect_stdout(
                io.StringIO()
            ):
                hash_file.write_text(root)
                with self.assertRaisesRegex(z.Error, "account password first"):
                    z.set_password(hash_file, root=True)
                self.assertFalse(credentials.exists())
                hash_file.write_text(user)
                z.set_password(hash_file)
                self.assertFalse(z.has_root_password())
                hash_file.write_text(root)
                z.set_password(hash_file, root=True)
                self.assertEqual(
                    z.read_credentials(), {"password_hash": user, "root_password_hash": root}
                )
                hash_file.write_text(newer)
                z.set_password(hash_file)
                self.assertEqual(
                    z.read_credentials(), {"password_hash": newer, "root_password_hash": root}
                )
                z.set_password(hash_file, root=True)
                self.assertEqual(
                    z.read_credentials(), {"password_hash": newer, "root_password_hash": newer}
                )
            self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)

    def test_imported_hash_warns_that_strength_is_unchecked(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials, hash_file = Path(directory) / "credentials", Path(directory) / "hash"
            hash_file.write_text("$y$j9T$TESTONLY$" + "A" * 43)
            with patch.object(z, "CREDENTIALS", credentials), contextlib.redirect_stdout(
                io.StringIO()
            ) as logs:
                z.set_password(hash_file)
            self.assertIn("cannot check the strength", logs.getvalue())

    def test_prompt_rejects_weak_passwords_and_the_username(self):
        try:
            z.yescrypt("probe password")
        except z.Error:
            self.skipTest("libxcrypt not installed")
        answers = ["aaaaaaaaaaaaaaaa", "sysadmin-is-me!!", "good passphrase 1", "good passphrase 1"]
        with self.tty(), patch.object(
            z, "read_secret", side_effect=answers
        ), contextlib.redirect_stdout(io.StringIO()) as logs:
            value = z.prompt_password_hash(username="sysadmin")
        self.assertTrue(value.startswith("$y$j9T$"))
        self.assertIn("repetitive", logs.getvalue())
        self.assertIn("username", logs.getvalue())

    def tty(self):
        return patch.object(z.sys.stdin, "isatty", return_value=True)

    def test_set_password_writes_private_credentials_from_prompt(self):
        try:
            z.yescrypt("probe password")
        except z.Error:
            self.skipTest("libxcrypt not installed")
        password = "synthetic test password"
        with tempfile.TemporaryDirectory() as directory:
            credentials = Path(directory) / "credentials"
            private(credentials, "password_hash: old\n")
            with patch.object(z, "CREDENTIALS", credentials), self.tty(), patch.object(
                z, "read_secret", return_value=password
            ) as prompt, contextlib.redirect_stdout(io.StringIO()) as logs:
                z.set_password()
            self.assertEqual(prompt.call_count, 2)
            self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
            self.assertEqual(sorted(os.listdir(directory)), ["credentials"])
            value = z.password_hash(credentials)
            self.assertTrue(value.startswith("$y$"))
            lib = next(
                filter(
                    lambda lib: lib and hasattr(lib, "crypt_gensalt"), map(self.load, z.LIBCRYPT)
                )
            )
            lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            lib.crypt.restype = ctypes.c_char_p
            self.assertEqual(lib.crypt(password.encode(), value.encode()).decode(), value)
            self.assertNotEqual(lib.crypt(b"wrong password!", value.encode()).decode(), value)
            self.assertNotIn(password, credentials.read_text())
            self.assertNotIn(password, logs.getvalue())
            self.assertNotIn(value, logs.getvalue())

    def test_set_password_from_hash_file_never_prints_the_hash(self):
        synthetic = "$y$j9T$TESTONLY$" + "A" * 43
        with tempfile.TemporaryDirectory() as directory:
            credentials = Path(directory) / "credentials"
            hash_file = Path(directory) / "hash"
            hash_file.write_text(synthetic + "\n")
            with patch.object(z, "CREDENTIALS", credentials), patch.object(
                z, "read_secret", side_effect=AssertionError("unexpected prompt")
            ), contextlib.redirect_stdout(io.StringIO()) as logs:
                z.set_password(hash_file)
                self.assertEqual(z.password_hash(), synthetic)
            self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
            self.assertNotIn(synthetic, logs.getvalue())
            hash_file.write_text("plaintext")
            with patch.object(z, "CREDENTIALS", credentials), self.assertRaises(z.Error):
                z.set_password(hash_file)
            self.assertEqual(z.password_hash(credentials), synthetic)

    def test_rejected_passwords_save_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials = Path(directory) / "credentials"
            answers = ["too short", "first password", "second password", "short again"]
            with patch.object(z, "CREDENTIALS", credentials), self.tty(), patch.object(
                z, "read_secret", side_effect=answers
            ), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(z.Error, "Password not set"):
                    z.set_password()
            self.assertEqual(os.listdir(directory), [])
            with patch.object(z, "CREDENTIALS", credentials), patch.object(
                z.sys.stdin, "isatty", return_value=False
            ), self.assertRaisesRegex(z.Error, "interactively"):
                z.set_password()
            self.assertFalse(os.path.lexists(credentials))

    def test_secret_prompt_shows_dots_and_never_echoes_input(self):
        import pty, select, termios, tty

        master, slave = pty.openpty()
        try:
            tty.setcbreak(
                slave
            )  # No echo before read_secret takes over, so the input below is never echoed.
            before = termios.tcgetattr(slave)
            os.write(master, "pässw\x7fword\x1b[Aok\n".encode())
            self.assertEqual(z.read_secret("Password: ", os.ttyname(slave)), "pässwordok")
            shown = b""
            while not shown.endswith(b"\r\n"):
                self.assertTrue(select.select([master], [], [], 2)[0], "Terminal output timed out")
                shown += os.read(master, 4096)
            self.assertEqual(
                shown,
                b"Password: " + "•".encode() * 5 + b"\b \b" + "•".encode() * 6 + b"\r\n",
            )
            self.assertEqual(termios.tcgetattr(slave), before)
            os.write(master, b"\x04")
            with self.assertRaises(EOFError):
                z.read_secret("Password: ", os.ttyname(slave))
        finally:
            os.close(master)
            os.close(slave)


class InternalDisks(unittest.TestCase):
    def test_inventory_zero_one_multiple_and_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sysfs = root / "sys"
            (sysfs / "block").mkdir(parents=True)
            dev = root / "dev"
            dev.mkdir()
            mounts = root / "mounts"
            mounts.write_text("")
            swaps = root / "swaps"
            swaps.write_text("")
            bindir = root / "bin"
            bindir.mkdir()
            (bindir / "blkid").write_text("#!/bin/sh\nexit 2\n")
            (bindir / "blkid").chmod(0o755)

            def disk(name, removable="0", transport="pci"):
                node = sysfs / "devices" / transport / name
                node.mkdir(parents=True)
                for field, value in [
                    ("size", "67108864"),
                    ("removable", removable),
                    ("ro", "0"),
                    ("dev", "8:0"),
                ]:
                    (node / field).write_text(value)
                (node / "device").mkdir()
                (node / "device/model").write_text("Fixture Disk")
                (sysfs / "block" / name).symlink_to(node)
                (dev / name).touch()
                return node

            def inventory():
                result = subprocess.run(
                    [
                        "sh",
                        "-c",
                        '. "$1"; disk_inventory "$2" "$3" "$4" "$5"',
                        "sh",
                        str(z.ROOT / "debian/disk-lib.sh"),
                        str(sysfs),
                        str(dev),
                        str(mounts),
                        str(swaps),
                    ],
                    env=dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"]),
                    capture_output=True,
                    check=True,
                )
                return [line.split("\t") for line in result.stdout.decode().splitlines()]

            self.assertEqual(inventory(), [])
            one = disk("sda")
            self.assertEqual([r[3] for r in inventory()], ["eligible"])
            disk("nvme0n1")
            self.assertEqual(len([r for r in inventory() if r[3] == "eligible"]), 2)
            disk("sdb", "1", "usb1")
            disk("sdc", "0", "usb2")
            (one / "sda1").mkdir()
            (one / "sda1/partition").write_text("1")
            (dev / "sda1").touch()
            mounts.write_text(f"{dev}/sda1 /cdrom iso9660 ro 0 0\n")
            rows = inventory()
            self.assertEqual([r[0] for r in rows if r[3] == "eligible"], [str(dev / "nvme0n1")])
            self.assertTrue(any("installer media" in r[3] for r in rows))


if __name__ == "__main__":
    unittest.main()

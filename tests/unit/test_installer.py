"""Execute the real installer hooks in a fake root; no host disk nodes exist there."""

import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zapdos
import debian

ROOT = Path(__file__).resolve().parents[2]
CHROOT = shutil.which("chroot")


@unittest.skipUnless(
    os.geteuid() == 0 and Path("/bin/busybox").exists(), "requires Debian test container"
)
class InstallerHooks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in (
            "bin",
            "dev",
            "etc/udhcpc",
            "proc/sys/kernel",
            "sys/block",
            "sys/devices/pci",
            "sys/firmware/efi/efivars",
            "tmp",
            "zapdos",
            "usr/share/debconf",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(os.environ.get("ZAPDOS_BUSYBOX", "/bin/busybox"), self.root / "bin/busybox")
        (self.root / "bin/busybox").chmod(0o755)
        if "ZAPDOS_BUSYBOX" in os.environ:
            # DVD BusyBox is dynamically linked; copy only its loader/libraries into the fake root.
            libraries = subprocess.check_output(["ldd", os.environ["ZAPDOS_BUSYBOX"]], text=True)
            for library in set(re.findall(r"/[^\s()]+", libraries)):
                destination = self.root / library.lstrip("/")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, destination)
        for name in (
            "sh",
            "cat",
            "cut",
            "readlink",
            "tr",
            "sha256sum",
            "awk",
            "wc",
            "grep",
            "mkdir",
            "dd",
            "cmp",
            "printf",
            "mv",
            "cp",
            "chmod",
            "sleep",
        ):
            (self.root / "bin" / name).symlink_to("busybox")
        config = debian.configure(zapdos.load_config(), None)
        for file in (ROOT / "debian").iterdir():
            if file.is_file():
                (self.root / "zapdos" / file.name).write_text(
                    debian.render_install_template(file.read_text(), config)
                )
        (self.root / "dev/console").touch()
        (self.root / "proc/swaps").write_text("")
        (self.root / "proc/mounts").write_text(
            "efivarfs /sys/firmware/efi/efivars efivarfs rw 0 0\n"
        )
        (self.root / "proc/sys/kernel/hostname").write_text("(none)")
        (self.root / "proc/sys/kernel/random").mkdir()
        (self.root / "proc/sys/kernel/random/uuid").write_text(
            "a1b2c3d4-0000-4000-8000-000000000000\n"
        )
        (self.root / "etc/udhcpc/default.script").write_text("#!/bin/sh\nexit 0\n")
        for name, value in [("SecureBoot", 1), ("SetupMode", 0)]:
            (
                self.root / f"sys/firmware/efi/efivars/{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c"
            ).write_bytes(b"\x07\x00\x00\x00" + bytes([value]))
        self.command("blkid", "exit 2")
        self.command(
            "parted_devices",
            'printf "/dev/vda\\t25769803776\\tFirst disk\\n/dev/vdb\\t25769803776\\tSecond disk\\n/dev/sda\\t8000000000\\tUSB\\n"',
        )
        self.command("debconf-set", 'printf "%s %s\\n" "$1" "$2" >> /tmp/partition-authorization')
        self.command("debconf-loadtemplate", "exit 0")
        (self.root / "usr/share/debconf/confmodule").write_text("""db_set() { :; }
db_fset() { :; }
db_input() { printf '%s\\n' "$*" >> /tmp/questions; }
db_go() { return "${CANCEL:-0}"; }
db_get() { RET=$ANSWER; }
""")

    def command(self, name, body):
        path = self.root / "bin" / name
        path.unlink(missing_ok=True)
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def disk(self, name, transport="pci", mounted=False, removable=0):
        path = self.root / "sys/devices" / transport / name
        path.mkdir(parents=True)
        (self.root / "sys/block" / name).symlink_to("../devices/" + transport + "/" + name)
        for field, value in [
            ("size", "50331648"),
            ("removable", str(removable)),
            ("ro", "0"),
            ("dev", "8:0"),
        ]:
            (path / field).write_text(value)
        (path / "device").mkdir()
        (path / "device/model").write_text("Fixture disk")
        (self.root / "dev" / name).touch()  # regular file; never a device node
        if mounted:
            with (self.root / "proc/mounts").open("a") as file:
                file.write(f"/dev/{name} /cdrom iso9660 ro 0 0\n")

    def run_hook(self, script="disk.sh", **env):
        return subprocess.run(
            [CHROOT, str(self.root), "/bin/sh", "/zapdos/" + script],
            env={"PATH": "/bin", "ANSWER": "STOP", **env},
            capture_output=True,
        )

    def test_zero_and_multiple_stop_never_authorize_partitioning(self):
        self.disk("sda", "usb1", mounted=True)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertFalse((self.root / "tmp/partition-authorization").exists())
        self.disk("vda")
        self.disk("vdb")
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertTrue((self.root / "tmp/questions").exists())
        self.assertFalse((self.root / "tmp/partition-authorization").exists())
        self.assertNotEqual(
            self.run_hook(ANSWER="/dev/vda (Fixture disk)", CANCEL="1").returncode, 0
        )
        self.assertFalse((self.root / "tmp/partition-authorization").exists())

    def test_unique_and_explicit_selection_only_authorize_selected_disk(self):
        self.disk("vda")
        self.disk("sda", "usb1")
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "tmp/partition-authorization").read_text(),
            "partman-auto/disk /dev/vda\ngrub-installer/bootdev /dev/vda\n",
        )
        (self.root / "tmp/partition-authorization").unlink()
        self.disk("vdb")
        result = self.run_hook(ANSWER="/dev/vdb (Fixture disk; 24 GiB)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "tmp/partition-authorization").read_text(),
            "partman-auto/disk /dev/vdb\ngrub-installer/bootdev /dev/vdb\n",
        )
        result = subprocess.run(
            [CHROOT, str(self.root), "/bin/parted_devices"],
            env={"PATH": "/bin"},
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"/dev/vdb\t25769803776\tSecond disk\n")
        self.command("vendor-parted-devices", "exit 1")
        shutil.copyfile(
            self.root / "bin/vendor-parted-devices", self.root / "zapdos/vendor-parted-devices"
        )
        self.assertNotEqual(
            subprocess.run(
                [CHROOT, str(self.root), "/bin/parted_devices"],
                env={"PATH": "/bin"},
                capture_output=True,
            ).returncode,
            0,
        )

    def test_secure_boot_disabled_or_unreadable_never_authorizes_disks(self):
        self.disk("vda")
        variable = (
            self.root / "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        )
        for contents in (b"\x07\x00\x00\x00\x00", b"", b"\x01"):
            variable.write_bytes(contents)
            self.assertNotEqual(self.run_hook().returncode, 0)
            self.assertFalse((self.root / "tmp/partition-authorization").exists())
        variable.write_bytes(b"\x07\x00\x00\x00\x01")
        (
            self.root / "sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        ).write_bytes(b"\x07\x00\x00\x00\x01")
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertFalse((self.root / "tmp/partition-authorization").exists())
        shutil.rmtree(self.root / "sys/firmware/efi")
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertFalse((self.root / "tmp/partition-authorization").exists())

    def test_dhcp_wrapper_valid_missing_invalid_names(self):
        self.assertEqual(self.run_hook("early.sh").returncode, 0)
        self.assertEqual(
            (self.root / "proc/sys/kernel/hostname").read_text().strip(), "debian-a1b2c3d4"
        )
        for name, expected in [
            ("DHCP-Server.Example.Net", "dhcp-server"),
            ("", "debian-a1b2c3d4"),
            ("invalid_name", "debian-a1b2c3d4"),
            ("good\nbad", "debian-a1b2c3d4"),
        ]:
            result = subprocess.run(
                [CHROOT, str(self.root), "/bin/sh", "/etc/udhcpc/default.script", "bound"],
                env={"PATH": "/bin", "hostname": name},
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.root / "tmp/dhcp-hostname").read_text().strip(), expected)
            self.assertEqual((self.root / "proc/sys/kernel/hostname").read_text().strip(), expected)

    def test_disabled_shim_validation_never_authorizes_disks(self):
        self.disk("vda")
        (
            self.root / "sys/firmware/efi/efivars/MokSBStateRT-605dab50-e046-4300-abb6-3dd810dd8b23"
        ).write_bytes(b"\x07\x00\x00\x00\x01")
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertFalse((self.root / "tmp/partition-authorization").exists())

    def test_network_none_no_carrier_and_failed_dhcp_never_block(self):
        (self.root / "sys/class/net").mkdir(parents=True)
        self.assertEqual(self.run_hook("network.sh").returncode, 0)
        node = self.root / "sys/class/net/eth0"
        (node / "device").mkdir(parents=True)
        (node / "type").write_text("1")
        (node / "carrier").write_text("0")
        self.command("ip", "exit 0")
        self.command("sleep", "exit 0")
        self.command("udhcpc", 'printf "%s\\n" "$*" > /tmp/dhcp-arguments; exit 1')
        self.assertEqual(self.run_hook("network.sh").returncode, 0)
        self.assertFalse((self.root / "tmp/dhcp-arguments").exists())
        (node / "carrier").write_text("1")
        self.assertEqual(self.run_hook("network.sh").returncode, 0)
        self.assertIn("-O hostname", (self.root / "tmp/dhcp-arguments").read_text())

    def test_existing_linux_intel_and_ddf_raid_members_never_authorize_disks(self):
        self.disk("vda")
        for kind in ("LVM2_member", "linux_raid_member", "isw_raid_member", "ddf_raid_member"):
            self.command("blkid", f"echo {kind}")
            self.assertNotEqual(self.run_hook().returncode, 0)
            self.assertFalse((self.root / "tmp/partition-authorization").exists())

    def test_probe_errors_ambiguity_and_running_partitioner_never_authorize(self):
        self.disk("vda")
        for body in ("exit 4", "exit 8", 'echo "blkid: Input/output error" >&2; exit 2'):
            self.command("blkid", body)
            self.assertNotEqual(self.run_hook().returncode, 0)
            self.assertFalse((self.root / "tmp/partition-authorization").exists())
        self.command("blkid", "exit 2")
        (self.root / "var/run").mkdir(parents=True)
        (self.root / "var/run/parted_server.pid").write_text("42")
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertFalse((self.root / "tmp/partition-authorization").exists())

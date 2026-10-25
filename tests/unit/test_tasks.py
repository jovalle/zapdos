"""Task tests never install packages, download media, or access real disks."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import tasks as t


class Tasks(unittest.TestCase):
    def setUp(self):
        self.host = patch.object(t, "host")
        self.host.start()
        self.addCleanup(patch.stopall)

    def test_ready_setup_is_idempotent_and_check_never_installs(self):
        with patch.object(t, "needed", return_value=[]), patch.object(t.subprocess, "run") as run:
            with contextlib.redirect_stdout(io.StringIO()), patch.object(
                t.os, "geteuid", return_value=1000
            ):
                t.setup()
                t.setup()
            run.assert_not_called()
        with patch.object(t, "needed", return_value=["xorriso"]), patch.object(
            t.subprocess, "run"
        ) as run:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                t.setup(install=False)
            run.assert_not_called()

    def test_setup_seeds_missing_zapdos_config_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            example = config / "zapdos.example.json"
            example.write_text('{"username":"example"}\n')
            local = config / "zapdos.json"
            with patch.object(t, "ROOT", root), patch.object(
                t, "needed", return_value=[]
            ), patch.object(t.os, "geteuid", return_value=1000), contextlib.redirect_stdout(
                io.StringIO()
            ):
                t.setup()
                self.assertEqual(local.read_text(), example.read_text())
                local.write_text('{"username":"local"}\n')
                t.setup()
                self.assertEqual(local.read_text(), '{"username":"local"}\n')
                local.unlink()
                t.setup(install=False)
                self.assertFalse(local.exists())

    def test_version_checks_are_offline_and_reject_old_or_unknown_versions(self):
        env = {"PATH": "/tools"}
        for xorriso, expected in [("1.5.6", []), ("1.5.5", ["xorriso"]), ("unknown", ["xorriso"])]:
            with patch.object(t.shutil, "which", return_value="/tools/tool"), patch.object(
                t.platform, "system", return_value="Linux"
            ), patch.object(
                t.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "xorriso " + xorriso, ""),
            ) as run:
                self.assertEqual(t.needed(env), expected)
                run.assert_called_once()
                self.assertEqual(run.call_args.args[0], ["xorriso", "-version"])

    def test_mac_requires_homebrew_libxcrypt_for_yescrypt(self):
        with patch.object(t.shutil, "which", return_value=None), patch.object(
            t.platform, "system", return_value="Darwin"
        ):
            for exists, expected in [(False, True), (True, False)]:
                with patch.object(t.os.path, "exists", return_value=exists):
                    self.assertEqual("libxcrypt" in t.needed({"PATH": ""}), expected)

    def test_package_managers_install_only_missing_packages(self):
        for manager, system, expected in [
            ("brew", "Darwin", ["brew", "install", "gnupg"]),
            (
                "apt-get",
                "Linux",
                ["sudo", "apt-get", "install", "--yes", "--no-install-recommends", "gnupg"],
            ),
            ("dnf", "Linux", ["sudo", "dnf", "install", "--assumeyes", "gnupg2"]),
            (
                "pacman",
                "Linux",
                ["sudo", "pacman", "-S", "--needed", "--noconfirm", "gnupg"],
            ),
            ("zypper", "Linux", ["sudo", "zypper", "--non-interactive", "install", "gpg2"]),
        ]:
            with self.subTest(manager=manager), contextlib.redirect_stdout(
                io.StringIO()
            ), patch.object(t.platform, "system", return_value=system), patch.object(
                t.os, "geteuid", return_value=1000
            ), patch.object(
                t.shutil,
                "which",
                side_effect=lambda name, **kw: name if name in (manager, "sudo") else None,
            ), patch.object(
                t, "needed", side_effect=[["gpg"], []]
            ), patch.object(
                t.subprocess, "run"
            ) as run:
                t.setup()
                self.assertEqual(run.call_args.args[0], expected)
                self.assertEqual(run.call_count, 2 if manager == "apt-get" else 1)

    def test_brew_upgrades_only_outdated_tools(self):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
            t.platform, "system", return_value="Darwin"
        ), patch.object(t.os, "geteuid", return_value=1000), patch.object(
            t.shutil, "which", return_value="/tools/tool"
        ), patch.object(
            t, "needed", side_effect=[["xorriso"], []]
        ), patch.object(
            t.subprocess, "run"
        ) as run:
            t.setup()
            run.assert_called_once_with(["brew", "upgrade", "xorriso"], check=True)

    def test_install_failure_stops_before_launching_zapdos(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ), patch.object(t.os, "geteuid", return_value=1000), patch.object(
            t.platform, "system", return_value="Darwin"
        ), patch.object(
            t.shutil, "which", side_effect=lambda name, **kw: name if name == "brew" else None
        ), patch.object(
            t, "needed", return_value=["xorriso"]
        ), patch.object(
            t.sys, "argv", ["-c", "zap", "amd64"]
        ), patch.object(
            t.subprocess, "run", side_effect=subprocess.CalledProcessError(42, ["brew"])
        ) as run:
            with self.assertRaises(SystemExit) as exc:
                t.main("zap")
            self.assertEqual(exc.exception.code, 1)
            run.assert_called_once_with(["brew", "install", "xorriso"], check=True)

    def test_target_is_explicit_and_bad_input_never_installs(self):
        for answer, expected in [("arm64", "arm64"), ("", "amd64")]:
            with patch("builtins.input", return_value=answer):
                self.assertEqual(t.architecture(""), expected)
        with patch.object(t.sys, "argv", ["-c", "zap", "mips"]), contextlib.redirect_stderr(
            io.StringIO()
        ), patch.object(t, "setup") as setup, patch.object(t.os, "execve") as execute:
            with self.assertRaises(SystemExit):
                t.main("zap")
            setup.assert_not_called()
            execute.assert_not_called()

    def test_build_output_and_password_hash_file_are_optional(self):
        for command, argv, expected in [
            ("build", ["", "arm64"], ["zapdos.py", "build", "--arch", "arm64"]),
            ("build", ["arm64", ""], ["zapdos.py", "build", "--arch", "arm64"]),
            ("build", ["debian", "amd64"], ["zapdos.py", "build", "--arch", "amd64"]),
            ("password", [""], ["zapdos.py", "password"]),
        ]:
            with patch.object(t.sys, "argv", ["-c", command, *argv]), patch.object(
                t, "setup", return_value={}
            ), patch.object(t.os, "chdir"), patch.object(t.os, "execve") as execute:
                t.main(command)
                execute.assert_called_once_with(sys.executable, [sys.executable, *expected], {})

    def test_interactive_architecture_defaults_to_amd64(self):
        for command in ("build", "zap"):
            for answers, arch in [([""], "amd64"), (["arm64"], "arm64")]:
                args = ["", "", ""] if command == "build" else ["", ""]
                with self.subTest(command=command, answers=answers), patch.object(
                    t.sys, "argv", ["-c", command, *args]
                ), patch("builtins.input", side_effect=answers) as prompt, patch.object(
                    t, "setup", return_value={}
                ) as setup, patch.object(
                    t.os, "chdir"
                ), patch.object(
                    t.os, "execve"
                ) as execute:
                    t.main(command)
                    self.assertEqual(
                        [call.args[0] for call in prompt.call_args_list],
                        ["Target architecture [amd64] (amd64, arm64): "],
                    )
                    expected = [
                        sys.executable,
                        "zapdos.py",
                        "build" if command == "build" else "prepare",
                        "--arch",
                        arch,
                    ]
                    setup.assert_called_once_with()
                    execute.assert_called_once_with(sys.executable, expected, {})

    def test_zap_with_device_is_noninteractive_and_never_installs_tools(self):
        for args, expected_arch in (
            (["/dev/disk4", "amd64"], "amd64"),
            (["arm64", "/dev/disk4"], "arm64"),
            (["/dev/disk4"], "amd64"),
        ):
            with self.subTest(args=args), patch.object(
                t.sys, "argv", ["-c", "zap", *args]
            ), patch.object(t, "setup", return_value={"PATH": "/tools"}) as setup, patch(
                "builtins.input", side_effect=AssertionError("unexpected prompt")
            ), patch.object(
                t.os, "chdir"
            ), patch.object(
                t.os, "execve"
            ) as execute:
                t.main("zap")
                setup.assert_called_once_with(install=False)
                execute.assert_called_once_with(
                    sys.executable,
                    [
                        sys.executable,
                        "zapdos.py",
                        "prepare",
                        "--arch",
                        expected_arch,
                        "--device",
                        "/dev/disk4",
                        "--yes",
                    ],
                    {"PATH": "/tools"},
                )
        for args in (["/dev/disk4", "mips"], ["disk4"], ["/dev/disk4", "arm64", "unknown"]):
            with patch.object(t.sys, "argv", ["-c", "zap", *args]), patch.object(
                t, "setup"
            ) as setup, patch.object(t.os, "execve") as execute, contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit):
                    t.main("zap")
                setup.assert_not_called()
                execute.assert_not_called()

    def test_disk_commands_dispatch_and_reject_unsupported_hosts(self):
        with patch.object(t.platform, "system", return_value="Darwin"), patch.object(
            t.subprocess, "run"
        ) as run, patch.object(t.sys, "argv", ["-c", "disks"]):
            t.main("disks")
            run.assert_called_once_with(["diskutil", "list", "external", "physical"], check=True)
        with patch.object(t.platform, "system", return_value="Darwin"), patch.object(
            t, "eject_usb"
        ) as eject, patch.object(t.sys, "argv", ["-c", "eject", "/dev/disk4"]):
            t.main("eject")
            eject.assert_called_once_with("/dev/disk4")
        for command in ("disks", "eject"):
            with patch.object(t.platform, "system", return_value="Linux"), patch.object(
                t.sys, "argv", ["-c", command, "/dev/disk4"]
            ), patch.object(t.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    t.main(command)
                run.assert_not_called()

    def test_eject_requires_an_eligible_unchanged_external_usb(self):
        import zapdos as z

        selected = {"path": "/dev/disk4", "reason": "eligible"}
        devices = [selected, {"path": "/dev/disk0", "reason": "system/boot"}]
        with patch.object(z, "inventory", return_value=devices), patch.object(
            z, "revalidate", return_value=selected
        ) as revalidate, patch.object(t.subprocess, "run") as run, contextlib.redirect_stdout(
            io.StringIO()
        ):
            t.eject_usb("/dev/disk4")
            revalidate.assert_called_once_with(selected, [t.ROOT])
            run.assert_called_once_with(["diskutil", "eject", "/dev/disk4"], check=True)
            run.reset_mock()
            for device in ("/dev/disk0", "/dev/disk4s2", "/dev/disk9", "-force"):
                with self.assertRaises(ValueError):
                    t.eject_usb(device)
            run.assert_not_called()
            revalidate.side_effect = z.Error("identity changed")
            with self.assertRaisesRegex(ValueError, "identity changed"):
                t.eject_usb("/dev/disk4")
            run.assert_not_called()

    def test_invalid_interactive_target_never_installs_or_launches(self):
        for answers in (["windows"], ["mips"]):
            with self.subTest(answers=answers), patch.object(
                t.sys, "argv", ["-c", "build", "", "", ""]
            ), patch("builtins.input", side_effect=answers), patch.object(
                t, "setup"
            ) as setup, patch.object(
                t.os, "execve"
            ) as execute, contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit) as exc:
                    t.main("build")
                self.assertEqual(exc.exception.code, 1)
                setup.assert_not_called()
                execute.assert_not_called()

    def test_paths_are_literal_and_zapdos_receives_signals_directly(self):
        output = '/tmp/ISO "quoted" $(touch should-not-exist); file.iso'
        for command, argv, expected in [
            (
                "build",
                [output, "arm64"],
                ["zapdos.py", "build", "--arch", "arm64", "--output", output],
            ),
            ("password", [output], ["zapdos.py", "password", "--hash-file", output]),
        ]:
            with patch.object(t.sys, "argv", ["-c", command, *argv]), patch.object(
                t, "setup", return_value={}
            ), patch.object(t.os, "chdir") as chdir, patch.object(t.os, "execve") as execute:
                t.main(command)
                chdir.assert_called_once_with(t.ROOT)
                execute.assert_called_once_with(sys.executable, [sys.executable, *expected], {})

    @unittest.skipUnless(shutil.which("just"), "requires just")
    def test_real_just_passes_arguments_literally_from_a_subdirectory(self):
        with tempfile.TemporaryDirectory(prefix="zapdos tasks ") as directory:
            root = Path(directory)
            shutil.copyfile(t.ROOT / "justfile", root / "justfile")
            (root / "sub").mkdir()
            (root / "tasks.py").write_text(
                "import json, sys\nfrom pathlib import Path\n"
                "def main(command):\n"
                '    Path("args.json").write_text(json.dumps([command, sys.argv]))\n',
                encoding="utf-8",
            )
            output = 'ISO "quoted" $(touch should-not-exist); file.iso'
            for command, arguments, expected in [
                ("build", [output, "arm64"], [output, "arm64"]),
                ("zap", [], []),
                ("zap", ["/dev/disk4", "arm64"], ["/dev/disk4", "arm64"]),
                ("disks", [], []),
                ("eject", ["/dev/disk4"], ["/dev/disk4"]),
                ("password", [], []),
            ]:
                with self.subTest(command=command, arguments=arguments):
                    result = subprocess.run(
                        ["just", "--set", "python", sys.executable, command, *arguments],
                        cwd=root / "sub",
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        json.loads((root / "args.json").read_text()),
                        [command, ["-c", command, *expected]],
                    )
            self.assertFalse((root / "should-not-exist").exists())

    def test_unsupported_hosts_fail_before_installation(self):
        self.host.stop()
        with patch.object(t.platform, "system", return_value="Windows"), self.assertRaises(
            ValueError
        ):
            t.host()
        with patch.object(t.platform, "system", return_value="Linux"), patch.object(
            t.os, "geteuid", return_value=0
        ), self.assertRaises(ValueError), patch.object(t.subprocess, "run") as run:
            t.setup()
        run.assert_not_called()

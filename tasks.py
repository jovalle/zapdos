"""Standard-library task support for the justfile; never run Zapdos as root."""

import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
MINIMUM = {"xorriso": (1, 5, 6)}
TOOLS = ("xorriso", "gpg")
# macOS crypt lacks yescrypt; Homebrew's libxcrypt is keg-only and has no command to probe.
LIBXCRYPT = (
    "/opt/homebrew/opt/libxcrypt/lib/libcrypt.dylib",
    "/usr/local/opt/libxcrypt/lib/libcrypt.dylib",
)


def host():
    if sys.version_info < (3, 10):
        raise ValueError("Python 3.10+ is required.")
    if platform.system() not in ("Darwin", "Linux"):
        raise ValueError(
            "Zapdos supports macOS and Linux. On Windows, use WSL with USB access configured."
        )


def environment():
    return dict(os.environ)


def needed(env):
    missing = []
    tools = TOOLS + (("lsblk", "sudo") if platform.system() == "Linux" else ("sudo",))
    for tool in tools:
        if not shutil.which(tool, path=env["PATH"]):
            missing.append(tool)
        elif tool in MINIMUM:
            result = subprocess.run(
                ["xorriso", "-version"], env=env, capture_output=True, text=True, check=True
            )
            match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout + result.stderr)
            if not match or tuple(map(int, match.groups())) < MINIMUM[tool]:
                missing.append(tool)
    if platform.system() == "Darwin" and not any(os.path.exists(p) for p in LIBXCRYPT):
        missing.append("libxcrypt")
    return missing


def ensure_zapdos_config():
    destination = ROOT / "config/zapdos.json"
    if destination.exists():
        return
    template = ROOT / "config/zapdos.example.json"
    if not template.is_file():
        raise ValueError("Missing config/zapdos.example.json")
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "wb") as output:
        output.write(template.read_bytes())
    print(
        "Created config/zapdos.json from config/zapdos.example.json; replace the SSH key placeholder before use.",
        flush=True,
    )


def setup(install=True):
    host()
    if install and os.geteuid() == 0:
        raise ValueError(
            "Run just as your ordinary account; only package installation and USB access use sudo."
        )
    env = environment()
    missing = needed(env)
    if not missing:
        if install:
            ensure_zapdos_config()
        print("System tools are ready.", flush=True)
        return env
    print("Missing or too old: " + ", ".join(missing), flush=True)
    if not install:
        raise ValueError("Run just setup to install them. See README.md for minimum versions.")
    mac = platform.system() == "Darwin"
    managers = ("brew",) if mac else ("apt-get", "dnf", "pacman", "zypper")
    manager = next((name for name in managers if shutil.which(name)), None)
    if not manager:
        raise ValueError(
            "Install Homebrew first on macOS, or install the tools listed in README.md on this Linux distribution."
        )
    if not mac and not shutil.which("sudo"):
        raise ValueError(
            "sudo is required to install system packages. Ask your administrator to install the README.md requirements."
        )
    gpg_package = {"dnf": "gnupg2", "zypper": "gpg2"}.get(manager, "gnupg")
    packages = {"gpg": gpg_package, "lsblk": "util-linux"}
    requested = sorted({packages.get(tool, tool) for tool in missing})
    if requested:
        print("Installing: " + ", ".join(requested), flush=True)
        if manager == "apt-get":
            subprocess.run(["sudo", manager, "update"], check=True)
        commands = {
            "brew": ["brew", "install"],
            "apt-get": ["sudo", "apt-get", "install", "--yes", "--no-install-recommends"],
            "dnf": ["sudo", "dnf", "install", "--assumeyes"],
            "pacman": ["sudo", "pacman", "-S", "--needed", "--noconfirm"],
            "zypper": ["sudo", "zypper", "--non-interactive", "install"],
        }
        if manager == "brew":
            for action in ("install", "upgrade"):
                selected = sorted(
                    {
                        packages.get(tool, tool)
                        for tool in missing
                        if ("upgrade" if shutil.which(tool, path=env["PATH"]) else "install")
                        == action
                    }
                )
                if selected:
                    subprocess.run(["brew", action, *selected], check=True)
        else:
            subprocess.run([*commands[manager], *requested], check=True)
    remaining = needed(env)
    if remaining:
        raise ValueError(
            "Still missing or too old: "
            + ", ".join(remaining)
            + ". Follow the README.md installation instructions."
        )
    ensure_zapdos_config()
    print("System tools are ready.", flush=True)
    return env


def architecture(value):
    if not value:
        value = input("Target architecture [amd64] (amd64, arm64): ").strip()
        if not value:
            value = "amd64"
    if value not in ("amd64", "arm64"):
        raise ValueError("Choose amd64 or arm64; the target can differ from this computer.")
    return value


def eject_usb(device):
    import zapdos as z

    try:
        selected = next(
            (d for d in z.inventory([ROOT]) if d["path"] == device and d["reason"] == "eligible"),
            None,
        )
        if selected is None:
            raise ValueError("Choose an eligible external whole USB from just disks.")
        z.revalidate(selected, [ROOT])
    except z.Error as exc:
        raise ValueError(str(exc)) from exc
    subprocess.run(["diskutil", "eject", selected["path"]], check=True)
    z.ok(f"Ejected {selected['path']}; safe to unplug.")


def options(command, args):
    """Parse zap/build options given in any order; prompt only for what is missing."""
    arch = device = output = ""
    for value in filter(None, args):
        if value == "debian":
            continue
        if value in ("amd64", "arm64"):
            arch = value
        elif command == "zap" and value.startswith("/dev/"):
            device = value
        elif command == "build" and not output:
            output = value
        else:
            raise ValueError(
                f"Unknown option {value!r}. Use debian, amd64, arm64"
                + (", or a /dev/ device." if command == "zap" else ", or an output path.")
            )
    target = architecture(arch or ("amd64" if device else ""))
    invocation = ["zapdos.py", "build" if command == "build" else "prepare", "--arch", target]
    if output:
        invocation += ["--output", output]
    if device:
        invocation += ["--device", device, "--yes"]
    return invocation, device


def main(command):
    try:
        host()
        # Python -c receives the recipe name before its positional arguments.
        args = sys.argv[2:]
        if command in ("setup", "check"):
            setup(install=command == "setup")
            return
        if command in ("disks", "eject"):
            if platform.system() != "Darwin":
                raise ValueError(f"just {command} currently supports macOS only.")
            if command == "disks":
                subprocess.run(["diskutil", "list", "external", "physical"], check=True)
            else:
                eject_usb(args[0])
            return
        if command == "test":
            invocation = ["-m", "unittest", "discover", "-s", "tests/unit", "-v"]
            env = environment()
        elif command == "password":
            invocation = ["zapdos.py", "password"]
            for option in filter(None, args):
                if option == "root":
                    invocation += ["--root"]
                elif "--hash-file" not in invocation:
                    invocation += ["--hash-file", option]
                else:
                    raise ValueError("Use: just password [root] [HASH_FILE]")
            env = setup()
        else:
            invocation, device = options(command, args)
            if device:
                # A named device means no prompts and no package installation.
                env = setup(install=False)
            else:
                env = setup()
        # Replace this wrapper so Zapdos receives cancellation signals directly.
        os.chdir(ROOT)
        os.execve(sys.executable, [sys.executable, *invocation], env)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        message = (
            f"Command failed (exit {exc.returncode})."
            if isinstance(exc, subprocess.CalledProcessError)
            else str(exc)
        )
        print("Error: " + message, file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("Cancelled.", file=sys.stderr)
        sys.exit(1)

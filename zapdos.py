#!/usr/bin/env python3
"""Prepare an unattended Debian installer. No third-party Python dependencies."""

import argparse
import base64
import contextlib
import ctypes
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty
import urllib.request

# The Debian module imports "zapdos"; share this module (and its Error class) when run as a script.
sys.modules.setdefault("zapdos", sys.modules[__name__])

ROOT = Path(__file__).resolve().parent
CREDENTIALS = ROOT / "config/credentials.yaml"
# Debian/Fedora/Arch libcrypt.so.1 is libxcrypt; macOS needs Homebrew's keg-only libxcrypt.
LIBCRYPT = (
    "/opt/homebrew/opt/libxcrypt/lib/libcrypt.dylib",
    "/usr/local/opt/libxcrypt/lib/libcrypt.dylib",
    "libcrypt.so.1",
)
YESCRYPT = r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}"
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# libxcrypt's default yescrypt cost ("j9T"): N = 2^12 blocks of 128 * r(32) bytes = 16 MiB.
YESCRYPT_MIN_MEMORY = 16 * 2**20
PASSWORD_MIN_LENGTH = 12
PASSWORD_MIN_DISTINCT = 6
CHUNK = 4 * 1024 * 1024
RECEIPT_SIZE = 4096
ERASE_EDGE = 64 * 2**20
RECEIPT_MAGIC = b"ZAPDOS-WRITE-1\n"


class Error(Exception):
    pass


def fancy(stream=None):
    stream = stream or sys.stdout
    return stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def paint(code, text, stream=None):
    return f"\033[{code}m{text}\033[0m" if fancy(stream) else text


def ok(message):
    print(paint("32", "✔") + " " + message if fancy() else message, flush=True)


def note(message):
    print(paint("36", "›") + " " + message if fancy() else message, flush=True)


def warn(message):
    print(paint("33", "!") + " " + message if fancy() else "Warning: " + message, flush=True)


class Spin:
    detail = ""


@contextlib.contextmanager
def spinner(label):
    """Animated status line on a terminal; plain text elsewhere."""
    state = Spin()
    if not fancy():
        print(f"{label}…", flush=True)
        yield state
        if state.detail:
            print(f"{label}: {state.detail}", flush=True)
        return
    stop = threading.Event()

    def spin():
        for frame in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
            if stop.wait(0.08):
                return
            print(
                f"\r\033[2K{paint('36', frame)} {label} {paint('90', state.detail)}",
                end="",
                flush=True,
            )

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    mark = paint("31", "✘")
    try:
        yield state
        mark = paint("32", "✔")
    finally:
        stop.set()
        thread.join()
        print(f"\r\033[2K{mark} {label} {state.detail}", flush=True)


def bar(done, total, color="36"):
    width = 24
    filled, fraction = divmod(width * 8 * done // total, 8)
    partial = "▏▎▍▌▋▊▉"[fraction - 1] if fraction else ""
    line = paint(color, "█" * filled + partial) + paint(
        "90", "░" * (width - filled - bool(partial))
    )
    percent = (1000 * done // total) / 10
    return f"{line} {percent:5.1f}%  {done / 2**20:.1f}/{total / 2**20:.1f} MiB"


def run(args, *, data=None, quiet=False):
    result = subprocess.run(
        [str(a) for a in args],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        # Preseed input can contain a password hash. Never echo command/output.
        raise Error(
            f"{Path(str(args[0])).name} failed (exit {result.returncode})"
            + ("" if quiet else ": " + result.stderr.decode(errors="replace")[-2000:])
        )
    return result.stdout


def require(*names):
    missing = [n for n in names if not shutil.which(n)]
    if missing:
        raise Error("Install required commands: " + ", ".join(missing))


def sha(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


VERSION = r"\d+\.\d+\.\d+"


def version(value):
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        raise Error("Invalid Debian version")
    return tuple(int(n) for n in value.split("."))


def download(url, destination, limit=None, progress=None):
    if not url.startswith("https://"):
        raise Error("Downloads must use HTTPS")
    partial = destination.with_suffix(destination.suffix + ".part")
    created = False
    try:
        with urllib.request.urlopen(url, timeout=60) as response, open(partial, "xb") as out:
            created = True
            if not response.url.startswith("https://"):
                raise Error("Refusing an insecure redirect")
            total = 0
            while block := response.read(CHUNK):
                total += len(block)
                if limit and total > limit:
                    raise Error("Metadata download exceeded size limit")
                out.write(block)
                if progress:
                    progress(total, int(response.headers.get("Content-Length") or 0))
            out.flush()
            os.fsync(out.fileno())
        partial.replace(destination)
    finally:
        if created:
            partial.unlink(missing_ok=True)


def verify_signature(home, sums, signature, signers):
    result = run(
        [
            "gpg",
            "--homedir",
            home,
            "--batch",
            "--no-auto-key-retrieve",
            "--status-fd",
            "1",
            "--verify",
            signature,
            sums,
        ]
    )
    valid = []
    for line in result.decode().splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fields = line.split()
            valid.append(fields[-1] if len(fields) >= 12 else fields[2])
        if any(
            f"[GNUPG:] {bad} " in line
            for bad in ("BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG")
        ):
            raise Error("Checksum signature is not valid")
    if not valid or any(signer not in signers for signer in valid):
        raise Error("Checksum signature was not made by a pinned release key")


def load_config():
    config = json.loads((ROOT / "config/zapdos.json").read_text())
    settings = {"username", "full_name", "locale", "timezone", "keyboard"}
    if not isinstance(config, dict) or set(config) != settings | {"ssh_public_keys"}:
        raise Error("zapdos.json must contain all install settings and SSH public keys")
    username = config["username"]
    if not isinstance(username, str) or not re.fullmatch(
        r"(?=.{1,32}$)[a-z_][a-z0-9_-]*\$?", username
    ):
        raise Error("Username must be a valid Debian account name")
    full_name = config["full_name"]
    if (
        not isinstance(full_name, str)
        or not full_name.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in full_name)
    ):
        raise Error("Full name must be a non-empty single line")
    locale = config["locale"]
    if not isinstance(locale, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", locale):
        raise Error("Locale must contain only letters, numbers, and locale separators")
    timezone = config["timezone"]
    if not isinstance(timezone, str) or not re.fullmatch(
        r"(?:[A-Za-z0-9_+-]+/)*[A-Za-z0-9_+-]+", timezone
    ):
        raise Error("Timezone must be an IANA timezone name")
    keyboard = config["keyboard"]
    if not isinstance(keyboard, str) or not re.fullmatch(r"[A-Za-z0-9,]+", keyboard):
        raise Error("Keyboard layout must contain only layout codes")
    keys = config["ssh_public_keys"]
    if not isinstance(keys, list) or not keys:
        raise Error("Add at least one Ed25519 SSH public key to config/zapdos.json")
    blobs = set()
    for key in keys:
        if not isinstance(key, str) or "\n" in key or "\r" in key:
            raise Error("SSH public keys must each be a single line")
        parts = key.split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise Error("Use plain Ed25519 public keys without authorized_keys options")
        try:
            raw = base64.b64decode(parts[1], validate=True)
        except ValueError as exc:
            raise Error("Invalid SSH public key encoding") from exc
        if len(raw) != 51 or raw[:19] != struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(
            ">I", 32
        ):
            raise Error("Invalid Ed25519 public key structure")
        if raw in blobs:
            raise Error("Each SSH public key must be listed only once")
        blobs.add(raw)
    return config


def yescrypt(password):
    for name in LIBCRYPT:
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        if hasattr(lib, "crypt_gensalt"):
            break
    else:
        raise Error("yescrypt needs libxcrypt; run just setup (macOS: brew install libxcrypt)")
    lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
    lib.crypt_gensalt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.crypt.restype = ctypes.c_char_p
    salt = lib.crypt_gensalt(b"$y$", 0, os.urandom(32), 32)
    value = (lib.crypt(password.encode(), salt) if salt else None) or b""
    if not re.fullmatch(YESCRYPT, value.decode()):
        raise Error("yescrypt hashing failed")
    return value.decode()


def read_secret(prompt, device="/dev/tty"):
    """Read a line from the terminal without echo, showing one dot per character."""
    with open(device, "r+b", buffering=0) as terminal:
        fd = terminal.fileno()
        saved = termios.tcgetattr(fd)
        terminal.write(prompt.encode())
        typed = bytearray()
        try:
            tty.setcbreak(fd, termios.TCSANOW)
            while (char := os.read(fd, 1)) not in (b"\r", b"\n"):
                if not char or (char == b"\x04" and not typed):
                    raise EOFError()
                if char in (b"\x7f", b"\b"):
                    if typed:
                        # Drop one whole UTF-8 character, then erase one dot.
                        while typed and typed.pop() & 0xC0 == 0x80:
                            pass
                        terminal.write(b"\b \b")
                elif char == b"\x1b":
                    # Discard arrow/function-key escape sequences.
                    if os.read(fd, 1) in (b"[", b"O"):
                        while (part := os.read(fd, 1)) and not 0x40 <= part[0] <= 0x7E:
                            pass
                elif char[0] >= 0x20:
                    typed += char
                    if char[0] & 0xC0 != 0x80:
                        terminal.write("•".encode())
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, saved)
            terminal.write(b"\n")
    return typed.decode(errors="replace")


def yescrypt_memory(value):
    """Return the memory cost (bytes) of a libxcrypt-encoded yescrypt hash, or None if unknown."""
    params = value.split("$")[2]
    if len(params) < 3 or params[0] != "j" or any(char not in ITOA64[:47] for char in params[1:3]):
        return None
    # Single-character fields encode value - 1 (N as log2), as in yescrypt's decode64_uint32.
    n_log2, r = ITOA64.index(params[1]) + 1, ITOA64.index(params[2]) + 1
    return 128 * r * 2**n_log2


def password_problem(password, username=None):
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Too short; use at least {PASSWORD_MIN_LENGTH} characters."
    if len(set(password)) < PASSWORD_MIN_DISTINCT:
        return f"Too repetitive; use at least {PASSWORD_MIN_DISTINCT} different characters."
    if username and username.lower() in password.lower():
        return "Do not include the username."
    return None


def prompt_password_hash(label="console/sudo password for the installed account", username=None):
    if not sys.stdin.isatty():
        raise Error("Run interactively to set the local password")
    print(f"Choose the {label} (input hidden).")
    for _ in range(3):
        password = read_secret(f"Password ({PASSWORD_MIN_LENGTH}+ characters): ")
        if problem := password_problem(password, username):
            print(problem)
        elif read_secret("Repeat password: ") != password:
            print("Passwords do not match.")
        else:
            return yescrypt(password)
    raise Error("Password not set; nothing was saved")


def read_credentials(path=None):
    """Parse config/credentials.yaml: "name: value" lines; blank lines and # comments are ignored."""
    path = path or CREDENTIALS
    if path.is_symlink() or not path.is_file():
        raise Error(f"{path} must be a regular file")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise Error(f"{path} must be owned by you with mode 0600 (chmod 600 {path})")
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not separator or key not in ("password_hash", "root_password_hash") or key in values:
            raise Error(f"{path} line {number}: expected password_hash: or root_password_hash:")
        values[key] = value
    return values


def check_hash(value, field="password_hash"):
    if not re.fullmatch(YESCRYPT, value):
        raise Error(f"{field} must be a Debian yescrypt ($y$) hash")
    memory = yescrypt_memory(value)
    if memory is None or memory < YESCRYPT_MIN_MEMORY:
        raise Error(f"{field} uses a weaker yescrypt cost than the libxcrypt default ($y$j9T$)")
    return value


def password_hash(path=None, root=False):
    """Return the account hash, or root's: its own optional hash, else the account's."""
    value = read_credentials(path)
    if "password_hash" not in value:
        raise Error("config/credentials.yaml must contain password_hash")
    field = "root_password_hash" if root and "root_password_hash" in value else "password_hash"
    return check_hash(value[field], field)


def has_root_password(path=None):
    return "root_password_hash" in read_credentials(path)


def configured_username():
    try:
        return json.loads((ROOT / "config/zapdos.json").read_text()).get("username")
    except (OSError, ValueError, AttributeError):
        return None


def set_password(hash_file=None, root=False):
    """Update one hash in config/credentials.yaml, keeping the other, from a prompt or a hash file."""
    field = "root_password_hash" if root else "password_hash"
    existing = read_credentials() if os.path.lexists(CREDENTIALS) else {}
    if root and "password_hash" not in existing:
        raise Error("Set the account password first (just password)")
    if hash_file is None:
        label = (
            "root console password" if root else "console/sudo password for the installed account"
        )
        value = prompt_password_hash(label, configured_username())
    else:
        value = Path(hash_file).read_text().strip()
        if not re.fullmatch(YESCRYPT, value):
            raise Error("Hash file must contain one Debian yescrypt ($y$) hash")
        check_hash(value, field)
        warn("Imported a hash; Zapdos cannot check the strength of the password behind it.")
    values = dict(existing, **{field: value})
    text = (
        "# Zapdos login password hashes (yescrypt). Kept out of git.\n"
        "# Run `just password` (account) or `just password root` to generate/update a hash.\n"
        f"password_hash: {values['password_hash']}\n"
    )
    if "root_password_hash" in values:
        text += f"root_password_hash: {values['root_password_hash']}\n"
    temporary = CREDENTIALS.with_name(".credentials.tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as out:
        out.write(text)
    os.replace(temporary, CREDENTIALS)
    ok(f"Saved the {'root' if root else 'account'} password hash to config/credentials.yaml.")


def fingerprint(config, secret):
    h = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
    for value in [secret] if isinstance(secret, str) else secret:
        h.update(b"\0" + value.encode() + b"\0")
    sources = [p for p in (ROOT / "debian").rglob("*") if p.is_file() and p.suffix != ".pyc"]
    for path in [ROOT / "zapdos.py", ROOT / "debian.py", *sorted(sources)]:
        h.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()


def decision(old, latest, config_hash):
    if old is None:
        return "write"
    if old.get("os", "debian") != latest.get("os", "debian"):
        return "write"
    if old.get("arch") != latest["arch"]:
        raise Error("Existing media has a different architecture; use a blank USB")
    before = version(old["version"])
    after = version(latest["version"])
    if before > after:
        raise Error("USB is newer than official current stable metadata; refusing downgrade")
    if before < after:
        return "upgrade"
    return "skip" if old["fingerprint"] == config_hash else "write"


def choose(devices, input_fn=None, *, device=None, yes=False):
    input_fn = input_fn or input
    eligible = [d for d in devices if d["reason"] == "eligible"]
    for candidate in devices:
        model = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", candidate["model"])[:80]
        number = f"{eligible.index(candidate) + 1})" if candidate in eligible else "-"
        line = f"{number:>3} {candidate['path']}: {model} | {candidate['size'] / 1e9:.1f} GB | {candidate['reason']}"
        print(paint("32;1" if candidate["reason"] == "eligible" else "90", line))
    if not eligible:
        raise Error("No eligible external USB. See inventory rejection reasons above.")
    if device is not None:
        selected = next((d for d in eligible if d["path"] == device), None)
        if selected is None:
            raise Error("Requested device is not an eligible whole USB; nothing written")
    elif yes:
        raise Error("--yes requires --device; nothing written")
    elif len(eligible) == 1:
        selected = eligible[0]
    else:
        answer = input_fn(
            f"Select the USB to ERASE [1-{len(eligible)}] or its device path (empty cancels): "
        ).strip()
        selected = next(
            (d for n, d in enumerate(eligible, 1) if answer in (str(n), d["path"])), None
        )
        if selected is None:
            raise Error("No eligible device selected; nothing written")
    model = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", selected["model"])[:80]
    question = (
        f"ERASE everything on {selected['path']} ({model}, {selected['size'] / 1e9:.1f} GB)? [y/N] "
    )
    if not yes and input_fn(paint("33;1", question)).strip().lower() not in ("y", "yes"):
        raise Error("USB not confirmed; nothing written")
    return selected


def protects(mount, paths):
    if not mount or mount == "[SWAP]":
        return mount == "[SWAP]"
    if mount in (
        "/",
        "/boot",
        "/boot/efi",
        "/usr",
        "/var",
        "/home",
        "/cdrom",
        "/System/Volumes/Data",
    ):
        return True
    if any(
        mount == prefix or mount.startswith(prefix + "/")
        for prefix in ("/run/live", "/run/initramfs", "/lib/live/mount")
    ):
        return True
    for p in paths:
        for parent in (p, *p.parents):
            if parent == Path(mount):
                return True
            try:
                # Case-insensitive names and mount aliases can defeat text comparisons.
                if Path(mount).samefile(parent):
                    return True
            except OSError:
                pass
    return False


def linux_devices(tree, protected):
    result = []

    def descendants(node):
        yield node
        for child in node.get("children", []):
            yield from descendants(child)

    for node in tree["blockdevices"]:
        if node["type"] != "disk":
            continue
        children = list(descendants(node))
        reason = "eligible"
        if node.get("tran") != "usb" or not node.get("hotplug"):
            reason = "not external USB transport/hotplug media"
        if node.get("ro") is not False or int(node.get("size", 0)) < 8_000_000_000:
            reason = "read-only, unknown writeability, or smaller than 8 GB"
        if any(c["type"] not in ("disk", "part") for c in children):
            reason = "RAID/LVM/active dependent device"
        if any(protects(m, protected) for c in children for m in c.get("mountpoints", []) or []):
            reason = "system/boot/swap or contains preparation files"
        if not (node.get("serial") or node.get("wwn")):
            reason = "no stable hardware serial/WWN; cannot revalidate safely"
        if not re.fullmatch(r"/dev/(sd[a-z]+|nvme\d+n\d+)", node["path"]):
            reason = "unsupported whole USB device path"
        identity = {k: node.get(k) for k in ("path", "size", "serial", "wwn", "maj:min", "tran")}
        result.append(
            {
                "path": node["path"],
                "raw": node["path"],
                "size": int(node["size"]),
                "model": node.get("model") or "unknown",
                "reason": reason,
                "identity": identity,
                "mounts": [m for c in children for m in c.get("mountpoints", []) or [] if m],
            }
        )
    return result


def mac_devices(infos, protected_disks):
    result = []
    for info in infos:
        path = info.get("DeviceNode", "")
        reason = "eligible"
        if info.get("Internal") is not False or info.get("BusProtocol") != "USB":
            reason = "not external USB transport"
        if (
            info.get("WholeDisk") is not True
            or info.get("Writable") is not True
            or info.get("TotalSize", 0) < 8_000_000_000
        ):
            reason = "not a writable whole disk of at least 8 GB"
        if info.get("DeviceIdentifier") in protected_disks:
            reason = "system/boot or contains preparation files"
        if not info.get("DeviceTreePath"):
            reason = "no physical device identity; cannot revalidate safely"
        if not re.fullmatch(r"/dev/disk\d+", path):
            reason = "unsupported physical disk path"
        identity = {
            k: info.get(k)
            for k in ("DeviceNode", "DeviceTreePath", "TotalSize", "MediaName", "DiskUUID")
        }
        result.append(
            {
                "path": path,
                "raw": path.replace("/dev/disk", "/dev/rdisk"),
                "model": info.get("MediaName", "unknown"),
                "size": int(info.get("TotalSize", 0)),
                "identity": identity,
                "reason": reason,
                "mounts": [],
            }
        )
    return result


def inventory(protected):
    system = platform.system()
    protected = [Path(p).resolve() for p in protected] + [ROOT.resolve()]
    if system == "Linux":
        require("lsblk")
        tree = json.loads(
            run(
                [
                    "lsblk",
                    "--json",
                    "--bytes",
                    "--paths",
                    "--output",
                    "PATH,TYPE,SIZE,TRAN,RM,RO,MODEL,SERIAL,WWN,HOTPLUG,MOUNTPOINTS,MAJ:MIN",
                ]
            )
        )
        return linux_devices(tree, protected)
    if system != "Darwin":
        raise Error("Only macOS and Linux preparation hosts are supported")
    listing = plistlib.loads(run(["diskutil", "list", "-plist", "physical"]))
    infos, protected_disks = [], set()
    for disk in listing["WholeDisks"]:
        info = plistlib.loads(run(["diskutil", "info", "-plist", disk]))
        infos.append(info)
    all_disks = plistlib.loads(run(["diskutil", "list", "-plist"]))
    for disk in all_disks["AllDisks"]:
        info = plistlib.loads(run(["diskutil", "info", "-plist", disk]))
        if protects(info.get("MountPoint"), protected):
            protected_disks.add(info.get("ParentWholeDisk", info["DeviceIdentifier"]))
    # APFS volumes are synthesized disks: map protected containers to every physical store.
    apfs = plistlib.loads(run(["diskutil", "apfs", "list", "-plist"]))
    for container in apfs.get("Containers", []):
        if container["ContainerReference"] in protected_disks or any(
            protects(v.get("MountPoint"), protected) for v in container.get("Volumes", [])
        ):
            for store in container["PhysicalStores"]:
                info = plistlib.loads(
                    run(["diskutil", "info", "-plist", store["DeviceIdentifier"]])
                )
                protected_disks.add(info.get("ParentWholeDisk", info["DeviceIdentifier"]))
    return mac_devices(infos, protected_disks)


def inspect_manifest(raw, work):
    # Distinguish unreadable media from media without our manifest.
    try:
        with open(raw, "rb") as disk:
            disk.read(1)
    except OSError as exc:
        raise Error(
            f"Cannot read {raw}; grant disk access/read permission before preparation"
        ) from exc
    # xorriso treats raw character devices as unsupported; read the block node through stdio.
    device = "stdio:" + re.sub(r"^/dev/rdisk", "/dev/disk", str(raw))
    manifest = work / "old-manifest.json"
    result = subprocess.run(
        [
            "xorriso",
            "-abort_on",
            "FAILURE",
            "-osirrox",
            "on",
            "-indev",
            device,
            "-extract",
            "/zapdos/manifest.json",
            str(manifest),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not manifest.exists() and not manifest.is_symlink():
        if b"Permission denied" in result.stderr or b"Input/output error" in result.stderr:
            raise Error("USB inspection failed; refusing to overwrite unreadable media")
        import debian

        return debian.stock_media(device, work)
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 4096:
        raise Error("Existing manifest is not a small regular file; refusing overwrite")
    try:
        old = json.loads(manifest.read_text())
        if (
            old["schema"] != 1
            or old.get("os", "debian") != "debian"
            or old["arch"] not in ("amd64", "arm64")
            or not re.fullmatch(r"[0-9a-f]{64}", old["fingerprint"])
        ):
            raise ValueError()
        version(old["version"])
    except (Error, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise Error("Invalid existing zapdos manifest; refusing automatic overwrite") from exc
    result = {key: old[key] for key in ("schema", "version", "arch", "fingerprint")}
    if "os" in old:
        result["os"] = "debian"
    return result


def inspect_usb(selected, work, *, unattended=False):
    revalidate(selected, [work, ROOT])
    if os.access(selected["raw"], os.R_OK):
        old = inspect_completed(selected, work)
        revalidate(selected, [work, ROOT])
        return old
    require("sudo")
    # Leave stderr on the terminal so sudo prompts and diagnostics stay visible.
    result = subprocess.run(
        [
            "sudo",
            *(["-n"] if unattended else []),
            sys.executable,
            str(ROOT / "zapdos.py"),
            "_inspect",
            "--selected",
            json.dumps(selected),
        ],
        stdout=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise Error(f"USB inspection failed (exit {result.returncode}); nothing written")
    return json.loads(result.stdout)


def inspect_completed(selected, work):
    with open(selected["raw"], "rb") as disk:
        disk.seek(selected["size"] - RECEIPT_SIZE)
        receipt = disk.read(RECEIPT_SIZE)
        if not receipt.startswith(RECEIPT_MAGIC):
            # A readable manifest alone can survive an interrupted write.
            old = inspect_manifest(selected["raw"], work)
            if old is not None:
                old["fingerprint"] = None
            return old
        try:
            record = json.loads(receipt[len(RECEIPT_MAGIC) :].rstrip(b"\0"))
            size, digest = record["size"], record["sha256"]
            if (
                type(size) is not int
                or not 0 < size <= selected["size"] - RECEIPT_SIZE
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ValueError()
        except (ValueError, KeyError, TypeError) as exc:
            raise Error("Invalid USB completion record; refusing automatic overwrite") from exc
        disk.seek(0)
        actual = hashlib.sha256()
        remaining = size
        with spinner("Verifying existing USB readback") as status:
            status.detail = bar(0, size, "32")
            while remaining:
                block = disk.read(min(remaining, CHUNK))
                if not block:
                    raise Error("USB integrity read ended early")
                actual.update(block)
                remaining -= len(block)
                status.detail = bar(size - remaining, size, "32")
        if actual.hexdigest() != digest:
            raise Error("Previously completed USB is corrupt; do not boot it or trust its manifest")
    old = inspect_manifest(selected["raw"], work)
    if old is None or old["fingerprint"] is None:
        raise Error("Completed USB has no valid zapdos manifest; refusing automatic overwrite")
    return old


def newc(files):
    """Small append-only initramfs archive; avoids host-specific cpio behavior."""
    archive = bytearray()
    for ino, (name, (data, mode)) in enumerate([*files.items(), ("TRAILER!!!", (b"", 0))], 1):
        name = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        archive.extend(b"070701" + "".join(f"{v:08x}" for v in fields).encode() + name)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))
    return bytes(archive)


def extract(iso, source, destination):
    run(
        [
            "xorriso",
            "-abort_on",
            "FAILURE",
            "-osirrox",
            "on",
            "-indev",
            iso,
            "-extract",
            source,
            destination,
        ]
    )


def revalidate(selected, protected):
    current = next((d for d in inventory(protected) if d["path"] == selected["path"]), None)
    if (
        current is None
        or current["reason"] != "eligible"
        or current["identity"] != selected["identity"]
    ):
        raise Error("Selected USB identity or eligibility changed; refusing to write")
    return current


def copy_verify(fd, capacity, image, flush):
    # Open before erasing so a missing/unreadable/replaced source cannot destroy a USB.
    with image.open("rb") as source:
        return copy_open_image(fd, capacity, source, flush)


def copy_open_image(fd, capacity, source, flush):
    info = os.fstat(source.fileno())
    size = info.st_size
    if not stat.S_ISREG(info.st_mode) or size <= 0:
        raise Error("Source image must be a nonempty regular file")
    if size + RECEIPT_SIZE > capacity:
        raise Error("USB is smaller than customized DVD image")
    os.lseek(fd, 0, os.SEEK_SET)
    zero = b"\0" * CHUNK
    # Clear only the partition tables and filesystem signatures at both ends (including any
    # backup GPT, Ventoy's trailing partition, and the completion record). Zero-filling the
    # whole medium takes hours on slow flash and adds nothing: the new image defines the layout.
    if capacity <= 2 * ERASE_EDGE:
        regions = [(0, capacity)]
    else:
        regions = [(0, ERASE_EDGE), (capacity - ERASE_EDGE, capacity)]
    total = sum(end - start for start, end in regions)
    done = 0
    with spinner("Erasing USB") as s:
        s.detail = bar(0, total, "33")
        for start, end in regions:
            os.lseek(fd, start, os.SEEK_SET)
            remaining = end - start
            while remaining:
                written = os.write(fd, zero[: min(remaining, CHUNK)])
                if written <= 0:
                    raise Error("USB erase made no progress")
                remaining -= written
                done += written
                s.detail = bar(done, total, "33")
    os.lseek(fd, 0, os.SEEK_SET)
    expected = hashlib.sha256()
    remaining = size
    with spinner("Writing installer") as s:
        s.detail = bar(0, size)
        while remaining:
            block = source.read(min(remaining, CHUNK))
            if not block:
                raise Error("Source image ended early; USB is incomplete")
            expected.update(block)
            view = memoryview(block)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise Error("USB write made no progress")
                view = view[n:]
                remaining -= n
                s.detail = bar(size - remaining, size)
        after = os.fstat(source.fileno())
        if source.read(1) or any(
            getattr(after, field) != getattr(info, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise Error("Source image changed during the write; USB is incomplete")
    with spinner("Flushing USB writes"):
        os.fsync(fd)
        flush(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    actual = hashlib.sha256()
    remaining = size
    with spinner("Verifying readback") as s:
        s.detail = bar(0, size, "32")
        while remaining:
            block = os.read(fd, min(remaining, CHUNK))
            if not block:
                raise Error("USB readback ended early")
            actual.update(block)
            remaining -= len(block)
            s.detail = bar(size - remaining, size, "32")
        if actual.digest() != expected.digest():
            raise Error("USB readback hash mismatch; do not use this medium")
    # Publish completion only after the full image has passed flushed readback.
    receipt = (
        RECEIPT_MAGIC + json.dumps({"size": size, "sha256": actual.hexdigest()}).encode()
    ).ljust(RECEIPT_SIZE, b"\0")
    with spinner("Saving completion record"):
        os.lseek(fd, capacity - RECEIPT_SIZE, os.SEEK_SET)
        view = memoryview(receipt)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise Error("USB completion record write made no progress")
            view = view[n:]
        os.fsync(fd)
        flush(fd)
        os.lseek(fd, capacity - RECEIPT_SIZE, os.SEEK_SET)
        if os.read(fd, RECEIPT_SIZE) != receipt:
            raise Error("USB completion record readback failed; USB is incomplete")
    return actual.hexdigest()


def write_usb(selected, image):
    # Called only by the privileged worker, after all signature/build checks completed.
    if os.geteuid() != 0:
        raise Error("USB write worker requires root")
    if not image.is_file() or image.is_symlink():
        raise Error("Source image must be a regular file")
    protected = [image, ROOT]
    current = revalidate(selected, protected)
    if platform.system() == "Darwin":
        run(["diskutil", "unmountDisk", current["path"]])
    else:
        for mount in sorted(set(current["mounts"]), key=len, reverse=True):
            run(["umount", "--", mount])
    revalidate(selected, protected)
    flags = os.O_RDWR | os.O_NOFOLLOW
    if platform.system() == "Linux":
        flags |= os.O_EXCL
    fd = os.open(current["raw"], flags)
    try:
        info = os.fstat(fd)
        if platform.system() == "Linux":
            if not stat.S_ISBLK(info.st_mode):
                raise Error("Write target is not a block device")
            expected = selected["identity"]["maj:min"]
            if f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" != expected:
                raise Error("Opened device identity mismatch")
            flush = lambda descriptor: fcntl.ioctl(descriptor, 0x1261)  # BLKFLSBUF
        else:
            if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.stat(current["raw"]).st_rdev:
                raise Error("Write target is not the selected raw disk")
            fcntl.fcntl(fd, 48, 1)  # F_NOCACHE: raw-device readback bypasses host cache.
            flush = lambda descriptor: fcntl.ioctl(
                descriptor, 0x20006416
            )  # DKIOCSYNCHRONIZECACHE (_IO('d', 22))
        revalidate(selected, protected)
        note("Erasing selected USB and writing verified installer…")
        digest = copy_verify(fd, current["size"], image, flush)
        ok(f"Verified image-sized readback on {current['path']}: SHA-256 {digest}")
    finally:
        os.close(fd)
    if platform.system() == "Darwin":
        with spinner("Ejecting USB"):
            run(["diskutil", "eject", current["path"]])
        ok(f"Ejected {current['path']}; safe to unplug.")


def save_image(image, destination):
    if os.path.lexists(destination):
        raise Error("Output must be a new file")
    # Publish a complete file exclusively; failed copies never leave a bootable-looking output.
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".zapdos-", mode="wb") as out:
        with image.open("rb") as source:
            shutil.copyfileobj(source, out)
        out.flush()
        os.fsync(out.fileno())
        os.link(out.name, destination, follow_symlinks=False)


def ventoy_mounts(disks):
    """Writable data mounts of disks that carry Ventoy's VTOYEFI partition."""
    found = []
    for partitions in disks:
        labels = [label for label, _ in partitions]
        if "VTOYEFI" not in labels:
            continue
        for label, mount in partitions:
            if label != "VTOYEFI" and mount and os.access(mount, os.W_OK):
                found.append(Path(mount))
    return found


def ventoy_folder():
    """The one attached Ventoy drive's ISO folder, or None to use the default output."""
    try:
        if platform.system() == "Darwin":
            disks = []
            for disk in plistlib.loads(run(["diskutil", "list", "-plist", "external", "physical"]))[
                "AllDisksAndPartitions"
            ]:
                partitions = []
                for part in disk.get("Partitions", []):
                    info = plistlib.loads(
                        run(["diskutil", "info", "-plist", part["DeviceIdentifier"]])
                    )
                    partitions.append((info.get("VolumeName") or "", info.get("MountPoint") or ""))
                disks.append(partitions)
        elif platform.system() == "Linux" and shutil.which("lsblk"):
            tree = json.loads(run(["lsblk", "--json", "--output", "TYPE,LABEL,MOUNTPOINT"]))
            disks = [
                [(c.get("label") or "", c.get("mountpoint") or "") for c in d.get("children", [])]
                for d in tree["blockdevices"]
                if d["type"] == "disk"
            ]
        else:
            return None
    except (Error, OSError, ValueError, KeyError):
        return None
    mounts = ventoy_mounts(disks)
    if len(mounts) != 1:
        if mounts:
            note("Multiple Ventoy drives attached; saving to build/ instead")
        return None
    folder = mounts[0] / "ISO"
    return folder if folder.is_dir() else mounts[0]


def prepare(args):
    started = time.monotonic()
    unattended = getattr(args, "yes", False)
    device = getattr(args, "device", None)
    if unattended and not device:
        raise Error("--yes requires --device; nothing written")
    if unattended and os.geteuid() != 0:
        # Fail before downloads or customization instead of prompting halfway through a job.
        run(["sudo", "-n", "true"])
    import debian as target

    if args.arch not in target.ARCHES:
        raise Error(f"{target.PRODUCT} supports only: " + ", ".join(target.ARCHES))
    require("xorriso", "gpg")
    config = target.configure(load_config(), args)
    secrets = CREDENTIALS
    if not os.path.lexists(secrets):
        if unattended:
            raise Error(
                "No config/credentials.yaml yet; run just once interactively (or just password)"
            )
        set_password()
    secret = target.secrets(secrets)
    if not has_root_password(secrets):
        warn("Root shares the account password. Run `just password root` to give root its own.")
    config_hash = fingerprint(config, secret)
    cache = args.cache.resolve()
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        cache.is_symlink()
        or cache.stat().st_uid != os.geteuid()
        or stat.S_IMODE(cache.stat().st_mode) & 0o077
    ):
        raise Error("Cache must be owned by you and have mode 0700")
    with (cache / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="work-", dir=cache) as directory:
            work = Path(directory)
            selected = None
            if args.command == "prepare":
                selected = choose(inventory([cache, secrets]), device=device, yes=unattended)
                note("Inspecting selected USB…")
                old = inspect_usb(selected, work, unattended=unattended)
            else:
                old = None
            with spinner(f"Checking latest {target.PRODUCT} release"):
                latest = target.discover(args.arch, work)
            ok(f"Latest authenticated {target.PRODUCT}: {latest['version']} ({args.arch})")
            action = decision(old, latest, config_hash)
            if action == "skip":
                if platform.system() == "Darwin":
                    revalidate(selected, [cache, secrets])
                    with spinner("Ejecting verified USB"):
                        run(["diskutil", "eject", selected["path"]])
                ok(
                    f"Ready: {target.PRODUCT} {latest['version']} {args.arch} on {selected['path']}; "
                    f"existing contents verified, no rewrite needed"
                    + (", ejected" if platform.system() == "Darwin" else "")
                    + f" ({time.monotonic() - started:.1f}s)."
                )
                return
            if action == "upgrade":
                print(f"USB {target.PRODUCT} {old['version']} → {latest['version']}")
                if not unattended and input(
                    "Upgrade and erase this USB? [y/N] "
                ).strip().lower() not in ("y", "yes"):
                    print("Upgrade declined; USB untouched.")
                    return
            iso = target.verified_iso(latest, cache)
            image = work / "zapdos.iso"
            with spinner("Customizing installer image"):
                target.build_image(iso, latest, config, secret, config_hash, work, image)
            if selected:
                revalidate(selected, [cache, secrets, image])
                # Privilege is limited to unmount/write/readback.
                command = [
                    sys.executable,
                    str(ROOT / "zapdos.py"),
                    "_write",
                    "--image",
                    str(image),
                    "--selected",
                    json.dumps(selected),
                ]
                if os.geteuid() != 0:
                    command = ["sudo", *(["-n"] if unattended else []), *command]
                process = subprocess.Popen(command)
                try:
                    returncode = process.wait()
                except BaseException:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    raise
                if returncode:
                    raise Error("USB write/verification/eject failed; do not use the medium")
                ok(
                    f"Ready: {target.PRODUCT} {latest['version']} {args.arch}; "
                    f"accounts {config['username']} + root; {selected['path']} verified"
                    + (" and ejected" if platform.system() == "Darwin" else "")
                    + f" ({time.monotonic() - started:.1f}s)."
                )
            else:
                if args.output is None:
                    folder = ventoy_folder()
                    if folder:
                        note(f"Ventoy drive detected; saving the ISO directly to {folder}")
                    else:
                        folder = ROOT / "build"
                        folder.mkdir(mode=0o700, exist_ok=True)
                    stamp = time.strftime("%Y%m%d-%H%M%S")
                    args.output = folder / f"zapdos-{target.NAME}-{args.arch}-{stamp}.iso"
                destination = args.output.absolute()
                save_image(image, destination)
                ok(f"Installer image saved: {destination} (contains the password hash; mode 0600)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True, metavar="{prepare,build,password}")
    for name in ("prepare", "build"):
        command = sub.add_parser(name)
        command.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
        command.add_argument("--cache", type=Path, default=ROOT / ".cache")
        if name == "build":
            command.add_argument("--output", type=Path)
        else:
            command.add_argument("--device", help="eligible whole USB path, e.g. /dev/disk4")
            command.add_argument(
                "--yes",
                action="store_true",
                help="approve erase/upgrade without prompts; requires --device and ready sudo",
            )
    setup = sub.add_parser("password")
    setup.add_argument("--hash-file", type=Path)
    setup.add_argument("--root", action="store_true", help="set root's separate console password")
    worker = sub.add_parser("_write")
    worker.add_argument("--image", type=Path, required=True)
    worker.add_argument("--selected", required=True)
    inspector = sub.add_parser("_inspect")
    inspector.add_argument("--selected", required=True)
    args = parser.parse_args()
    os.umask(0o077)

    def interrupted(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.command == "password":
            set_password(args.hash_file, root=args.root)
        elif args.command == "_write":
            write_usb(json.loads(args.selected), args.image)
        elif args.command == "_inspect":
            selected = json.loads(args.selected)
            revalidate(selected, [ROOT])
            with tempfile.TemporaryDirectory(prefix="zapdos-inspect-") as directory:
                with contextlib.redirect_stdout(sys.stderr):
                    old = inspect_completed(selected, Path(directory))
                revalidate(selected, [ROOT])
                print(json.dumps(old))
        else:
            prepare(args)
    except (Error, OSError, ValueError, KeyError) as exc:
        print(paint("31;1", f"Error: {exc}", sys.stderr), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled. If writing had started, treat the USB as incomplete.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

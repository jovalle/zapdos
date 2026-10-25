"""Authenticated Debian DVD-1 media with an unattended preseed installer."""

import gzip
import io
import json
import lzma
import re
import shutil
import stat
import subprocess
import tarfile

import zapdos as z

NAME = "debian"
PRODUCT = "Debian"
ARCHES = ("amd64", "arm64")
VERSION = r"\d+\.\d+\.\d+"
CD = "https://cdimage.debian.org/debian-cd"
SIGNERS = {"10460DAD76165AD81FBC0CE9988021A964E6EA7D", "DF9B9C49EAA9298432589D76DA87E80D6294BE9B"}


def configure(config, args):
    return config


def secrets(path):
    return [z.password_hash(path), z.password_hash(path, root=True)]


def release(sums, arch):
    pattern = rf"([0-9a-f]{{128}})  (debian-(\d+\.\d+\.\d+)-{arch}-DVD-1\.iso)"
    matches = [m for line in sums.splitlines() if (m := re.fullmatch(pattern, line))]
    if len(matches) != 1:
        raise z.Error(f"Expected exactly one official {arch} stable DVD-1 checksum")
    digest, name, number = matches[0].groups()
    return {"version": number, "arch": arch, "name": name, "sha512": digest}


def discover(arch, work):
    z.require("gpg")
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    for signer in sorted(SIGNERS):
        key = work / (signer + ".asc")
        z.download(f"https://www.debian.org/CD/key-{signer[-16:]}.txt", key, 100_000)
        listing = z.run(
            [
                "gpg",
                "--homedir",
                home,
                "--batch",
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                key,
            ]
        ).decode()
        primaries = re.findall(r"^pub:.*\n(?:[^\n]*\n)*?fpr:::::::::([0-9A-F]+):", listing, re.M)
        if primaries != [signer]:
            raise z.Error("Downloaded Debian signing key fingerprint did not match the pin")
        z.run(["gpg", "--homedir", home, "--batch", "--import", key])
    base = f"{CD}/current/{arch}/iso-dvd"
    sums, signature = work / "SHA512SUMS", work / "SHA512SUMS.sign"
    z.download(base + "/SHA512SUMS", sums, 1_000_000)
    z.download(base + "/SHA512SUMS.sign", signature, 100_000)
    z.verify_signature(home, sums, signature, SIGNERS)
    return release(sums.read_text(), arch)


def stock_media(source, work):
    """Stock Debian media has a version label but no configuration fingerprint."""
    info = work / "old-debian-info"
    result = subprocess.run(
        [
            "xorriso",
            "-abort_on",
            "FAILURE",
            "-osirrox",
            "on",
            "-indev",
            source,
            "-extract",
            "/.disk/info",
            str(info),
        ],
        capture_output=True,
    )
    if b"Permission denied" in result.stderr or b"Input/output error" in result.stderr:
        raise z.Error("USB version inspection failed; refusing overwrite")
    if info.exists() or info.is_symlink():
        if info.is_symlink() or not info.is_file() or info.stat().st_size > 4096:
            raise z.Error("Existing Debian version label is not a small regular file")
        match = re.match(
            r'^Debian GNU/Linux (\d+\.\d+\.\d+) "[^"\r\n]+" - Official (amd64|arm64) ',
            info.read_text(),
        )
        if match:
            number, arch = match.groups()
            return {"schema": 1, "version": number, "arch": arch, "fingerprint": None}
    return None


def verified_iso(latest, cache):
    path = cache / latest["name"]
    if not path.exists():
        with z.spinner(
            f"Downloading official Debian {latest['version']} {latest['arch']} DVD-1"
        ) as s:

            def progress(done, total):
                s.detail = (
                    f"{done / 1e9:.2f} / {total / 1e9:.2f} GB" if total else f"{done / 1e9:.2f} GB"
                )

            z.download(
                f"{CD}/{latest['version']}/{latest['arch']}/iso-dvd/{latest['name']}",
                path,
                progress=progress,
            )
    with z.spinner("Verifying DVD SHA-512"):
        if not path.is_file() or path.is_symlink() or z.sha(path, "sha512") != latest["sha512"]:
            raise z.Error("DVD checksum verification failed; remove the bad cached ISO and retry")
    z.ok("Official DVD signature and SHA-512 verified.")
    return path


def render_install_template(template, config):
    for key in ("username", "full_name", "locale", "timezone", "keyboard"):
        template = template.replace(f"@{key.upper()}@", config[key])
    return template


def newc_file(archive, wanted):
    """Return one regular file from an uncompressed newc archive (or concatenated archives)."""
    offset = 0
    while offset + 110 <= len(archive):
        header = archive[offset : offset + 110]
        if header[:6] != b"070701":
            if not archive[offset:].strip(b"\0"):
                break
            raise z.Error("Unsupported Debian installer initrd archive")
        fields = [int(header[i : i + 8], 16) for i in range(6, 110, 8)]
        size, name_size = fields[6], fields[11]
        name_start = offset + 110
        name = (
            archive[name_start : name_start + name_size].rstrip(b"\0").decode().removeprefix("./")
        )
        data_start = name_start + name_size + (-(110 + name_size) % 4)
        if name == wanted and stat.S_ISREG(fields[1]):
            return archive[data_start : data_start + size]
        offset = data_start + size + (-size % 4)
        if name == "TRAILER!!!":
            # Skip padding between concatenated archives.
            while offset < len(archive) and archive[offset] == 0:
                offset += 1
    raise z.Error(f"Debian installer initrd lacks {wanted}")


def deb_data(path):
    """Open the data archive of a .deb (an ar archive) as a tarfile."""
    content = path.read_bytes()
    if content[:8] != b"!<arch>\n":
        raise z.Error(f"{path.name} is not a Debian package")
    offset = 8
    while offset + 60 <= len(content):
        header = content[offset : offset + 60]
        name, size = header[:16].decode().strip().rstrip("/"), int(header[48:58])
        if name in ("data.tar.xz", "data.tar.gz", "data.tar"):
            return tarfile.open(fileobj=io.BytesIO(content[offset + 60 : offset + 60 + size]))
        offset += 60 + size + size % 2
    raise z.Error(f"{path.name} has no supported data archive")


def dvd_package(iso, folder, prefix, work):
    listing = z.run(
        ["xorriso", "-indev", iso, "-find", folder, "-name", prefix + "_*.deb"], quiet=True
    )
    names = [line.strip("'") for line in listing.decode().splitlines() if line.startswith("'")]
    if len(names) != 1:
        raise z.Error(f"Expected exactly one {prefix} package on the DVD")
    path = work / (prefix + ".deb")
    z.extract(iso, names[0], path)
    return path


def supported_settings(iso, initrd, work):
    """Timezones, locales and keyboard layouts that this authenticated DVD can install unattended."""
    with deb_data(dvd_package(iso, "/pool/main/t/tzdata", "tzdata", work)) as archive:
        zones = {
            member.name.removeprefix("./usr/share/zoneinfo/")
            for member in archive.getmembers()
            if member.name.startswith("./usr/share/zoneinfo/")
            and (member.isfile() or member.issym())
            and "." not in member.name.rsplit("/", 1)[-1]
            and not member.name.startswith(
                ("./usr/share/zoneinfo/posix/", "./usr/share/zoneinfo/right/")
            )
        } - {"leapseconds", "leap-seconds", "SECURITY"}
    with deb_data(dvd_package(iso, "/pool/main/g/glibc", "locales", work)) as archive:
        listing = archive.extractfile("./usr/share/i18n/SUPPORTED")
        if listing is None:
            raise z.Error("DVD locales package lacks its SUPPORTED list")
        locales = {line.split()[0] for line in listing.read().decode().splitlines() if line.strip()}
    templates = newc_file(
        gzip.decompress(initrd.read_bytes()), "var/lib/dpkg/info/console-setup-udeb.templates"
    ).decode()
    choices = re.search(
        r"^Template: keyboard-configuration/xkb-keymap\n(?:.+\n)*?Choices-C: (.+)$", templates, re.M
    )
    if not choices:
        raise z.Error("Debian installer lacks its keyboard layout list")
    # Only plain layouts: the config writes the layout code, not an XKB "layout(variant)".
    layouts = {choice for choice in choices[1].split(", ") if "(" not in choice}
    return zones, locales, layouts


def check_settings(config, supported):
    zones, locales, layouts = supported
    if config["timezone"] not in zones:
        raise z.Error(f"Timezone {config['timezone']} is not in this Debian release's tzdata")
    if config["locale"] not in locales:
        raise z.Error(
            f"Locale {config['locale']} is not supported by this Debian release (e.g. en_US.UTF-8)"
        )
    unknown = [layout for layout in config["keyboard"].split(",") if layout not in layouts]
    if unknown:
        raise z.Error("Keyboard layout not offered by the Debian installer: " + ", ".join(unknown))


def build_image(iso, latest, config, secrets, config_hash, work, output):
    z.require("xorriso")
    secret, root_secret = secrets
    boot = "install.amd" if latest["arch"] == "amd64" else "install.a64"
    original = work / "initrd.gz"
    z.extract(iso, f"/{boot}/initrd.gz", original)
    z.extract(iso, f"/{boot}/vmlinuz", work / "vmlinuz")
    check_settings(config, supported_settings(iso, original, work))
    # Validate the DVD contains every explicitly requested offline package + signed boot chain.
    packages = work / "packages"
    z.extract(iso, "/dists", packages)
    package_names = set()
    for file in packages.rglob("Packages*"):
        if file.name == "Packages.gz":
            content = gzip.decompress(file.read_bytes())
        elif file.name == "Packages.xz":
            content = lzma.decompress(file.read_bytes())
        elif file.name == "Packages":
            content = file.read_bytes()
        else:
            continue
        package_names.update(re.findall(rb"^Package: ([^\n]+)", content, re.M))
    needed = {
        "openssh-server",
        "sudo",
        "efibootmgr",
        "dhcpcd-base",
        "ca-certificates",
        "ifupdown",
        "console-setup",
        "keyboard-configuration",
        "shim-signed",
        f"grub-efi-{latest['arch']}-signed",
    }
    if not all(p.encode() in package_names for p in needed):
        raise z.Error(
            "DVD-1 lacks required offline packages: "
            + ", ".join(sorted(p for p in needed if p.encode() not in package_names))
        )
    files = {"zapdos": (b"", stat.S_IFDIR | 0o700)}
    for file in sorted((z.ROOT / "debian").iterdir()):
        if file.is_file() and file.name != "preseed.cfg":
            content = render_install_template(file.read_text(), config).encode()
            files["zapdos/" + file.name] = (content, stat.S_IFREG | 0o600)
    preseed = render_install_template((z.ROOT / "debian/preseed.cfg").read_text(), config)
    preseed = preseed.replace("@YESCRYPT@", secret)
    preseed = preseed.replace("@ROOT_YESCRYPT@", root_secret)
    preseed = preseed.replace("@SIGNED_GRUB@", f"grub-efi-{latest['arch']}-signed")
    files["preseed.cfg"] = (preseed.encode(), stat.S_IFREG | 0o600)
    files["zapdos/authorized_keys"] = (
        ("\n".join(config["ssh_public_keys"]) + "\n").encode(),
        stat.S_IFREG | 0o600,
    )
    files["zapdos/arch"] = (latest["arch"].encode(), stat.S_IFREG | 0o600)
    # Scripts invoked as /bin/sh do not need executable permission.
    initrd = work / "custom-initrd.gz"
    with initrd.open("wb") as out:
        with original.open("rb") as source:
            shutil.copyfileobj(source, out)
        out.write(gzip.compress(z.newc(files), mtime=0))
    manifest = work / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "version": latest["version"],
                "arch": latest["arch"],
                "fingerprint": config_hash,
                "official_sha512": latest["sha512"],
            },
            indent=2,
        )
        + "\n"
    )
    grub = work / "grub.cfg"
    grub.write_text(f"""set default=0
set timeout=3
menuentry 'Zapdos unattended Debian — ERASES the selected internal disk' {{
    linux /{boot}/vmlinuz auto=true priority=critical --- quiet
    initrd /{boot}/initrd.gz
}}
""")
    command = [
        "xorriso",
        "-abort_on",
        "FAILURE",
        "-indev",
        iso,
        "-outdev",
        output,
        "-boot_image",
        "any",
        "discard",
        "-boot_image",
        "any",
        "system_area=/dev/zero",
        "-map",
        initrd,
        f"/{boot}/initrd.gz",
        "-map",
        grub,
        "/boot/grub/grub.cfg",
        "-map",
        manifest,
        "/zapdos/manifest.json",
    ]
    if latest["arch"] == "amd64":
        bios = work / "isolinux.cfg"
        bios.write_text("SERIAL 0 115200\nDISPLAY /isolinux/zapdos.txt\nPROMPT 1\nTIMEOUT 0\n")
        message = work / "bios-message.txt"
        message.write_text(
            "Zapdos requires UEFI with Secure Boot. Select the UEFI USB entry in firmware.\n"
        )
        command += ["-map", bios, "/isolinux/isolinux.cfg", "-map", message, "/isolinux/zapdos.txt"]
    # A standard GPT ESP is readable by macOS; the vendor's hybrid APM labels FAT as HFS.
    if latest["arch"] == "amd64":
        command += [
            "-boot_image",
            "isolinux",
            "bin_path=/isolinux/isolinux.bin",
            "-boot_image",
            "isolinux",
            "boot_info_table=on",
            "-boot_image",
            "any",
            "cat_path=/isolinux/boot.cat",
            "-boot_image",
            "any",
            "next",
        ]
    command += [
        "-boot_image",
        "any",
        "efi_path=/boot/grub/efi.img",
        "-boot_image",
        "any",
        "efi_boot_part=--efi-boot-image",
    ]
    z.run(command + ["-commit", "-end"])
    output.chmod(0o600)
    # Signed EFI PE binaries and installer kernel must survive customization byte-for-byte.
    before, after = work / "efi-original", work / "efi-custom"
    z.extract(iso, "/EFI", before)
    z.extract(output, "/EFI", after)

    def hashes(folder):
        return {str(p.relative_to(folder)): z.sha(p) for p in folder.rglob("*") if p.is_file()}

    if hashes(before) != hashes(after) or not any(
        p.suffix.lower() == ".efi" for p in before.rglob("*")
    ):
        raise z.Error("Signed UEFI components changed or are absent")
    z.extract(output, f"/{boot}/vmlinuz", work / "custom-vmlinuz")
    if z.sha(work / "vmlinuz") != z.sha(work / "custom-vmlinuz"):
        raise z.Error("Installer kernel changed")
    z.extract(iso, "/boot/grub/efi.img", work / "efi-original.img")
    z.extract(output, "/boot/grub/efi.img", work / "efi-custom.img")
    if z.sha(work / "efi-original.img") != z.sha(work / "efi-custom.img"):
        raise z.Error("UEFI boot partition changed")
    # Rebuilt media no longer matches the vendor md5sum.txt for modified installer files.
    # shortcut: vendor media-check menu is not supported; use our full write/readback check.
    result = subprocess.run(
        [
            "xorriso",
            "-indev",
            str(output),
            "-report_el_torito",
            "plain",
            "-report_system_area",
            "plain",
        ],
        capture_output=True,
    )
    report = result.stdout + result.stderr
    if (
        result.returncode
        or b"UEFI" not in report
        or b"APM" in report
        or b"GPT type GUID" not in report
        or b"28732ac11ff8d211ba4b00a0c93ec93b" not in report
    ):
        raise z.Error("Customized image lacks a standard GPT EFI System Partition")

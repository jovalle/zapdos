<p align="center">
  <img src="assets/zapdos.png" alt="Zapdos logo" width="160" height="160">
</p>

<h1 align="center">Zapdos</h1>

<p align="center">Zap baremetal hosts into Debian</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&amp;logo=python&amp;logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Debian-stable-A81D33?style=flat-square&amp;logo=debian&amp;logoColor=white" alt="Debian stable">
</p>

---

## ⚡ Features

- **Authenticated Debian media** — Pinned release signing keys and SHA-512 verification of the official DVD-1.
- **Two target architectures** — Explicit `amd64` or `arm64` selection, independent of the preparation computer.
- **Unattended server setup** — Minimal packages, SSH key-only login, sudo, and a yescrypt console password.
- **Offline installation** — DVD-based packages, wired DHCP when available, and a validated DHCP hostname with `zapdos` as fallback.
- **Disk selection safeguards** — Device inventory, rejection reasons, protected preparation/system disks, and STOP as the default for multiple internal targets.
- **Verified USB writes** — Full image readback and a completion record; verified current media skips rewriting, while older Debian media requires approval.
- **No plaintext passwords** — Only a yescrypt hash is stored, in a local file that git ignores.

## 🚀 Quick Start

You need [just](https://just.systems/man/en/packages.html) 1.46+ and Python 3.10+ (on macOS: `brew install just python`). Then:

```sh
just setup     # once: installs the remaining tools
just           # erases a USB and writes the installer
```

`just setup` creates `config/zapdos.json` from the example if it is missing. Replace the SSH-key placeholder with your Ed25519 public key before running `just`.

## 🔐 Security & Safeguards

> [!IMPORTANT]
> **Protect the completed USB and customized ISO.** They contain the local password hash, which permits offline guessing. Debian Secure Boot authenticates shim, GRUB, and the kernel; it does not authenticate the customized initrd or preseed. No target disk encryption is configured.

## 🧪 Verification

```sh
just test
```

Unit tests use mocks and temporary regular files. The Docker/QEMU harness uses regular virtual-disk files, with no host block devices attached:

```sh
docker build -t zapdos tests/harness
docker run --rm -v "$PWD:/work" zapdos python3 tests/harness/vm.py --arch amd64 --network offline
```

## 📚 References

- [Debian image verification](https://www.debian.org/CD/verify.html)
- [Debian installer preseeding](https://wiki.debian.org/DebianInstaller/Preseed)
- [GNU xorriso](https://www.gnu.org/software/xorriso/)

## ⚠️ Disclaimer

It's technically "Zap D’OS” (Zap Debian OS). No relation to the Pokémon. Any similarity is purely coincidental and/or parodic.

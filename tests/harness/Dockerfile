FROM debian:trixie
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    python3 xorriso gnupg ca-certificates curl cpio shellcheck debconf-utils zstd squashfs-tools \
    qemu-system-x86 qemu-system-arm qemu-utils ovmf qemu-efi-aarch64 busybox-static \
    whois openssh-client age efitools dosfstools mtools fdisk \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work

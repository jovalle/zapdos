#!/bin/sh
set -eu
[ -d /sys/firmware/efi ] || { echo 'UEFI boot is required.' >/dev/console; exit 1; }
if ! grep -qs ' /sys/firmware/efi/efivars efivarfs ' /proc/mounts; then
    mkdir -p /sys/firmware/efi/efivars
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars
fi
secure=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
setup=/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
efi_equals() {
    # Debian's minimal initrd has dd/cmp but no od. Never accept a missing/short read.
    dd if="$1" of=/tmp/zapdos-efi-byte bs=1 skip=4 count=1 2>/dev/null || return 1
    printf '%b' "$2" > /tmp/zapdos-efi-expected
    cmp -s /tmp/zapdos-efi-byte /tmp/zapdos-efi-expected
}
efi_equals "$secure" '\001' || {
    echo 'Secure Boot must be enabled before installation (variable unavailable or not 1).' >/dev/console; exit 1;
}
efi_equals "$setup" '\000' || exit 1
insecure=/sys/firmware/efi/efivars/MokSBStateRT-605dab50-e046-4300-abb6-3dd810dd8b23
if [ -e "$insecure" ]; then
    efi_equals "$insecure" '\000' || {
        echo 'Shim validation is disabled. Enable it before installation.' >/dev/console; exit 1;
    }
fi
# The latest DVD installer uses this BusyBox hook; refuse an unknown client layout.
if [ ! -f /zapdos/vendor-udhcpc ]; then
    [ -f /etc/udhcpc/default.script ] || {
        echo 'Unsupported installer DHCP client layout; stopping.' >/dev/console; exit 1;
    }
    mv /etc/udhcpc/default.script /zapdos/vendor-udhcpc
    cp /zapdos/udhcpc-wrapper /etc/udhcpc/default.script
    chmod 700 /etc/udhcpc/default.script
    read -r id < /proc/sys/kernel/random/uuid
    printf 'zapdos_fallback=debian-%s\n' "${id%%-*}" >> /zapdos/hostname.sh
    printf 'debian-%s\n' "${id%%-*}" > /proc/sys/kernel/hostname
fi

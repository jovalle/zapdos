#!/bin/sh
set -eu
step='account and SSH configuration'
report_failure() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "Zapdos stopped during $step (exit $rc). Inspect the installer log." >/dev/console
    fi
}
trap report_failure 0
. /zapdos/hostname.sh
# The bounded DHCP hook records only a validated name here.
dhcp_name=
[ ! -f /tmp/dhcp-hostname ] || dhcp_name=$(cat /tmp/dhcp-hostname)
name=$(zapdos_hostname "$dhcp_name")
printf '%s\n' "$name" > /target/etc/hostname
sed -i '/^127\.0\.1\.1[[:space:]]/d' /target/etc/hosts
printf '127.0.1.1 %s\n' "$name" >> /target/etc/hosts
mkdir -p /target/home/@USERNAME@/.ssh /target/usr/local/lib /target/etc/ssh/sshd_config.d
cp /zapdos/authorized_keys /target/home/@USERNAME@/.ssh/authorized_keys
chmod 700 /target/home/@USERNAME@/.ssh
chmod 600 /target/home/@USERNAME@/.ssh/authorized_keys
in-target chown -R @USERNAME@:@USERNAME@ /home/@USERNAME@/.ssh
in-target usermod -aG sudo @USERNAME@
cat > /target/etc/ssh/sshd_config.d/00-zapdos.conf <<'SSH'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
SSH
# in-target mounts a temporary /run; create sshd's runtime directory inside that mount.
in-target /bin/sh -c 'mkdir -p /run/sshd && /usr/sbin/sshd -t >/dev/console 2>&1'
step='console keyboard configuration'
cat > /target/etc/default/keyboard <<'KEYBOARD'
XKBMODEL="pc105"
XKBLAYOUT="@KEYBOARD@"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
KEYBOARD
# Cache the map for the next physical-console boot; serial terminals keep their own encoding.
in-target setupcon --save-only
step='network configuration'
cp /zapdos/hostname.sh /target/usr/local/lib/zapdos-hostname.sh
# Debian dhcpcd sources /etc/dhcpcd.exit-hook (not a hooks.d directory).
cp /zapdos/dhcpcd-hook /target/etc/dhcpcd.exit-hook
# Ensure ethernet DHCP also works after an offline installation (netcfg may write only lo).
if [ ! -s /target/etc/network/interfaces ]; then
    mkdir -p /target/etc/network
    printf 'auto lo\niface lo inet loopback\n' > /target/etc/network/interfaces
fi
if ! grep -q 'inet dhcp' /target/etc/network/interfaces; then
    for iface in /sys/class/net/*; do
        iface=${iface##*/}
        [ -e "/sys/class/net/$iface/device" ] || continue
        [ -d "/sys/class/net/$iface/wireless" ] && continue
        printf '\nallow-hotplug %s\niface %s inet dhcp\n' "$iface" "$iface" >> /target/etc/network/interfaces
    done
fi
# Keep the installed signed shim + GRUB; fail if these packages are absent.
step='signed bootloader verification'
status=$(in-target --pass-stdout dpkg-query -W '-f=${db:Status-Status}\n' shim-signed "grub-efi-$(cat /zapdos/arch)-signed")
[ "$(printf '%s\n' "$status" | grep -cx installed)" = 2 ] || exit 1
# Determine suite from the authenticated DVD, never from mutable "stable" at install time.
. /target/etc/os-release
case $VERSION_CODENAME in *[!a-z]*|'') exit 1 ;; esac
mkdir -p /target/etc/apt/sources.list.d
# Remove the DVD entry once packages are installed so offline boots never ask for the USB.
rm -f /target/etc/apt/sources.list
cat > /target/etc/apt/sources.list.d/debian.sources <<APT
Types: deb
URIs: https://deb.debian.org/debian
Suites: $VERSION_CODENAME $VERSION_CODENAME-updates
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: $VERSION_CODENAME-security
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
APT
# A bounded, authenticated update attempt; DVD installation remains usable without internet.
step='security updates'
if in-target apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o APT::Update::Error-Mode=any update; then
    if in-target env DEBIAN_FRONTEND=noninteractive apt-get -y -o Acquire::Retries=0 -o Acquire::https::Timeout=15 -o Dpkg::Options::=--force-confold upgrade; then
        echo 'Security/update repositories refreshed; available upgrades installed.' > /target/var/log/zapdos-updates.log
    else
        echo 'Update download/install failed; inspect dpkg state before use.' > /target/var/log/zapdos-updates.log
        exit 1
    fi
else
    echo 'Network repositories unavailable; installation completed from DVD. Run sudo apt update && sudo apt upgrade when online.' > /target/var/log/zapdos-updates.log
fi
echo 'Zapdos installation complete; powering off. Remove the USB before powering on.' >/dev/console

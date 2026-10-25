#!/bin/sh
set -eu
. /zapdos/disk-lib.sh
/bin/sh /zapdos/early.sh
# Do not permit partman to operate until a target has passed every guard.
disk_inventory /sys /dev /proc/mounts /proc/swaps > /tmp/zapdos-disks
cut -f1-4 /tmp/zapdos-disks >/dev/console
awk -F '\t' '$4=="eligible"' /tmp/zapdos-disks > /tmp/zapdos-candidates
count=$(wc -l < /tmp/zapdos-candidates)
[ "$count" -gt 0 ] || { echo 'No eligible internal disk. Installation stopped.' >/dev/console; exit 1; }
if [ "$count" -eq 1 ]; then
    selected=$(cut -f1 /tmp/zapdos-candidates)
else
    . /usr/share/debconf/confmodule
    choices=$(awk -F '\t' '{printf ", %s (%s; %s)", $1,$2,$3}' /tmp/zapdos-candidates)
    cat > /tmp/zapdos.templates <<TEMPLATE
Template: zapdos/disk
Type: select
Choices: STOP${choices}
Default: STOP
Description: Select the internal disk to ERASE completely:
 All data on the selected disk will be destroyed. STOP leaves disks untouched.
TEMPLATE
    debconf-loadtemplate zapdos /tmp/zapdos.templates
    db_set zapdos/disk STOP
    db_fset zapdos/disk seen false
    db_input critical zapdos/disk || exit 1
    db_go || exit 1
    db_get zapdos/disk
    selected=${RET%% *}
    [ "$selected" != STOP ] || exit 1
fi
expected=$(awk -F '\t' -v d="$selected" '$1==d {print $5}' /tmp/zapdos-candidates)
[ -n "$expected" ] || exit 1
disk_inventory /sys /dev /proc/mounts /proc/swaps > /tmp/zapdos-recheck
actual=$(awk -F '\t' -v d="$selected" '$1==d && $4=="eligible" {print $5}' /tmp/zapdos-recheck)
[ "$actual" = "$expected" ] || { echo 'Disk identity changed. Stopping.' >/dev/console; exit 1; }
printf '%s\n' "$selected" > /tmp/zapdos-target
# Debian otherwise scans every disk and can mount an unselected disk's ESP.
[ ! -e /var/run/parted_server.pid ] || { echo 'Partitioner already running; stopping.' >/dev/console; exit 1; }
if [ ! -f /zapdos/vendor-parted-devices ]; then
    detector=$(command -v parted_devices) || exit 1
    mv "$detector" /zapdos/vendor-parted-devices
    cp /zapdos/parted-devices "$detector"
    chmod 700 "$detector"
fi
# This is the first authorization to partition; the inventory itself never writes disks.
debconf-set partman-auto/disk "$selected"
debconf-set grub-installer/bootdev "$selected"

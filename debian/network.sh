#!/bin/sh
set -eu
# netcfg's no-interface/DHCP error screens cannot reliably be preseeded away.
# Drivers have been loaded by hw-detect before this partman early hook.
for node in /sys/class/net/*; do
    iface=${node##*/}
    [ -e "$node/device" ] || continue
    [ ! -d "$node/wireless" ] || continue
    [ "$(cat "$node/type")" = 1 ] || continue
    ip link set "$iface" up || continue
    sleep 3
    [ "$(cat "$node/carrier" 2>/dev/null || :)" = 1 ] || continue
    if udhcpc -n -q -f -i "$iface" -T 1 -t 20 -O hostname -s /etc/udhcpc/default.script; then
        echo 'Wired DHCP configured.' >/dev/console
    else
        echo 'DHCP unavailable; continuing installation from DVD.' >/dev/console
    fi
    exit 0
done
echo 'No connected wired interface; continuing installation from DVD.' >/dev/console

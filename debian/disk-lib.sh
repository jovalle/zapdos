#!/bin/sh
# Read-only inventory. Parameters permit fixture tests without touching host disks.
disk_inventory() {
    sys=$1; dev=$(readlink -f "$2"); mounts=$3; swaps=$4
    for node in "$sys"/block/*; do
        [ -e "$node" ] || continue
        disk=${node##*/}; path=$(readlink -f "$node")
        sectors=$(cat "$node/size" 2>/dev/null || echo 0)
        model=$(cat "$node/device/model" 2>/dev/null || echo unknown)
        model=$(printf '%s' "$model" | tr -c 'A-Za-z0-9 ._-' '?' | cut -c1-60)
        reason=eligible
        case $disk in sd[a-z]*|nvme[0-9]*n[0-9]*|vd[a-z]*|mmcblk[0-9]*) ;; *) reason='not a supported whole internal disk' ;; esac
        case $path in */usb[0-9]*/*|*/thunderbolt/*) reason='USB or Thunderbolt media' ;; esac
        [ "$(cat "$node/removable" 2>/dev/null)" = 0 ] || reason='removable or unknown removability'
        [ "$(cat "$node/ro" 2>/dev/null)" = 0 ] || reason='read-only or unknown writeability'
        [ "$sectors" -ge 33554432 ] 2>/dev/null || reason='smaller than 16 GiB or unknown capacity'
        [ ! -f "$node/partition" ] || reason='partition, not whole disk'
        for component in "$node" "$node"/*; do
            [ "$component" = "$node" ] || [ -f "$component/partition" ] || continue
            name=${component##*/}
            for dependent in "$component"/holders/* "$component"/slaves/*; do
                [ ! -e "$dependent" ] || reason='active RAID/LVM/dependent device'
            done
            while read -r source rest; do
                [ "$(readlink -f "$source")" != "$dev/$name" ] || reason='mounted or active swap (includes installer media)'
            done < "$mounts"
            while read -r source rest; do
                [ "$(readlink -f "$source")" != "$dev/$name" ] || reason='mounted or active swap (includes installer media)'
            done < "$swaps"
            # Refuse multi-disk metadata instead of asking partman to remove a VG/array.
            probe_status=0
            kind=$(blkid -p -s TYPE -o value "$dev/$name" 2>&1) || probe_status=$?
            case $probe_status in 0|2) ;; *) reason='failed or ambiguous filesystem probe' ;; esac
            case $kind in *[!A-Za-z0-9_]*) reason='filesystem probe reported an error' ;; esac
            [ "$probe_status" != 2 ] || [ -z "$kind" ] || reason='filesystem probe reported an error'
            case $kind in LVM2_member|*_raid_member) reason='existing RAID/LVM metadata' ;; esac
        done
        serial=$(cat "$node/device/serial" 2>/dev/null || :)
        identity=$(printf '%s' "$path:$sectors:$serial:$(cat "$node/dev" 2>/dev/null)" | sha256sum | cut -d' ' -f1)
        printf '%s\t%s\t%s\t%s\t%s\n' "$dev/$disk" "$model" "$((sectors / 2097152)) GiB" "$reason" "$identity"
    done
}

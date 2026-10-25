#!/bin/sh
# Sourceable by DHCP hooks; only a valid RFC 1123 first label becomes the hostname.
# early.sh appends zapdos_fallback=debian-<id>, generated once per install.
# shellcheck disable=SC2154
zapdos_hostname() {
    name=${1:-}
    name=${name%.}
    if ! printf '%s\n' "$name" | LC_ALL=C awk '
        length($0) < 1 || length($0) > 253 {exit 1}
        {n=split($0,a,"."); for(i=1;i<=n;i++)
            if(length(a[i])>63 || a[i]!~/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) exit 1}
        END {if (NR != 1) exit 1}
    '; then name=$zapdos_fallback; fi
    printf '%s\n' "${name%%.*}" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

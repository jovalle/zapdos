#!/bin/sh
# VM-only checks, installed by the harness and never included in production media.
set -eu
trap 'if [ "$?" -ne 0 ]; then echo VM_ACCEPTANCE_FAIL; fi' 0
user=$1
timezone=$2
locale=$3
keyboard=$4
step='account password hashes'
echo "VM check: $step"
while IFS=: read -r account expected; do
    actual=$(getent shadow "$account" | cut -d: -f2)
    [ "$actual" = "$expected" ]
    [ "$(passwd -S "$account" | awk '{print $2}')" = P ]
done < /usr/local/lib/zapdos/vm-expected
[ "$(id -u root)" = 0 ]
[ "$(id -u "$user")" -ge 1000 ]
id -nG "$user" | tr ' ' '\n' | grep -qx sudo
sudo -l -U "$user" >/dev/null
[ "$(su -s /bin/sh -c 'id -un' "$user")" = "$user" ]
echo VM_ACCOUNTS_PASS
step='Secure Boot and SSH policy'
echo "VM check: $step"
[ "$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d ' ')" = 1 ]
/usr/sbin/sshd -T > /run/zapdos-vm-sshd
for setting in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'authenticationmethods publickey' 'permitrootlogin no'; do
    grep -qx "$setting" /run/zapdos-vm-sshd
done
cmp /usr/local/lib/zapdos/vm-keys "/home/$user/.ssh/authorized_keys"
[ "$(stat -c %a "/home/$user/.ssh")" = 700 ]
[ "$(stat -c %a "/home/$user/.ssh/authorized_keys")" = 600 ]
[ "$(readlink /etc/localtime)" = "/usr/share/zoneinfo/$timezone" ]
grep -Fq "$locale" /etc/default/locale
grep -Fq "XKBLAYOUT=\"$keyboard\"" /etc/default/keyboard
echo VM_POLICY_PASS
echo VM_ACCEPTANCE_PASS

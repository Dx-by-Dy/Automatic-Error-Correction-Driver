#!/bin/bash
# Rebuilds and reloads the driver, then creates the corrdm device on a zeroed /dev/vdb.
# Runs as root inside the development VM (see deploy/vm.sh): it overwrites /dev/vdb.
set -e

if ! systemd-detect-virt --vm --quiet; then
    echo "error: not a virtual machine, refusing to overwrite /dev/vdb" >&2
    exit 1
fi

cd "$(dirname "$(readlink -f "$0")")/../correction-driver"

if dmsetup info corrdm >/dev/null 2>&1; then
    dmsetup remove corrdm
fi
if lsmod | grep -q '^correction_driver '; then
    rmmod correction_driver
fi

make clean

if [ "$1" == "-d" ] || [ "$1" == "debug" ]; then
    make debug
else
    make
fi

insmod correction_driver.ko

dd if=/dev/zero of=/dev/vdb bs=1G count=1
echo "0 $(blockdev --getsz /dev/vdb) corrdm /dev/vdb" | dmsetup create corrdm

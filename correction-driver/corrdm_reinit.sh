#!/bin/bash

dmsetup remove corrdm
rmmod correction_driver.ko
make clean

if [ "$1" == "-d" ] || [ "$1" == "debug" ]; then
    make debug
else
    make
fi

insmod correction_driver.ko

dd if=/dev/zero of=vdb bs=1G count=1
echo "0 $(blockdev --getsz /dev/vdb) corrdm /dev/vdb" | dmsetup create corrdm
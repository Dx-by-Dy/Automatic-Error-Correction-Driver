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
echo "0 $(blockdev --getsz /dev/loop0) corrdm /dev/loop0" | dmsetup create corrdm
#!/bin/bash

dmsetup remove corrdm
rmmod correction_driver.ko
make clean
make
insmod correction_driver.ko
echo "0 131072 correction_dm /dev/loop0" | dmsetup create corrdm
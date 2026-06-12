#!/bin/bash

dmsetup remove corrdm
rmmod correction_driver.ko
make clean
make
insmod correction_driver.ko
echo "0 131072 corrdm /dev/loop0" | dmsetup create corrdm
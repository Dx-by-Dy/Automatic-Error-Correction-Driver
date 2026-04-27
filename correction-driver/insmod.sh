#!/bin/bash

sudo dmsetup remove corrdm
sudo rmmod correction_driver.ko
make clean
make
sudo insmod correction_driver.ko
echo "0 10000 correction_dm /dev/ramdisk" | sudo dmsetup create corrdm
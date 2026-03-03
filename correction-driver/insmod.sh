#!/bin/bash

sudo dmsetup remove corrdm
sudo rmmod correction_driver.ko
make clean
make
sudo insmod correction_driver.ko
echo "0 10000 correction_dm /dev/ramdisk 0 5000 5000" | sudo dmsetup create corrdm
#!/bin/bash

make clean
make
sudo insmod ./build/ramdisk.ko
sudo mkfs.ext2 /dev/ramdisk
# sudo mount /dev/ramdisk /mnt/ramdisk
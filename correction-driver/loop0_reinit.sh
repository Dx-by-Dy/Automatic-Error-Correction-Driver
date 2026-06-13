#!/bin/bash

losetup -d loop0
dd if=/dev/zero of=backend.img bs=1M count=256
losetup -fP backend.img

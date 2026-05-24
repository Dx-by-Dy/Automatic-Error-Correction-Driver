#!/bin/bash

dd if=/dev/zero of=backend.img bs=1M count=64
losetup -fP backend.img
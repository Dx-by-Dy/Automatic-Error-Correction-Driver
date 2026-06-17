#!/usr/bin/env python3

import hashlib
import os
import random
import shutil
import subprocess
from pathlib import Path

DEVICE_DM = "/dev/mapper/corrdm"
DEVICE_REAL = "/dev/vdb"

MOUNTPOINT = "/mnt/corrdm_test"

TEST_FILE = "blob.bin"
FILE_SIZE_MB = 128

def run(cmd):
    print(" ".join(cmd))

    result = subprocess.run(
        cmd,
        text=True,
        capture_output=True
        )
    
    print(result.stderr)
    result.check_returncode()

def sha256(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            data = f.read(1024 * 1024)

            if not data:
                break

            h.update(data)

    return h.hexdigest()

def create_fs():
    run(["mkfs.ext4", "-F", DEVICE_DM])

    Path(MOUNTPOINT).mkdir(exist_ok=True)

    run([
        "mount",
        DEVICE_DM,
        MOUNTPOINT
    ])

def write_random_file():

    path = Path(MOUNTPOINT) / TEST_FILE

    with open(path, "wb") as f:

        for _ in range(FILE_SIZE_MB):

            f.write(os.urandom(1024 * 1024))

    run(["sync"])

    return sha256(path)

def unmount():
   run(["umount", "-f", MOUNTPOINT])

def cleanup():
    subprocess.run(
        ["umount", "-f", MOUNTPOINT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    Path(MOUNTPOINT).mkdir(exist_ok=True)

def remount():
    unmount()

    run([
        "mount",
        DEVICE_DM,
        MOUNTPOINT
    ])

def fio_verify():
    run([
        "fio",
        "--name=verify",
        f"--filename={DEVICE_DM}",
        "--rw=randrw",
        "--bs=4k",
        "--runtime=60",
        "--time_based",
        "--verify=crc32",
        "--do_verify=1",
        "--direct=1"
    ])

def corrupt_sector(sector):
    run([
        "dd",
        "if=/dev/zero",
        f"of={DEVICE_REAL}",
        "bs=512",
        f"seek={sector}",
        "count=1",
        "conv=notrunc"
    ])

    run(["sync"])

def read_sector():
    run([
        "dd",
        f"if={DEVICE_DM}",
        f"of=/dev/null",
        "bs=512",
        f"skip=0",
        "count=1",
        "conv=notrunc"
    ])

def clear_disk():
    run([
        "dd",
        "if=/dev/zero",
        f"of={DEVICE_REAL}",
        "bs=1G",
        "count=1",
    ])

def crc_test():
    path = Path(MOUNTPOINT) / TEST_FILE

    try:
        read_sector()

        print("ERROR: corruption not detected")

    except subprocess.CalledProcessError as e:

        print("CRC check triggered")
        print(e)

def main():

    clear_disk()
    cleanup()
    
    try:
        fio_verify()

        create_fs()

        original_hash = write_random_file()

        current_hash = sha256(
            Path(MOUNTPOINT) / TEST_FILE
        )

        assert original_hash == current_hash

        unmount()

        corrupt_sector(8)

        crc_test()
    
        print("All tests ended")

    finally:
        cleanup()

    clear_disk()

if __name__ == "__main__":
    main()
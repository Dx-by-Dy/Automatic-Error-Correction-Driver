"""Filesystems on top of the device keep files intact across a remount."""

import hashlib
import os

import pytest

from harness import run

FILE_MIB = 128
LOWER_MIB = 512
MOUNTPOINT = "/mnt/corrdm_test"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture
def mounted(request, make_stack):
    stack = make_stack(LOWER_MIB)
    mkfs = {"ext4": ("mkfs.ext4", "-F", "-q"), "xfs": ("mkfs.xfs", "-f", "-q")}[request.param]
    run(*mkfs, stack.upper_path)
    os.makedirs(MOUNTPOINT, exist_ok=True)
    run("mount", stack.upper_path, MOUNTPOINT)
    yield stack
    run("umount", MOUNTPOINT, check=False)


def drop_caches():
    run("sync")
    with open("/proc/sys/vm/drop_caches", "w") as file:
        file.write("3")


@pytest.mark.slow
@pytest.mark.parametrize("mounted", ["ext4", "xfs"], indirect=True)
def test_file_survives_a_remount(mounted):
    path = os.path.join(MOUNTPOINT, "blob.bin")
    with open(path, "wb") as file:
        for _ in range(FILE_MIB):
            file.write(os.urandom(1024 * 1024))
    written = sha256(path)

    drop_caches()
    assert sha256(path) == written

    run("umount", MOUNTPOINT)
    run("mount", mounted.upper_path, MOUNTPOINT)
    assert sha256(path) == written

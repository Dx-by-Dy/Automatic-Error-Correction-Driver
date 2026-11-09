"""An fsync on the device must reach the lower device."""

import os
import stat

import pytest

from conftest import TEST_DISK
from harness import pattern

TRACING = "/sys/kernel/tracing"
EVENT = f"{TRACING}/events/block/block_bio_queue/enable"


def write_file(path, value):
    with open(path, "w") as file:
        file.write(value)


def flushes_on_test_disk(action):
    """Runs the action and counts the flush and FUA bios it queued on the test disk."""
    device = os.stat(TEST_DISK).st_rdev
    disk = f" {os.major(device)},{os.minor(device)} "
    write_file(f"{TRACING}/trace", "")
    write_file(EVENT, "1")
    try:
        action()
    finally:
        write_file(EVENT, "0")
    with open(f"{TRACING}/trace") as trace:
        lines = [line for line in trace if disk in line]
    return sum(1 for line in lines if any(flag in line.split(disk)[1].split()[0] for flag in "FP"))


def write_and_fsync(path, sector):
    fd = os.open(path, os.O_RDWR)
    try:
        os.lseek(fd, sector * 512, os.SEEK_SET)
        os.write(fd, pattern("fsync", 8))
        os.fsync(fd)
    finally:
        os.close(fd)


def test_the_test_disk_has_a_write_cache():
    """Without one, the tests below would prove nothing."""
    assert stat.S_ISBLK(os.stat(TEST_DISK).st_mode)
    name = os.path.basename(TEST_DISK)
    with open(f"/sys/block/{name}/queue/write_cache") as file:
        assert file.read().strip() == "write back"


def test_fsync_on_the_lower_device_flushes(stack):
    """The control for the test below: this way of counting does see flushes."""
    assert flushes_on_test_disk(lambda: write_and_fsync(stack.lower_path, 0)) > 0


@pytest.mark.xfail(strict=True, reason="TODO.md: fsync does not reach the lower device")
def test_fsync_on_the_device_flushes(stack):
    assert flushes_on_test_disk(lambda: write_and_fsync(stack.upper_path, 0)) > 0

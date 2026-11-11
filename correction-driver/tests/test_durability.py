"""Flushes and FUA writes on the device reach the lower device.

The bios queued on the test disk are seen through the block_bio_queue trace event. A write is
durable once it is FUA or a flush is queued after it, so after an fsync every write it caused must
be one or the other.
"""

import os
import stat
from dataclasses import dataclass

import pytest

from conftest import LOWER_NAME, TEST_DISK, dmsetup_remove, make_lower
from harness import pattern, run

TRACING = "/sys/kernel/tracing"
EVENT = f"{TRACING}/events/block/block_bio_queue/enable"
MOUNTPOINT = "/mnt/corrdm_durability"
FS_LOWER_MIB = 64


@dataclass
class Bio:
    """One bio queued on the test disk, from its line in the trace."""

    preflush: bool
    op: str
    fua: bool
    sector: int
    sectors: int

    @property
    def is_write(self):
        return self.op == "W" and self.sectors > 0


def write_file(path, value):
    with open(path, "w") as file:
        file.write(value)


def parse_rwbs(rwbs):
    """The flags of blk_fill_rwbs: F for a preflush, the operation, then F for FUA."""
    preflush = rwbs.startswith("F")
    rest = rwbs[1:] if preflush else rwbs
    return preflush, rest[:1], "F" in rest[1:]


def bios_on_test_disk(action):
    """Runs the action and returns the bios it queued on the test disk, in order."""
    device = os.stat(TEST_DISK).st_rdev
    disk = f" {os.major(device)},{os.minor(device)} "
    write_file(f"{TRACING}/trace", "")
    write_file(EVENT, "1")
    try:
        action()
    finally:
        write_file(EVENT, "0")
    bios = []
    with open(f"{TRACING}/trace") as trace:
        for line in trace:
            if disk not in line:
                continue
            fields = line.split(disk)[1].split()
            # RWBS SECTOR + COUNT [TASK]
            preflush, op, fua = parse_rwbs(fields[0])
            bios.append(Bio(preflush, op, fua, int(fields[1]), int(fields[3])))
    return bios


def writes_left_in_the_cache(bios):
    """The writes that are neither FUA nor followed by a flush."""
    left = []
    for bio in bios:
        if bio.preflush:
            left.clear()
        if bio.is_write and not bio.fua:
            left.append(bio)
    return left


def write_and_fsync(path, sector):
    fd = os.open(path, os.O_RDWR)
    try:
        os.lseek(fd, sector * 512, os.SEEK_SET)
        os.write(fd, pattern("fsync", 8))
        os.fsync(fd)
    finally:
        os.close(fd)


def queue_attribute(path, name):
    """An attribute of the request queue of a block device given by its path."""
    disk = os.path.basename(os.path.realpath(path))
    with open(f"/sys/block/{disk}/queue/{name}") as file:
        return file.read().strip()


def test_the_test_disk_has_a_write_cache():
    """Without one, the tests below would prove nothing."""
    assert stat.S_ISBLK(os.stat(TEST_DISK).st_mode)
    assert queue_attribute(TEST_DISK, "write_cache") == "write back"


def test_device_reports_a_write_cache_and_fua(stack):
    """Otherwise the layers above send neither flushes nor FUA writes."""
    assert queue_attribute(stack.upper_path, "write_cache") == "write back"
    assert queue_attribute(stack.upper_path, "fua") == "1"


def test_fsync_on_the_lower_device_flushes(stack):
    """The control for the test below: this way of counting does see flushes."""
    bios = bios_on_test_disk(lambda: write_and_fsync(stack.lower_path, 0))
    assert any(bio.preflush for bio in bios)


def test_fsync_on_the_device_flushes(stack):
    bios = bios_on_test_disk(lambda: write_and_fsync(stack.upper_path, 0))
    assert any(bio.preflush for bio in bios)
    assert not writes_left_in_the_cache(bios)


@pytest.fixture
def ext4(request, make_stack):
    """ext4 on the device or, for the control, on the lower device alone, with nothing left to write.

    With 1 KiB blocks the commit block covers part of a chunk, so its metadata is read, then written.
    """
    where, block_size = request.param
    if where == "device":
        path = make_stack(FS_LOWER_MIB).upper_path
    else:
        path = make_lower(FS_LOWER_MIB * 2048)
    # Without lazy initialisation, so that no background thread writes while the bios are traced.
    run("mkfs.ext4", "-F", "-q", "-b", str(block_size), "-E", "lazy_itable_init=0,lazy_journal_init=0", path)
    os.makedirs(MOUNTPOINT, exist_ok=True)
    run("mount", path, MOUNTPOINT)
    run("sync")
    yield
    run("umount", MOUNTPOINT, check=False)
    if where != "device":
        dmsetup_remove(LOWER_NAME)


def create_file_and_fsync():
    """A new file makes the journal commit, whose commit block is a FUA write."""
    fd = os.open(os.path.join(MOUNTPOINT, "file"), os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.write(fd, os.urandom(64 * 1024))
        os.fsync(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "ext4",
    [("lower device", 4096), ("device", 4096), ("device", 1024)],
    ids=["lower device", "device, 4k blocks", "device, 1k blocks"],
    indirect=True,
)
def test_fsync_on_ext4_leaves_nothing_in_the_cache(ext4):
    """Every write of the fsync is FUA or flushed, the metadata of the chunks included.

    On the lower device it is the control: the checker passes there, and sees FUA writes.
    """
    bios = bios_on_test_disk(create_file_and_fsync)
    assert any(bio.fua for bio in bios), "no FUA write: the journal commit was not seen"
    assert not writes_left_in_the_cache(bios)

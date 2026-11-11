"""What the device holds after a crash, replayed from a log of the writes that reached its disk.

The stack is the driver on dm-log-writes on the lower device. After the workload the log is read,
and a prefix of it is replayed to the zeroed lower device, with the driver put on it again: that is
the device after a crash at that point. See logwrites.py.
"""

import hashlib
import os

import pytest

from conftest import LOG_DEVICE_NAME, LOG_NAME, LOWER_NAME, UPPER_NAME, dmsetup_remove, make_lower
from harness import DATA_SECTORS, BlockDevice, capacity, metadata_sector, pattern, physical_sector, run
from logwrites import FLUSH, FUA, mark_index, read_log, replay

LOWER_MIB = 32
LOG_MIB = 128
LOG_OFFSET_MIB = 256
MOUNTPOINT = "/mnt/corrdm_crash"
FILES = 8


class LoggedStack:
    """The driver on dm-log-writes on a zeroed lower device."""

    def __init__(self):
        self.lower_sectors = LOWER_MIB * 2048
        self.lower_path = make_lower(self.lower_sectors)
        self.log_device_path = make_lower(LOG_MIB * 2048, LOG_DEVICE_NAME, LOG_OFFSET_MIB)
        run(
            "dmsetup", "create", LOG_NAME,
            stdin=f"0 {self.lower_sectors} log-writes {self.lower_path} {self.log_device_path}\n",
        )
        self.create_upper(f"/dev/mapper/{LOG_NAME}")

    @property
    def sectors(self):
        return capacity(self.lower_sectors)

    def create_upper(self, lower):
        run("dmsetup", "create", UPPER_NAME, stdin=f"0 {self.lower_sectors} corrdm {lower}\n")
        self.upper_path = f"/dev/mapper/{UPPER_NAME}"

    def mark(self, name):
        run("dmsetup", "message", LOG_NAME, "0", "mark", name)

    def finish(self):
        """Removes the driver and the log target, and returns the log."""
        dmsetup_remove(UPPER_NAME)
        dmsetup_remove(LOG_NAME)
        return read_log(self.log_device_path)

    def replay(self, entries):
        """The device after a crash with only these entries on its disk; close it after use."""
        dmsetup_remove(UPPER_NAME)
        run("dd", "if=/dev/zero", f"of={self.lower_path}", "bs=1M", "oflag=direct", f"count={LOWER_MIB}")
        lower = BlockDevice(self.lower_path)
        try:
            replay(entries, lower)
        finally:
            lower.close()
        self.create_upper(self.lower_path)
        return BlockDevice(self.upper_path)


@pytest.fixture
def logged():
    stack = LoggedStack()
    yield stack
    run("umount", MOUNTPOINT, check=False)
    for name in (UPPER_NAME, LOG_NAME, LOG_DEVICE_NAME, LOWER_NAME):
        dmsetup_remove(name)


def write_and_flush(path, writes):
    """Writes (sector, data) pairs with O_DIRECT, then flushes the device."""
    device = BlockDevice(path)
    try:
        for sector, data in writes:
            device.write(sector, data)
        os.fsync(device.fd)
    finally:
        device.close()


def apply(image, writes):
    for sector, data in writes:
        image[sector * 512 : sector * 512 + len(data)] = data


# Whole chunks, a partial write and a write across a chunk boundary, so both ways of writing
# metadata are in the log.
STEPS = {
    "first": [(0, pattern("a", 16 * DATA_SECTORS))],
    "second": [(3, pattern("b", 2)), (5 * DATA_SECTORS + 6, pattern("c", 4)), (9 * DATA_SECTORS, pattern("d", DATA_SECTORS))],
}
UNFLUSHED = [(2 * DATA_SECTORS, pattern("e", DATA_SECTORS))]
AREA = 16 * DATA_SECTORS


def test_flushed_writes_survive_a_crash(logged):
    """At each mark after a flush, the device holds exactly what was written before it."""
    expected = {}
    image = bytearray(AREA * 512)
    for name, writes in STEPS.items():
        write_and_flush(logged.upper_path, writes)
        logged.mark(name)
        apply(image, writes)
        expected[name] = bytes(image)
    device = BlockDevice(logged.upper_path)
    for sector, data in UNFLUSHED:
        device.write(sector, data)
    device.close()
    entries = logged.finish()

    for name, contents in expected.items():
        device = logged.replay(entries[: mark_index(entries, name) + 1])
        try:
            assert device.read(0, AREA) == contents, f"after a crash at mark {name}"
        finally:
            device.close()


def chunk_entries(entries, first, last, chunk):
    """The indexes of the entries between two marks that wrote the data and the metadata of a chunk."""
    data_sectors = set(range(physical_sector(chunk * DATA_SECTORS), physical_sector(chunk * DATA_SECTORS) + DATA_SECTORS))
    data, metadata = [], []
    for entry in entries[first + 1 : last]:
        written = set(range(entry.sector, entry.sector + len(entry.data) // 512))
        if written & data_sectors:
            data.append(entry.index)
        if metadata_sector(chunk * DATA_SECTORS) in written:
            metadata.append(entry.index)
    return data, metadata


@pytest.mark.xfail(strict=True, reason="TODO.md: Data and CRC are not written atomically")
@pytest.mark.parametrize("sectors", [DATA_SECTORS, 1], ids=["whole chunk", "one sector"])
def test_a_write_cut_between_data_and_metadata_reads_old_or_new(logged, sectors):
    """A crash after one of the two writes of a chunk reached the disk, but not the other."""
    chunk = 3
    start = chunk * DATA_SECTORS
    old = pattern("old", DATA_SECTORS)
    new = pattern("new", sectors)
    write_and_flush(logged.upper_path, [(start, old)])
    logged.mark("old")
    write_and_flush(logged.upper_path, [(start, new)])
    logged.mark("new")
    entries = logged.finish()

    data, metadata = chunk_entries(entries, mark_index(entries, "old"), mark_index(entries, "new"), chunk)
    assert len(data) == 1 and len(metadata) == 1, (data, metadata)
    cut = min(data[0], metadata[0])
    device = logged.replay(entries[: cut + 1])
    try:
        contents = device.read(start, DATA_SECTORS)
    except OSError as error:
        pytest.fail(f"the chunk does not read after the crash: {error}")
    finally:
        device.close()
    assert contents in (old, new + old[len(new) :])


def flush_points(entries):
    """The indexes of the entries after which a crash leaves what the filesystem made durable."""
    return [entry.index for entry in entries if entry.flags & (FLUSH | FUA)]


def file_digests(directory):
    digests = {}
    for name in sorted(os.listdir(directory)):
        if name.startswith("file"):
            with open(os.path.join(directory, name), "rb") as file:
                digests[name] = hashlib.sha256(file.read()).hexdigest()
    return digests


def ext4_workload(logged, block_size=1024):
    """Files on ext4, each written, fsynced and marked; returns the log, the digests and the marks.

    With 1 KiB blocks, which mkfs takes for a device this small anyway, the journal writes parts of
    chunks; with 4 KiB blocks, whole chunks.
    """
    run(
        "mkfs.ext4", "-F", "-q", "-b", str(block_size),
        "-E", "lazy_itable_init=0,lazy_journal_init=0", logged.upper_path,
    )
    # mkfs flushes on its way too, before the filesystem is complete.
    logged.mark("mkfs")
    os.makedirs(MOUNTPOINT, exist_ok=True)
    run("mount", logged.upper_path, MOUNTPOINT)
    written = {}
    for number in range(FILES):
        name = f"file{number}"
        data = os.urandom((number + 1) * 24 * 1024)
        with open(os.path.join(MOUNTPOINT, name), "wb") as file:
            file.write(data)
            file.flush()  # out of the buffer of Python, or the fsync has nothing to write
            os.fsync(file.fileno())
        written[name] = hashlib.sha256(data).hexdigest()
        logged.mark(name)
    run("umount", MOUNTPOINT)
    entries = logged.finish()
    marks = {entry.index: entry.mark for entry in entries if entry.mark in written}
    return entries, written, marks


def check_ext4_after_a_crash(logged, entries, point, written, marks):
    """ext4 mounts, fsck finds nothing, and every file marked before the point is intact."""
    logged.replay(entries[: point + 1]).close()
    run("mount", logged.upper_path, MOUNTPOINT)
    try:
        found = file_digests(MOUNTPOINT)
    finally:
        run("umount", MOUNTPOINT)
    fsck = run("e2fsck", "-f", "-n", logged.upper_path, check=False)
    assert fsck.returncode == 0, f"after a crash at entry {point}:\n{fsck.stdout}"
    for name in (marks[index] for index in marks if index <= point):
        assert found.get(name) == written[name], f"{name} after a crash at entry {point}"


@pytest.mark.slow
@pytest.mark.parametrize("block_size", [1024, 4096], ids=["1k blocks", "4k blocks"])
def test_ext4_survives_a_crash_after_each_fsync(logged, block_size):
    """A crash right after an fsync returned: nothing of the filesystem is in flight."""
    entries, written, marks = ext4_workload(logged, block_size)
    assert len(marks) == FILES
    for point in sorted(marks):
        check_ext4_after_a_crash(logged, entries, point, written, marks)


@pytest.mark.slow
def test_ext4_survives_a_crash_at_any_flush(logged):
    """A crash at any flush or FUA write, with other writes of the filesystem in flight.

    Before the cache it failed at once: ext4 writes its superblock, part of a chunk, with FUA, and the
    data reached the disk before the metadata write was even sent. The cache turns a FUA write into a
    write back and a flush, and sends a flush down only once every write back before it is done, so at
    these points nothing of the driver is in flight. A crash between the data and the metadata of one
    write is still possible, between flushes: test_a_write_cut_between_data_and_metadata_reads_old_or_new.
    """
    entries, written, marks = ext4_workload(logged)
    start = mark_index(entries, "mkfs")
    points = [point for point in flush_points(entries) if point > start]
    assert points, "no flush in the log after mkfs"
    for point in points:
        check_ext4_after_a_crash(logged, entries, point, written, marks)

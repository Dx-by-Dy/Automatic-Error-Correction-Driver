"""What the device holds after a crash, replayed from a log of the writes that reached its disk.

The stack is the driver on dm-log-writes on the lower device. After the workload the log is read,
and a prefix of it is replayed to the zeroed lower device, with the driver put on it again: that is
the device after a crash at that point. See logwrites.py.
"""

import hashlib
import os

import pytest

from conftest import (
    LOG_DEVICE_NAME,
    LOG_NAME,
    LOWER_NAME,
    UPPER_NAME,
    device_status,
    dmsetup_remove,
    make_lower,
    wait_for_write_back,
)
from harness import (
    DATA_SECTORS,
    BlockDevice,
    capacity,
    format_device,
    metadata_sector,
    metadata_sectors,
    pattern,
    physical_sector,
    run,
)
from logwrites import FLUSH, FUA, mark_index, read_log, replay

LOWER_MIB = 32
LOG_MIB = 128
LOG_OFFSET_MIB = 256
MOUNTPOINT = "/mnt/dcorr_crash"
FILES = 8
# test_ext4_survives_a_crash_at_any_flush checks every flush and every FUA_STRIDE-th FUA write.
FUA_STRIDE = 4


class LoggedStack:
    """The driver on dm-log-writes on a zeroed lower device.

    The device is formatted through dm-log-writes, so the superblock is in the log and every replay,
    which starts from a zeroed device, has it.
    """

    def __init__(self):
        self.lower_sectors = LOWER_MIB * 2048
        self.lower_path = make_lower(self.lower_sectors)
        self.log_device_path = make_lower(LOG_MIB * 2048, LOG_DEVICE_NAME, LOG_OFFSET_MIB)
        self.start_log(format=True)

    def start_log(self, format=False):
        """Puts dm-log-writes on the lower device as it is, with a fresh log, and the driver on it."""
        run(
            "dmsetup", "create", LOG_NAME,
            stdin=f"0 {self.lower_sectors} log-writes {self.lower_path} {self.log_device_path}\n",
        )
        if format:
            format_device(f"/dev/mapper/{LOG_NAME}")
        self.create_upper(f"/dev/mapper/{LOG_NAME}")

    def log_again(self):
        """Logs anew from the state of the last replay: its entries and the new ones replay in a row."""
        dmsetup_remove(UPPER_NAME)
        run("dd", "if=/dev/zero", f"of={self.log_device_path}", "bs=1M", "oflag=direct", f"count={LOG_MIB}")
        self.start_log()

    @property
    def sectors(self):
        return capacity(self.lower_sectors)

    def create_upper(self, lower):
        run("dmsetup", "create", UPPER_NAME, stdin=f"0 {capacity(self.lower_sectors)} dcorr {lower}\n")
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


# Whole chunks, a partial write and a write across a chunk boundary, of chunks that share metadata
# sectors.
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
    first_sector = physical_sector(chunk * DATA_SECTORS, LOWER_MIB * 2048)
    data_sectors = set(range(first_sector, first_sector + DATA_SECTORS))
    data, metadata = [], []
    for entry in entries[first + 1 : last]:
        written = set(range(entry.sector, entry.sector + len(entry.data) // 512))
        if written & data_sectors:
            data.append(entry.index)
        if metadata_sector(chunk * DATA_SECTORS, LOWER_MIB * 2048) in written:
            metadata.append(entry.index)
    return data, metadata


def read_after(logged, entries, start, sectors=DATA_SECTORS):
    """What the device holds at these sectors after a crash with only these entries on its disk."""
    device = logged.replay(entries)
    try:
        return device.read(start, sectors)
    except OSError as error:
        pytest.fail(f"the chunk does not read after a crash at entry {entries[-1].index}: {error}")
    finally:
        device.close()


def write_old_and_new(logged, start, sectors):
    """A whole chunk, flushed, then new data over some of it, flushed; returns the log and both contents."""
    old = pattern("old", DATA_SECTORS)
    new = pattern("new", sectors)
    write_and_flush(logged.upper_path, [(start, old)])
    logged.mark("old")
    write_and_flush(logged.upper_path, [(start, new)])
    logged.mark("new")
    return logged.finish(), old, new + old[len(new) :]


@pytest.mark.parametrize("sectors", [DATA_SECTORS, 1], ids=["whole chunk", "one sector"])
def test_the_leading_copy_is_durable_before_the_data(logged, sectors):
    """The leading metadata sector of a write back is a FUA write logged before its data.

    The log is in the order writes complete, so this is what makes the order hold on any disk: the
    data is sent only once the leading copy is durable.
    """
    chunk = 3
    entries, _, _ = write_old_and_new(logged, chunk * DATA_SECTORS, sectors)
    data, metadata = chunk_entries(entries, mark_index(entries, "old"), mark_index(entries, "new"), chunk)
    assert len(data) == 1 and len(metadata) == 1, (data, metadata)
    assert entries[metadata[0]].flags & FUA, "the leading copy is not a FUA write"
    assert metadata[0] < data[0], "the data reached the disk before the leading copy"


@pytest.mark.parametrize("sectors", [DATA_SECTORS, 1], ids=["whole chunk", "one sector"])
def test_a_write_cut_between_data_and_metadata_reads_old_or_new(logged, sectors):
    """A crash at any entry between two flushes leaves the chunk with its old or its new data.

    The leading copy has the CRC of the new data before the data is sent, and the trailing copy keeps
    that of the old one until the new data is flushed.
    """
    chunk = 3
    start = chunk * DATA_SECTORS
    entries, old, new = write_old_and_new(logged, start, sectors)
    for point in range(mark_index(entries, "old"), mark_index(entries, "new") + 1):
        assert read_after(logged, entries[: point + 1], start) in (old, new), f"after a crash at entry {point}"


# (chunk, first sector, sectors) written anew: chunks 3 and 5 share a metadata sector, 13 has another,
# all in region 0.
CUT_CHUNKS = [(3, 0, DATA_SECTORS), (5, 2, 1), (13, 0, DATA_SECTORS)]


def test_chunks_of_a_region_cut_between_flushes_read_old_or_new_each(logged):
    """Several chunks of a region written back between two flushes, two of them in one metadata sector.

    A crash at any entry leaves each sector with its old or its new data, whichever reached the disk:
    the new one is read by the leading copy, the old one by the trailing copy. Some points leave one
    chunk new and another old, or the test would check nothing. Once flushed, both copies are equal.
    """
    old = {chunk: pattern(f"old {chunk}", DATA_SECTORS) for chunk, _, _ in CUT_CHUNKS}
    writes, new = [], {}
    for chunk, first, sectors in CUT_CHUNKS:
        data = pattern(f"new {chunk}", sectors)
        writes.append((chunk * DATA_SECTORS + first, data))
        new[chunk] = old[chunk][: first * 512] + data + old[chunk][(first + sectors) * 512 :]
    write_and_flush(logged.upper_path, [(chunk * DATA_SECTORS, data) for chunk, data in old.items()])
    logged.mark("old")
    write_and_flush(logged.upper_path, writes)
    logged.mark("new")
    entries = logged.finish()

    mixed = False
    for point in range(mark_index(entries, "old"), mark_index(entries, "new") + 1):
        device = logged.replay(entries[: point + 1])
        try:
            states = set()
            for chunk in old:
                try:
                    data = device.read(chunk * DATA_SECTORS, DATA_SECTORS)
                except OSError as error:
                    pytest.fail(f"chunk {chunk} does not read after a crash at entry {point}: {error}")
                for index in range(DATA_SECTORS):
                    sector = data[index * 512 :][:512]
                    versions = (old[chunk][index * 512 :][:512], new[chunk][index * 512 :][:512])
                    assert sector in versions, f"chunk {chunk}, sector {index}, after a crash at entry {point}"
                states.add(data == new[chunk])
            mixed |= len(states) > 1
        finally:
            device.close()
    assert mixed, "no crash point left one chunk new and another old"

    logged.replay(entries).close()
    lower = BlockDevice(logged.lower_path)
    try:
        for chunk, _, _ in CUT_CHUNKS:
            lead, trail = metadata_sectors(chunk * DATA_SECTORS, logged.lower_sectors)
            assert lower.read(lead) == lower.read(trail), f"the copies of the metadata of chunk {chunk} differ"
    finally:
        lower.close()


def test_a_chunk_written_back_twice_between_flushes_reads_one_of_its_versions(logged):
    """Written back by age twice without a flush from above, a chunk could hold three versions.

    The driver flushes before the second write back, counted as a barrier, so a crash at any entry
    leaves one of them readable.
    """
    start = 3 * DATA_SECTORS
    versions = [pattern(name, DATA_SECTORS) for name in ("a", "b", "c")]
    write_and_flush(logged.upper_path, [(start, versions[0])])
    logged.mark("a")
    assert device_status()["barriers"] == 0
    device = BlockDevice(logged.upper_path)
    try:
        for version in versions[1:]:
            device.write(start, version)
            wait_for_write_back()
        assert device_status()["barriers"] == 1
        device.flush()
    finally:
        device.close()
    logged.mark("c")
    entries = logged.finish()
    for point in range(mark_index(entries, "a"), mark_index(entries, "c") + 1):
        assert read_after(logged, entries[: point + 1], start) in versions, f"after a crash at entry {point}"


@pytest.mark.parametrize("cut", ["leading copy", "data"])
def test_a_second_crash_after_one_between_the_copies(logged, cut):
    """A crash leaves the copies of a chunk different; the next write back of it reads it first.

    Cut after the leading copy, the old data is there and matches the trailing copy. Cut after the
    data, the new data matches the leading copy, so the driver writes its CRC into the trailing copy
    before the leading one changes again: otherwise a second crash would leave the new data with
    neither copy matching it.
    """
    chunk = 3
    start = chunk * DATA_SECTORS
    entries, old, new = write_old_and_new(logged, start, DATA_SECTORS)
    data, metadata = chunk_entries(entries, mark_index(entries, "old"), mark_index(entries, "new"), chunk)
    first = entries[: (metadata[0] if cut == "leading copy" else data[0]) + 1]
    survived = old if cut == "leading copy" else new
    assert read_after(logged, first, start) == survived

    logged.log_again()
    newer = pattern("newer", DATA_SECTORS)
    write_and_flush(logged.upper_path, [(start, newer)])
    status = device_status()
    assert (status["settle_reads"], status["settle_mismatches"], status["barriers"]) == (1, 0, 0), status
    second = logged.finish()
    for point in range(len(second)):
        assert read_after(logged, first + second[: point + 1], start) in (survived, newer), (
            f"after a second crash at entry {point}"
        )


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
    these points nothing of the driver is in flight. The trailing copies of the metadata are written after
    such a flush, followed by another. A crash between the data and the metadata of one write is covered
    by the two copies: test_a_write_cut_between_data_and_metadata_reads_old_or_new.

    Every write back writes its leading metadata sector with FUA, which makes about 270 more points
    than the 60 flushes; every FUA_STRIDE-th of them is checked, so that the test takes about 6 minutes.
    """
    entries, written, marks = ext4_workload(logged)
    start = mark_index(entries, "mkfs")
    points = [point for point in flush_points(entries) if point > start]
    assert points, "no flush in the log after mkfs"
    flushes = [point for point in points if entries[point].flags & FLUSH]
    fua_only = [point for point in points if not entries[point].flags & FLUSH]
    for point in sorted(flushes + fua_only[::FUA_STRIDE]):
        check_ext4_after_a_crash(logged, entries, point, written, marks)

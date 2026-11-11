"""The write back cache: when data reaches the lower device, and what reads see before it does."""

import errno
import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import FAULTY_NAME, LOWER_NAME, UPPER_NAME, device_status, dmsetup_remove, make_lower
from harness import DATA_SECTORS, SECTOR_SIZE, BlockDevice, metadata_sector, pattern, physical_sector, run

CHUNK = 5
FIRST = CHUNK * DATA_SECTORS
CACHE_MIB = 64
AGE_SECONDS = 1
WAIT_SECONDS = 10
# A delayed sector answers reads this late on the delayed stack, and writes at once.
READ_DELAY_MS = 1000
# Time for an I/O started in a thread to reach the lower device, well below the delay.
SETTLE_SECONDS = 0.3


def on_lower(stack, logical=FIRST, count=DATA_SECTORS):
    """What the lower device holds for logical sectors of one chunk."""
    return stack.lower.read(physical_sector(logical), count)


def with_sectors(data, changes):
    """The data of a chunk with some sectors replaced, from (index, sector) pairs."""
    result = bytearray(data)
    for index, sector in changes:
        result[index * SECTOR_SIZE : (index + 1) * SECTOR_SIZE] = sector
    return bytes(result)


@pytest.fixture
def original(stack):
    """A chunk written and flushed, so the lower device holds it.

    An entry written back goes to the head of the free list with its page as it was, so the next
    write would get the same page, still holding this data, and a cache that wrote or read the
    whole page instead of its dirty sectors would look right. Another chunk is written and flushed
    after it, so that the page holds other data.
    """
    data = pattern("original", DATA_SECTORS)
    stack.upper.write(FIRST, data)
    stack.upper.flush()
    assert on_lower(stack) == data
    stack.upper.write(FIRST + 2 * DATA_SECTORS, pattern("elsewhere", DATA_SECTORS))
    stack.upper.flush()
    return data


def test_a_write_reaches_the_lower_device_on_a_flush(stack):
    data = pattern("flush", DATA_SECTORS)
    stack.upper.write(FIRST, data)
    assert on_lower(stack) == bytes(len(data)), "the write went straight to the lower device"
    assert stack.status()["dirty"] == 1
    stack.upper.flush()
    assert on_lower(stack) == data
    assert stack.status()["dirty"] == 0


def test_dirty_data_is_written_back_by_age(stack):
    data = pattern("age", DATA_SECTORS)
    stack.upper.write(FIRST, data)
    deadline = time.monotonic() + WAIT_SECONDS
    while on_lower(stack) != data:
        assert time.monotonic() < deadline, f"not written back in {WAIT_SECONDS}s without a flush"
        time.sleep(AGE_SECONDS / 4)
    assert stack.status()["dirty"] == 0


def test_a_dsync_write_reaches_the_lower_device(stack):
    """On a block device RWF_DSYNC gives a FUA write and then an fsync, so this cannot tell whether
    the FUA write itself waited; test_fsync_on_ext4_leaves_nothing_in_the_cache does."""
    data = pattern("fua", DATA_SECTORS)
    stack.upper.write(FIRST, data, os.RWF_DSYNC)
    assert on_lower(stack) == data
    assert stack.status()["dirty"] == 0


def test_a_suspend_writes_back(stack):
    data = pattern("suspend", DATA_SECTORS)
    stack.upper.write(FIRST, data)
    run("dmsetup", "suspend", UPPER_NAME)
    try:
        assert on_lower(stack) == data
    finally:
        run("dmsetup", "resume", UPPER_NAME)
    assert stack.upper.read(FIRST, DATA_SECTORS) == data


def test_a_partial_chunk_writes_only_its_sectors(stack, original):
    """Sectors 1 and 5 are dirty: the sectors between them must not be written from the cache."""
    one, five = pattern("one", 1), pattern("five", 1)
    stack.upper.write(FIRST + 1, one)
    stack.upper.write(FIRST + 5, five)
    stack.upper.flush()
    expected = with_sectors(original, [(1, one), (5, five)])
    assert on_lower(stack) == expected
    for index in range(DATA_SECTORS):  # each on its own, so each CRC is checked
        assert stack.upper.read(FIRST + index) == expected[index * SECTOR_SIZE :][:SECTOR_SIZE]


def test_a_read_of_a_partly_dirty_chunk(stack, original):
    """The dirty sector comes from the cache, the others from the lower device."""
    update = pattern("update", 1)
    stack.upper.write(FIRST + 3, update)
    assert stack.status()["dirty"] == 1
    assert stack.upper.read(FIRST, DATA_SECTORS) == with_sectors(original, [(3, update)])
    assert stack.status()["dirty"] == 1, "the sector was written back during the read"


def test_a_dirty_sector_reads_while_a_clean_one_is_damaged(stack, original):
    stack.lower.flip_bit(physical_sector(FIRST + 6))
    update = pattern("update", 1)
    stack.upper.write(FIRST + 3, update)
    assert stack.upper.read(FIRST + 3) == update
    assert stack.upper.read(FIRST, 3) == original[: 3 * SECTOR_SIZE]
    for sector, count in [(FIRST + 6, 1), (FIRST, DATA_SECTORS)]:
        with pytest.raises(OSError) as error:
            stack.upper.read(sector, count)
        assert error.value.errno == errno.EIO
    assert stack.status()["dirty"] == 1, "the sector was written back during the reads"


@pytest.mark.slow
def test_writes_larger_than_the_cache_go_through(make_stack):
    """More data than the cache holds, written without a flush, all arrives.

    One writer of 1 MiB at a time does not outrun the write back. Whether writes wait for free
    entries is not checked deterministically yet, see TODO.md.
    """
    stack = make_stack(2 * CACHE_MIB)
    mib = 3 * CACHE_MIB // 2
    blocks = [os.urandom(1 << 20) for _ in range(mib)]
    for index, block in enumerate(blocks):
        stack.upper.write(index * 2048, block)
    stack.upper.flush()
    for index, block in enumerate(blocks):
        assert stack.upper.read(index * 2048, 2048) == block, f"MiB {index}"


class DelayedStack:
    """The driver on dm-delay, which holds back reads of some sectors of the lower device.

    The rest of the lower device is dm-linear, and writes to those sectors go down at once.
    dm-delay holds a bio back before it sends it, so a delayed read sees what was written meanwhile.

    With the metadata sector of CHUNK delayed, every write back of the chunks of that sector reads
    their old CRCs for a second. With the data of CHUNK delayed, a read of the chunk gets its CRCs
    at once and its data a second later, so a write back that does not wait for the read lands in
    between.
    """

    def __init__(self, slow, count, lower_mib=4):
        sectors = lower_mib * 2048
        lower = make_lower(sectors)
        end = slow + count
        table = (
            f"0 {slow} linear {lower} 0\n"
            f"{slow} {count} delay {lower} {slow} {READ_DELAY_MS} {lower} {slow} 0\n"
            f"{end} {sectors - end} linear {lower} {end}\n"
        )
        run("dmsetup", "create", FAULTY_NAME, stdin=table)
        run("dmsetup", "create", UPPER_NAME, stdin=f"0 {sectors} corrdm /dev/mapper/{FAULTY_NAME}\n")
        self.upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
        self.threads = ThreadPoolExecutor(max_workers=1)
        self.original = pattern("original", DATA_SECTORS)
        self.upper.write(FIRST, self.original)
        self.upper.flush()

    def in_background(self, action):
        """Starts an I/O in another thread and gives it time to reach the lower device."""
        future = self.threads.submit(action)
        time.sleep(SETTLE_SECONDS)
        assert not future.done(), "the I/O did not wait for the delayed sector"
        return future

    def remove(self):
        self.threads.shutdown()
        self.upper.close()
        for name in (UPPER_NAME, FAULTY_NAME, LOWER_NAME):
            dmsetup_remove(name)


@pytest.fixture
def delayed():
    """Reads of the metadata sector of CHUNK are delayed."""
    stack = DelayedStack(metadata_sector(FIRST), 1)
    yield stack
    stack.remove()


@pytest.fixture
def delayed_data():
    """Reads of the data of CHUNK are delayed."""
    stack = DelayedStack(physical_sector(FIRST), DATA_SECTORS)
    yield stack
    stack.remove()


def test_a_write_back_waits_for_a_read_in_flight(delayed_data):
    """A read of the chunk holds off its write back until it has both its data and its CRCs.

    Without that, the write back lands between them: the read gets the old CRCs and the new data.
    """
    delayed = delayed_data
    read = delayed.in_background(lambda: delayed.upper.read(FIRST, DATA_SECTORS))
    new = pattern("new", DATA_SECTORS)
    delayed.upper.write(FIRST, new)
    delayed.upper.flush()
    assert read.result() == delayed.original
    assert delayed.upper.read(FIRST, DATA_SECTORS) == new


def test_the_write_backs_of_a_chunk_go_one_at_a_time(delayed):
    """Sectors 1 and 5 are written back by two lower writes, each merging its CRC into the old ones.

    At once, both would read the old CRCs and the later one would undo the earlier.
    """
    one, five = pattern("one", 1), pattern("five", 1)
    delayed.upper.write(FIRST + 1, one)
    delayed.upper.write(FIRST + 5, five)
    delayed.upper.flush()
    expected = with_sectors(delayed.original, [(1, one), (5, five)])
    assert delayed.upper.read(FIRST, DATA_SECTORS) == expected


def test_the_write_backs_of_chunks_sharing_a_metadata_sector_go_one_at_a_time(delayed):
    """CHUNK and the chunk after it keep their CRCs in one sector, and each write back merges into it.

    At once, both would read the old sector and the later one would undo the CRCs of the earlier.
    """
    neighbour = pattern("neighbour", DATA_SECTORS)
    one = pattern("one", 1)
    delayed.upper.write(FIRST + 1, one)
    delayed.upper.write(FIRST + DATA_SECTORS, neighbour)
    delayed.upper.flush()
    assert delayed.upper.read(FIRST, DATA_SECTORS) == with_sectors(delayed.original, [(1, one)])
    assert delayed.upper.read(FIRST + DATA_SECTORS, DATA_SECTORS) == neighbour


def test_a_read_of_a_clean_sector_waits_for_the_write_back(delayed):
    """Sector 5 is not written back, but a read of it waits until the write back of sector 1 ends.

    Otherwise a stream of reads of the chunk could hold its write back off for ever.
    """
    one = pattern("one", 1)
    delayed.upper.write(FIRST + 1, one)
    flush = delayed.in_background(delayed.upper.flush)
    before = device_status()["read_waits"]
    assert delayed.upper.read(FIRST + 5) == delayed.original[5 * SECTOR_SIZE :][:SECTOR_SIZE]
    assert device_status()["read_waits"] == before + 1
    flush.result()
    assert delayed.upper.read(FIRST, DATA_SECTORS) == with_sectors(delayed.original, [(1, one)])

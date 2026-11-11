"""The write back cache: when data reaches the lower device, and what reads see before it does."""

import errno
import os
import time

import pytest

from conftest import UPPER_NAME
from harness import DATA_SECTORS, SECTOR_SIZE, pattern, physical_sector, run

CHUNK = 5
FIRST = CHUNK * DATA_SECTORS
CACHE_MIB = 64
AGE_SECONDS = 1
WAIT_SECONDS = 10


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

    One writer of 1 MiB at a time does not outrun the write back, so whether writes wait for free
    entries is checked under fio in test_lifecycle.py and test_memory.py.
    """
    stack = make_stack(2 * CACHE_MIB)
    mib = 3 * CACHE_MIB // 2
    blocks = [os.urandom(1 << 20) for _ in range(mib)]
    for index, block in enumerate(blocks):
        stack.upper.write(index * 2048, block)
    stack.upper.flush()
    for index, block in enumerate(blocks):
        assert stack.upper.read(index * 2048, 2048) == block, f"MiB {index}"

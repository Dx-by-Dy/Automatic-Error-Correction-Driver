"""Failures of the lower device: they fail only the I/O that needs the failed sector.

dm-dust sits between the driver and the lower device, with 512-byte blocks, so a data sector and a
metadata sector fail apart. Its blocks are sectors of the lower device. A block fails reads once
added and enabled; a write to it clears it, unless it was added with a count of writes to fail
first, and until then reads of it fail too. One test loads dm-flakey in its place instead.
"""

import errno

import pytest

from conftest import FAULTY_NAME, LOWER_NAME, UPPER_NAME, device_status, dmsetup_remove, make_lower
from harness import DATA_SECTORS, BlockDevice, capacity, metadata_sector, pattern, physical_sector, run

LOWER_MIB = 4
CACHE_MIB = 64
CHUNKS = 3
AREA = CHUNKS * DATA_SECTORS
BAD_CHUNK = 1


class FaultyStack:
    """The driver on dm-dust on a zeroed lower device."""

    def __init__(self, lower_mib=LOWER_MIB):
        sectors = lower_mib * 2048
        self.lower = make_lower(sectors)
        self.lower_sectors = sectors
        run("dmsetup", "create", FAULTY_NAME, stdin=f"0 {sectors} dust {self.lower} 0 512\n")
        run("dmsetup", "create", UPPER_NAME, stdin=f"0 {sectors} corrdm /dev/mapper/{FAULTY_NAME}\n")
        self.sectors = capacity(sectors)
        self.upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")

    def message(self, *words):
        run("dmsetup", "message", FAULTY_NAME, "0", *map(str, words))

    def fail(self, lower_sector, writes=None):
        """Makes reads of a lower sector fail and, with a count, that many writes to it."""
        self.message("addbadblock", lower_sector, *([] if writes is None else [writes]))
        self.message("enable")

    def load(self, table):
        """Replaces the table of the faulty device, which the driver keeps open."""
        run("dmsetup", "suspend", FAULTY_NAME)
        run("dmsetup", "reload", FAULTY_NAME, stdin=f"0 {self.lower_sectors} {table}\n")
        run("dmsetup", "resume", FAULTY_NAME)

    def heal(self):
        self.message("clearbadblocks")

    def close(self):
        self.upper.close()

    def remove(self):
        self.close()
        for name in (UPPER_NAME, FAULTY_NAME, LOWER_NAME):
            dmsetup_remove(name)


def flushed_write(device, start, data):
    """A write that has reached the lower device, or an error if it could not."""
    device.write(start, data)
    device.flush()


@pytest.fixture
def faulty():
    stack = FaultyStack()
    flushed_write(stack.upper, 0, pattern("before", AREA))
    yield stack
    stack.remove()


def fails_with_eio(action):
    try:
        action()
    except OSError as error:
        assert error.errno == errno.EIO, error
        return True
    return False


def unreadable_sectors(device):
    """The sectors of the area that fail when read one at a time."""
    return [sector for sector in range(AREA) if fails_with_eio(lambda: device.read(sector))]


def chunk_sectors(chunk):
    return list(range(chunk * DATA_SECTORS, (chunk + 1) * DATA_SECTORS))


@pytest.mark.parametrize("index", [0, DATA_SECTORS - 1], ids=["first sector", "last sector"])
def test_failed_data_sector_fails_only_its_reads(faulty, index):
    bad = BAD_CHUNK * DATA_SECTORS + index
    faulty.fail(physical_sector(bad))

    assert unreadable_sectors(faulty.upper) == [bad]
    assert fails_with_eio(lambda: faulty.upper.read(0, AREA))
    assert faulty.upper.read(0, BAD_CHUNK * DATA_SECTORS) == pattern("before", AREA)[: BAD_CHUNK * DATA_SECTORS * 512]


def test_failed_metadata_sector_fails_only_its_chunk(faulty):
    faulty.fail(metadata_sector(BAD_CHUNK * DATA_SECTORS))
    assert unreadable_sectors(faulty.upper) == chunk_sectors(BAD_CHUNK)


def test_device_works_again_once_the_sector_reads(faulty):
    faulty.fail(physical_sector(BAD_CHUNK * DATA_SECTORS))
    faulty.fail(metadata_sector((BAD_CHUNK + 1) * DATA_SECTORS))
    assert unreadable_sectors(faulty.upper)
    faulty.heal()
    assert faulty.upper.read(0, AREA) == pattern("before", AREA)


def test_whole_chunk_write_over_a_failed_metadata_sector_needs_no_read(faulty):
    """A whole chunk is written without reading its old metadata, and the write clears the bad sector."""
    faulty.fail(metadata_sector(BAD_CHUNK * DATA_SECTORS))
    assert fails_with_eio(lambda: faulty.upper.read(BAD_CHUNK * DATA_SECTORS)), "the failure is not on"
    new = pattern("after", DATA_SECTORS)
    flushed_write(faulty.upper, BAD_CHUNK * DATA_SECTORS, new)
    assert faulty.upper.read(BAD_CHUNK * DATA_SECTORS, DATA_SECTORS) == new
    assert not unreadable_sectors(faulty.upper)


def test_partial_write_fails_when_the_old_metadata_does_not_read(faulty):
    """Its CRCs cannot be merged with those of the other sectors, so the write fails.

    What the chunk holds afterwards is open, see "Data and CRC are not written atomically" in
    TODO.md; here only the error and the other chunks are checked.
    """
    faulty.fail(metadata_sector(BAD_CHUNK * DATA_SECTORS))
    assert fails_with_eio(lambda: flushed_write(faulty.upper, BAD_CHUNK * DATA_SECTORS + 2, pattern("after", 1)))
    faulty.heal()
    readable = [sector for sector in range(AREA) if sector not in chunk_sectors(BAD_CHUNK)]
    assert not set(unreadable_sectors(faulty.upper)) & set(readable)


@pytest.mark.parametrize(
    "lower_sector, start, sectors",
    [
        (physical_sector(BAD_CHUNK * DATA_SECTORS + 3), BAD_CHUNK * DATA_SECTORS, DATA_SECTORS),
        (metadata_sector(BAD_CHUNK * DATA_SECTORS), BAD_CHUNK * DATA_SECTORS, DATA_SECTORS),
        (physical_sector(BAD_CHUNK * DATA_SECTORS + 3), BAD_CHUNK * DATA_SECTORS + 3, 1),
    ],
    ids=["data of a whole chunk", "metadata of a whole chunk", "data of one sector"],
)
def test_failed_write_is_reported(faulty, lower_sector, start, sectors):
    """A write whose data or metadata fails to reach the lower device reports it, and the device goes on.

    The error may come from the write or from the flush after it.

    A failed metadata write of a partial write is in test_writes_fail_while_reads_go_on: dm-dust
    would fail its read of the old metadata first.
    """
    faulty.fail(lower_sector, writes=1)
    assert fails_with_eio(lambda: flushed_write(faulty.upper, start, pattern("after", sectors)))

    faulty.heal()
    new = pattern("again", sectors)
    flushed_write(faulty.upper, start, new)
    assert faulty.upper.read(start, sectors) == new
    others = [sector for sector in range(AREA) if sector not in chunk_sectors(BAD_CHUNK)]
    assert not set(unreadable_sectors(faulty.upper)) & set(others)


def test_writes_fail_while_reads_go_on(faulty):
    """dm-flakey fails every write and lets reads through, as a drive that can no longer write.

    Whole, partial and crossing writes stay in the cache: they read back, and every flush fails
    while they are not on the lower device. Once dm-linear is back, a flush writes them back.
    """
    faulty.load(f"flakey {faulty.lower} 0 0 1 1 error_writes")
    expected = bytearray(pattern("before", AREA))
    for start, sectors in [(0, DATA_SECTORS), (BAD_CHUNK * DATA_SECTORS + 2, 1), (5, 6)]:
        data = pattern(f"after {start}", sectors)
        assert fails_with_eio(lambda: flushed_write(faulty.upper, start, data)), (start, sectors)
        expected[start * 512 : (start + sectors) * 512] = data
    assert faulty.upper.read(0, AREA) == expected
    assert fails_with_eio(faulty.upper.flush), "a flush succeeded with chunks not written back"
    assert device_status()["failed"] > 0

    faulty.load(f"linear {faulty.lower} 0")
    faulty.upper.flush()
    assert device_status()["failed"] == 0
    assert faulty.upper.read(0, AREA) == expected
    flushed_write(faulty.upper, 0, pattern("again", AREA))
    assert faulty.upper.read(0, AREA) == pattern("again", AREA)


def test_a_cache_full_of_failed_chunks_refuses_writes():
    """With every write back failing, the entries fill up and then new writes fail.

    What was taken in stays readable, and reaches the lower device once it takes writes again.
    """
    faulty = FaultyStack(CACHE_MIB + 32)
    try:
        faulty.load(f"flakey {faulty.lower} 0 0 1 1 error_writes")
        accepted = 0
        while accepted <= CACHE_MIB:
            if fails_with_eio(lambda: faulty.upper.write(accepted * 2048, pattern(accepted, 2048))):
                break
            accepted += 1
        assert 0 < accepted <= CACHE_MIB, f"{accepted} MiB taken in by a cache of {CACHE_MIB} MiB"
        assert faulty.upper.read(0, 2048) == pattern(0, 2048)

        faulty.load(f"linear {faulty.lower} 0")
        faulty.upper.flush()
        assert device_status()["failed"] == 0
        for mib in range(accepted):
            assert faulty.upper.read(mib * 2048, 2048) == pattern(mib, 2048), f"MiB {mib}"
    finally:
        faulty.remove()

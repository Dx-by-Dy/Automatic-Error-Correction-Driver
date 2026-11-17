"""Discard and write zeroes: whole chunks read as zeros through the bitmap of written chunks.

The driver offers discard in whole chunks of 4 KiB and does not pass it down: the bits of the whole
chunks of a discard are cleared, the partial chunks at its ends are left as they are, and data in the
cache for those chunks is dropped. A cleared bit reaches the lower device with the next flush.

Write zeroes is offered where the lower device has it, and not passed down either: its whole chunks
are cleared as by a discard, and its partial chunks written as zeros through the cache.
"""

import hashlib
import os

import pytest

from harness import (
    DATA_SECTORS,
    SECTOR_SIZE,
    BlockDevice,
    pattern,
    physical_sector,
    queue_limit,
    run,
)

# A chunk with written neighbours, as in test_corruption.py; the discards start inside the chunk before.
CHUNK = 5
FIRST = CHUNK * DATA_SECTORS
ZEROS = bytes(DATA_SECTORS * SECTOR_SIZE)
MOUNTPOINT = "/mnt/dcorr_discard"


def lower_writes(stack):
    """Writes the lower device has completed, from its statistics in sysfs."""
    device = os.path.basename(os.path.realpath(stack.lower_path))
    with open(f"/sys/block/{device}/stat") as stat:
        return int(stat.read().split()[4])


@pytest.fixture
def written(stack):
    """Five written chunks from `FIRST - 16`, flushed; returns their contents."""
    data = pattern("written", 5 * DATA_SECTORS)
    stack.upper.write(FIRST - 2 * DATA_SECTORS, data)
    stack.upper.flush_settled()
    return data


def test_the_device_offers_discard_in_chunks_and_write_zeroes(stack):
    """The lower device, dm-linear on the test disk, has write zeroes, so the driver offers it, of any length."""
    assert queue_limit(stack.lower_path, "write_zeroes_max_bytes") > 0, "the lower device has no write zeroes"
    assert queue_limit(stack.upper_path, "discard_granularity") == DATA_SECTORS * SECTOR_SIZE
    assert queue_limit(stack.upper_path, "discard_max_bytes") >= 1 << 30
    assert queue_limit(stack.upper_path, "write_zeroes_max_bytes") >= 1 << 30


def test_a_discard_reads_zeros_in_whole_chunks_and_keeps_the_ends(stack, written):
    """From sector 3 of the chunk before to sector 5 of the chunk after: the two chunks between read as zeros."""
    start = FIRST - DATA_SECTORS + 3
    end = FIRST + 2 * DATA_SECTORS + 5
    before = stack.status()
    stack.upper.discard(start, end - start)

    status = stack.status()
    # The block layer cuts the unaligned head off at the granularity, a discard of no whole chunk.
    assert status["discards"] > before["discards"]
    assert status["discarded_chunks"] == before["discarded_chunks"] + 2
    expected = bytearray(written)
    offset = DATA_SECTORS * SECTOR_SIZE
    expected[2 * offset : 4 * offset] = bytes(2 * offset)
    assert stack.upper.read(FIRST - 2 * DATA_SECTORS, 5 * DATA_SECTORS) == expected
    assert stack.status()["unwritten_reads"] > before["unwritten_reads"]


def test_a_discard_inside_one_chunk_changes_nothing(stack, written):
    before = stack.status()
    stack.upper.discard(FIRST + 1, DATA_SECTORS - 2)
    status = stack.status()
    assert status["discards"] == before["discards"] + 1
    assert status["discarded_chunks"] == before["discarded_chunks"]
    assert stack.upper.read(FIRST - 2 * DATA_SECTORS, 5 * DATA_SECTORS) == written


def test_a_discard_writes_no_data_below(stack, written):
    """Nothing is written at the discard; after a flush only the bitmap is, and the old data stays below."""
    before = lower_writes(stack)
    stack.upper.discard(FIRST, DATA_SECTORS)
    assert lower_writes(stack) == before
    stack.upper.flush_settled()
    assert stack.lower.read(physical_sector(FIRST, stack.lower_sectors), DATA_SECTORS) == (
        written[2 * DATA_SECTORS * SECTOR_SIZE :][: DATA_SECTORS * SECTOR_SIZE]
    )
    assert stack.upper.read(FIRST, DATA_SECTORS) == ZEROS


def test_data_in_the_cache_is_dropped_by_a_discard(stack):
    """A chunk written and not yet written back is discarded with its entry: it never reaches the lower device."""
    stack.upper.write(FIRST, pattern("dropped", DATA_SECTORS))
    assert stack.status()["dirty"] == 1
    stack.upper.discard(FIRST, DATA_SECTORS)
    assert stack.status()["dirty"] == 0
    assert stack.upper.read(FIRST, DATA_SECTORS) == ZEROS
    stack.upper.flush_settled()
    assert stack.lower.read(physical_sector(FIRST, stack.lower_sectors), DATA_SECTORS) == ZEROS


@pytest.mark.parametrize("flush", [True, False], ids=["flushed", "suspended"])
def test_a_discard_survives_recreating_the_device(stack, written, flush):
    """After a flush, or the sync of a suspend, the cleared bits are on the lower device."""
    stack.upper.discard(FIRST, DATA_SECTORS)
    if flush:
        stack.upper.flush()
    stack.recreate_upper()
    assert stack.upper.read(FIRST, DATA_SECTORS) == ZEROS
    assert stack.upper.read(FIRST + DATA_SECTORS, DATA_SECTORS) == (
        written[3 * DATA_SECTORS * SECTOR_SIZE :][: DATA_SECTORS * SECTOR_SIZE]
    )


def test_a_write_after_a_discard_is_written_whole_after_a_barrier(stack, written):
    """The chunk counts as never written: a write of one sector fills the rest with zeros. Its bit is still
    set on the lower device until a sync, so the driver syncs before the write back, as a barrier, and does
    not settle the chunk."""
    stack.upper.discard(FIRST, DATA_SECTORS)
    before = stack.status()
    update = pattern("after", 1)
    stack.upper.write(FIRST + 2, update)
    stack.upper.flush_settled()
    status = stack.status()
    assert status["barriers"] == before["barriers"] + 1
    assert status["settle_reads"] == before["settle_reads"]
    stack.recreate_upper()
    expected = bytearray(ZEROS)
    expected[2 * SECTOR_SIZE : 3 * SECTOR_SIZE] = update
    assert stack.upper.read(FIRST, DATA_SECTORS) == expected


def test_a_second_write_after_a_flushed_discard_needs_no_barrier(stack, written):
    """Once the cleared bit is on the lower device, a first write back goes without a sync."""
    stack.upper.discard(FIRST, DATA_SECTORS)
    stack.upper.flush_settled()
    before = stack.status()
    stack.upper.write(FIRST, pattern("after", DATA_SECTORS))
    stack.upper.flush_settled()
    assert stack.status()["barriers"] == before["barriers"]


def test_blkdiscard_of_the_whole_device_is_one_discard(stack, written):
    """Device mapper does not split a discard at the chunks, only the block layer by its limits."""
    stack.upper.close()
    before = stack.status()
    run("blkdiscard", stack.upper_path)
    stack.upper = BlockDevice(stack.upper_path)
    status = stack.status()
    assert status["discards"] == before["discards"] + 1
    assert status["discarded_chunks"] == before["discarded_chunks"] + stack.sectors // DATA_SECTORS
    assert stack.upper.read(FIRST - 2 * DATA_SECTORS, 5 * DATA_SECTORS) == bytes(len(written))


def digest(path):
    with open(path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()


@pytest.fixture
def ext4(stack):
    run("mkfs.ext4", "-F", "-q", stack.upper_path)
    os.makedirs(MOUNTPOINT, exist_ok=True)
    run("mount", stack.upper_path, MOUNTPOINT)
    yield stack
    run("umount", MOUNTPOINT, check=False)


def test_fstrim_on_ext4_keeps_the_files(ext4):
    """mkfs discards the device; fstrim discards the space of deleted files; the rest survives a remount."""
    kept = {}
    for name in ("kept", "deleted"):
        path = os.path.join(MOUNTPOINT, name)
        with open(path, "wb") as file:
            file.write(os.urandom(4 << 20))
        kept[name] = digest(path)
    run("sync")
    os.unlink(os.path.join(MOUNTPOINT, "deleted"))
    run("sync")
    before = ext4.status()
    run("fstrim", MOUNTPOINT)
    assert ext4.status()["discarded_chunks"] >= before["discarded_chunks"] + (4 << 20) // 4096

    run("umount", MOUNTPOINT)
    run("e2fsck", "-f", "-n", ext4.upper_path)
    run("mount", ext4.upper_path, MOUNTPOINT)
    assert digest(os.path.join(MOUNTPOINT, "kept")) == kept["kept"]


# Write zeroes from sector 3 of the chunk before to sector 5 of the chunk after, as the discards above.
ZERO_START = FIRST - DATA_SECTORS + 3
ZERO_END = FIRST + 2 * DATA_SECTORS + 5
WRITTEN_START = FIRST - 2 * DATA_SECTORS


def zeroed(data):
    """The five chunks from `FIRST - 16` as they read after the write zeroes."""
    expected = bytearray(data)
    expected[(ZERO_START - WRITTEN_START) * SECTOR_SIZE : (ZERO_END - WRITTEN_START) * SECTOR_SIZE] = bytes(
        (ZERO_END - ZERO_START) * SECTOR_SIZE
    )
    return bytes(expected)


def test_write_zeroes_reads_zeros_and_keeps_the_neighbours(stack, written):
    """The two whole chunks between read as zeros without a read of the lower device, as their bits are
    cleared; the partial ends are zeros through the cache. It is no discard, so the counters of discards stay."""
    before = stack.status()
    stack.upper.zeroout(ZERO_START, ZERO_END - ZERO_START)

    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == zeroed(written)
    status = stack.status()
    assert status["unwritten_reads"] >= before["unwritten_reads"] + 2
    assert status["discards"] == before["discards"]
    assert status["discarded_chunks"] == before["discarded_chunks"]


@pytest.mark.parametrize("flush", [True, False], ids=["flushed", "suspended"])
def test_write_zeroes_survives_recreating_the_device(stack, written, flush):
    """After a flush, or the sync of a suspend, the cleared bits and the zeroed ends are on the lower device."""
    stack.upper.zeroout(ZERO_START, ZERO_END - ZERO_START)
    if flush:
        stack.upper.flush()
    stack.recreate_upper()
    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == zeroed(written)


def test_write_zeroes_over_data_in_the_cache(stack, written):
    """Data written and not yet written back: the whole chunks drop it, the ends zero it in the cache."""
    new = pattern("new", 5 * DATA_SECTORS)
    stack.upper.write(WRITTEN_START, new)
    assert stack.status()["dirty"] == 5
    stack.upper.zeroout(ZERO_START, ZERO_END - ZERO_START)

    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == zeroed(new)
    stack.upper.flush()
    stack.recreate_upper()
    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == zeroed(new)


def test_blkdiscard_z_zeroes_through_write_zeroes(stack, written):
    """blkdiscard -z, as a user zeroes a range, comes as write zeroes: the whole chunks read without a read
    of the lower device, as they would not after ordinary writes of zeros."""
    before = stack.status()
    run(
        "blkdiscard", "-z",
        "-o", str(ZERO_START * SECTOR_SIZE), "-l", str((ZERO_END - ZERO_START) * SECTOR_SIZE),
        stack.upper_path,
    )
    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == zeroed(written)
    assert stack.status()["unwritten_reads"] >= before["unwritten_reads"] + 2


def test_write_zeroes_inside_one_chunk_zeroes_only_its_sectors(stack, written):
    start = FIRST + 2
    stack.upper.zeroout(start, 3)
    expected = bytearray(written)
    offset = (start - WRITTEN_START) * SECTOR_SIZE
    expected[offset : offset + 3 * SECTOR_SIZE] = bytes(3 * SECTOR_SIZE)
    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == expected
    stack.upper.flush()
    stack.recreate_upper()
    assert stack.upper.read(WRITTEN_START, 5 * DATA_SECTORS) == expected

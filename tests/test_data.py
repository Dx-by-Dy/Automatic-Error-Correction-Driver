"""Data written through the device reads back unchanged and lands where the layout says."""

import random

import pytest

from harness import (
    CHUNK_SIZE,
    CHUNKS_PER_METADATA_SECTOR,
    DATA_SECTORS,
    METADATA_ENTRY_SIZE,
    REGION_DATA_SECTORS,
    SECTOR_SIZE,
    metadata_offset,
    metadata_sectors,
    pattern,
    physical_sector,
    run,
)

ZERO_SECTOR = bytes(SECTOR_SIZE)


def test_capacity_excludes_metadata(stack):
    """16 MiB below: two areas of the superblock of 2048 sectors, 3 whole regions of 8448 sectors,
    then 3328 sectors, of which 256 are metadata."""
    assert stack.lower_sectors == 32768
    reported = int(run("blockdev", "--getsz", stack.upper_path).stdout)
    assert reported == 3 * 8192 + 3072


def test_layout_of_the_first_chunks_of_two_regions(stack):
    """The positions spelled out, apart from harness.py: the area of copy 0 of the superblock, 2048
    sectors, then regions of 8448 sectors, with the data after 256 sectors of metadata and the leading
    copy after the 128 sectors of the trailing copy of the region before. 16 MiB below make 4
    regions: copy 1 of the superblock takes 2048 sectors after region 1, at 18944, so region 2 starts
    at 20992, and the trailing copy of region 3 is at the start of region 0."""
    first, second = pattern("region 0", DATA_SECTORS), pattern("region 1", DATA_SECTORS)
    stack.upper.write(0, first)
    stack.upper.write(8192, second)
    stack.upper.flush_settled()
    assert stack.lower.read(0)[:8] == stack.lower.read(18944)[:8] == b"dm-dcorr", "the copies of the superblock"
    assert stack.lower.read(2048 + 256, DATA_SECTORS) == first
    assert stack.lower.read(10496 + 256, DATA_SECTORS) == second
    for metadata in (2048 + 128, 10496 + 128):
        sector = stack.lower.read(metadata)
        assert sector[:METADATA_ENTRY_SIZE] != bytes(METADATA_ENTRY_SIZE), f"sector {metadata}"
        assert sector[METADATA_ENTRY_SIZE:] == bytes(SECTOR_SIZE - METADATA_ENTRY_SIZE), f"sector {metadata}"
    assert stack.lower.read(10496) == stack.lower.read(2048 + 128), "trailing copy of region 0"
    assert stack.lower.read(20992) == stack.lower.read(10496 + 128), "trailing copy of region 1"
    assert stack.lower.read(2048, 128) == bytes(128 * SECTOR_SIZE), "trailing copy of region 3, not written"


def test_fresh_device_reads_zeros(stack):
    assert stack.upper.read(0, 64) == bytes(64 * SECTOR_SIZE)


@pytest.mark.parametrize("start", [0, 1, 7, 8, 13], ids=lambda s: f"start{s}")
@pytest.mark.parametrize("sectors", [1, 2, 7, 8, 9, 16, 64, 128, 256, 2048], ids=lambda s: f"{s}s")
def test_roundtrip(stack, start, sectors):
    data = pattern("roundtrip", sectors)
    stack.upper.write(start, data)
    assert stack.upper.read(start, sectors) == data


@pytest.mark.parametrize(
    "start", [0, REGION_DATA_SECTORS - 2 * DATA_SECTORS - 3], ids=["start of a region", "across regions"]
)
def test_data_lands_at_the_layout_position(stack, start):
    sectors = 4 * DATA_SECTORS
    data = pattern("layout", sectors)
    stack.upper.write(start, data)
    stack.upper.flush()
    for logical in range(start, start + sectors):
        expected = data[(logical - start) * SECTOR_SIZE :][:SECTOR_SIZE]
        assert stack.lower.read(physical_sector(logical, stack.lower_sectors)) == expected, f"sector {logical}"
    assert stack.upper.read(start, sectors) == data


def test_the_last_chunk_of_a_short_region(stack):
    last = stack.sectors - DATA_SECTORS
    data = pattern("last", DATA_SECTORS)
    stack.upper.write(last, data)
    stack.upper.flush()
    assert stack.lower.read(physical_sector(last, stack.lower_sectors), DATA_SECTORS) == data
    assert stack.upper.read(last, DATA_SECTORS) == data


def test_metadata_is_written_outside_the_data(stack):
    """The entry of the chunk changes in its sector, in both copies; the other entries and the next sector do not."""
    chunk = 3
    stack.upper.write(chunk * DATA_SECTORS, pattern("metadata", DATA_SECTORS))
    stack.upper.flush_settled()
    offset = metadata_offset(chunk * DATA_SECTORS)
    next_chunk = CHUNKS_PER_METADATA_SECTOR * DATA_SECTORS
    for lower, following in zip(
        metadata_sectors(chunk * DATA_SECTORS, stack.lower_sectors), metadata_sectors(next_chunk, stack.lower_sectors)
    ):
        sector = stack.lower.read(lower)
        assert sector[offset : offset + METADATA_ENTRY_SIZE] != bytes(METADATA_ENTRY_SIZE), lower
        assert sector[:offset] + sector[offset + METADATA_ENTRY_SIZE :] == bytes(SECTOR_SIZE - METADATA_ENTRY_SIZE)
        assert stack.lower.read(following) == ZERO_SECTOR, following


@pytest.mark.parametrize("sector", range(DATA_SECTORS))
def test_partial_write_to_an_empty_chunk(stack, sector):
    data = pattern("partial", 1)
    stack.upper.write(sector, data)
    expected = bytearray(CHUNK_SIZE)
    expected[sector * SECTOR_SIZE : (sector + 1) * SECTOR_SIZE] = data
    assert stack.upper.read(0, DATA_SECTORS) == bytes(expected)


@pytest.mark.parametrize("sector", range(DATA_SECTORS))
def test_partial_write_keeps_the_crcs_of_its_neighbours(stack, sector):
    original = pattern("original", DATA_SECTORS)
    stack.upper.write(0, original)
    stack.upper.flush()
    update = pattern("update", 1)
    stack.upper.write(sector, update)
    stack.upper.flush()
    expected = bytearray(original)
    expected[sector * SECTOR_SIZE : (sector + 1) * SECTOR_SIZE] = update
    # Each sector is read on its own, as its own CRC must match.
    for current in range(DATA_SECTORS):
        start = current * SECTOR_SIZE
        assert stack.upper.read(current) == bytes(expected[start : start + SECTOR_SIZE])


def test_write_across_a_chunk_boundary(stack):
    stack.upper.write(0, pattern("before", 2 * DATA_SECTORS))
    update = pattern("across", 4)
    stack.upper.write(DATA_SECTORS - 2, update)
    assert stack.upper.read(DATA_SECTORS - 2, 4) == update
    before = pattern("before", 2 * DATA_SECTORS)
    assert stack.upper.read(0, DATA_SECTORS - 2) == before[: (DATA_SECTORS - 2) * SECTOR_SIZE]
    assert stack.upper.read(DATA_SECTORS + 2, DATA_SECTORS - 2) == before[
        (DATA_SECTORS + 2) * SECTOR_SIZE :
    ]


def test_last_sector_of_the_device(stack):
    last = stack.sectors - 1
    data = pattern("last", 1)
    stack.upper.write(last, data)
    assert stack.upper.read(last) == data


def test_read_past_the_end_is_short(stack):
    last = stack.sectors - 1
    data = pattern("short", 1)
    stack.upper.write(last, data)
    assert stack.upper.read(last, 2) == data
    assert stack.upper.read(stack.sectors) == b""


def test_write_past_the_end_fails(stack):
    with pytest.raises(OSError):
        stack.upper.write(stack.sectors, pattern("past", 1))


def test_data_survives_recreating_the_device(stack):
    data = pattern("persistent", 3 * DATA_SECTORS + 5)
    stack.upper.write(3, data)
    stack.recreate_upper()
    assert stack.upper.read(3, 3 * DATA_SECTORS + 5) == data


def test_random_writes_match_a_reference_copy(stack):
    """Random sizes and positions over a small area, so that writes overlap a lot."""
    rng = random.Random(20261109)
    area = 32 * DATA_SECTORS
    reference = bytearray(area * SECTOR_SIZE)
    for step in range(1500):
        start = rng.randrange(area)
        count = rng.randint(1, min(3 * DATA_SECTORS, area - start))
        offset = start * SECTOR_SIZE
        if rng.random() < 0.6:
            data = rng.randbytes(count * SECTOR_SIZE)
            stack.upper.write(start, data)
            reference[offset : offset + len(data)] = data
        else:
            expected = bytes(reference[offset : offset + count * SECTOR_SIZE])
            assert stack.upper.read(start, count) == expected, f"step {step}"
    assert stack.upper.read(0, area) == bytes(reference)

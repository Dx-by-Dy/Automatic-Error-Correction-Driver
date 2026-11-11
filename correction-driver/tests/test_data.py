"""Data written through the device reads back unchanged and lands where the layout says."""

import random

import pytest

from harness import (
    CHUNK_SIZE,
    DATA_SECTORS,
    SECTOR_SIZE,
    metadata_sector,
    pattern,
    physical_sector,
    run,
)

ZERO_SECTOR = bytes(SECTOR_SIZE)


def test_capacity_excludes_metadata(stack):
    reported = int(run("blockdev", "--getsz", stack.upper_path).stdout)
    assert reported == stack.lower_sectors // 9 * 8


def test_fresh_device_reads_zeros(stack):
    assert stack.upper.read(0, 64) == bytes(64 * SECTOR_SIZE)


@pytest.mark.parametrize("start", [0, 1, 7, 8, 13], ids=lambda s: f"start{s}")
@pytest.mark.parametrize("sectors", [1, 2, 7, 8, 9, 16, 64, 128, 256, 2048], ids=lambda s: f"{s}s")
def test_roundtrip(stack, start, sectors):
    data = pattern("roundtrip", sectors)
    stack.upper.write(start, data)
    assert stack.upper.read(start, sectors) == data


def test_data_lands_at_the_layout_position(stack):
    data = pattern("layout", 3 * DATA_SECTORS)
    stack.upper.write(0, data)
    for logical in range(3 * DATA_SECTORS):
        expected = data[logical * SECTOR_SIZE:][:SECTOR_SIZE]
        assert stack.lower.read(physical_sector(logical)) == expected, f"sector {logical}"


def test_metadata_is_written_outside_the_data(stack):
    stack.upper.write(0, pattern("metadata", DATA_SECTORS))
    assert stack.lower.read(metadata_sector(0)) != ZERO_SECTOR
    assert stack.lower.read(metadata_sector(DATA_SECTORS)) == ZERO_SECTOR


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
    update = pattern("update", 1)
    stack.upper.write(sector, update)
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

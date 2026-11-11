"""Damage on the lower device is detected, and only where the damage is."""

import errno

import pytest

from harness import CRC_SIZE, DATA_SECTORS, SECTOR_SIZE, metadata_sector, pattern, physical_sector

# A chunk with written neighbours on both sides.
CHUNK = 5
FIRST = CHUNK * DATA_SECTORS


def assert_read_fails(device, sector, count=1):
    with pytest.raises(OSError) as error:
        device.read(sector, count)
    assert error.value.errno == errno.EIO


@pytest.fixture
def written(stack):
    """Three written chunks, returning their expected contents, starting at `FIRST - 8`."""
    data = pattern("written", 3 * DATA_SECTORS)
    stack.upper.write(FIRST - DATA_SECTORS, data)
    return data


def sector_of(data, logical):
    offset = (logical - (FIRST - DATA_SECTORS)) * SECTOR_SIZE
    return data[offset : offset + SECTOR_SIZE]


@pytest.mark.parametrize("in_chunk", range(DATA_SECTORS))
def test_data_corruption_fails_only_that_sector(stack, written, in_chunk):
    bad = FIRST + in_chunk
    stack.lower.flip_bit(physical_sector(bad), byte=100, bit=3)

    assert_read_fails(stack.upper, bad)
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)
    for logical in range(FIRST - DATA_SECTORS, FIRST + 2 * DATA_SECTORS):
        if logical != bad:
            assert stack.upper.read(logical) == sector_of(written, logical), f"sector {logical}"


@pytest.mark.parametrize("position", [(0, 0), (0, 7), (100, 0), (511, 7)], ids=str)
def test_any_bit_of_a_sector_is_covered(stack, written, position):
    byte, bit = position
    stack.lower.flip_bit(physical_sector(FIRST), byte=byte, bit=bit)
    assert_read_fails(stack.upper, FIRST)


@pytest.mark.parametrize("in_chunk", range(DATA_SECTORS))
def test_crc_corruption_fails_only_that_sector(stack, written, in_chunk):
    stack.lower.flip_bit(metadata_sector(FIRST), byte=in_chunk * CRC_SIZE, bit=0)

    assert_read_fails(stack.upper, FIRST + in_chunk)
    for current in range(DATA_SECTORS):
        if current != in_chunk:
            logical = FIRST + current
            assert stack.upper.read(logical) == sector_of(written, logical), f"sector {logical}"


def test_zeroed_metadata_is_detected(stack, written):
    """The scenario of the original tests.py, without damaging the neighbouring sectors."""
    stack.lower.write(metadata_sector(FIRST), bytes(SECTOR_SIZE))
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)
    assert stack.upper.read(FIRST + DATA_SECTORS) == sector_of(written, FIRST + DATA_SECTORS)


def test_unused_metadata_bytes_are_not_checked(stack, written):
    stack.lower.flip_bit(metadata_sector(FIRST), byte=DATA_SECTORS * CRC_SIZE, bit=0)
    assert stack.upper.read(FIRST) == sector_of(written, FIRST)


def test_restoring_the_data_clears_the_error(stack, written):
    target = physical_sector(FIRST)
    stack.lower.flip_bit(target)
    assert_read_fails(stack.upper, FIRST)
    stack.lower.flip_bit(target)
    assert stack.upper.read(FIRST) == sector_of(written, FIRST)


def test_rewriting_a_corrupted_sector_clears_the_error(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST))
    update = pattern("rewritten", 1)
    stack.upper.write(FIRST, update)
    assert stack.upper.read(FIRST) == update


def test_write_to_a_neighbour_does_not_hide_corruption(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST))
    update = pattern("neighbour", 1)
    stack.upper.write(FIRST + 1, update)
    assert stack.upper.read(FIRST + 1) == update
    assert_read_fails(stack.upper, FIRST)


def test_corruption_is_detected_after_recreating_the_device(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST))
    stack.recreate_upper()
    assert_read_fails(stack.upper, FIRST)


@pytest.mark.xfail(strict=True, reason="TODO.md: A zeroed chunk passes the check")
def test_zeroed_chunk_is_detected(stack, written):
    start = physical_sector(FIRST)
    stack.lower.write(start, bytes((DATA_SECTORS + 1) * SECTOR_SIZE))
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)


@pytest.mark.xfail(strict=True, reason="TODO.md: The CRC does not depend on the position")
def test_chunk_copied_elsewhere_is_detected(stack, written):
    source = physical_sector(FIRST)
    target = physical_sector(FIRST + DATA_SECTORS)
    stack.lower.write(target, stack.lower.read(source, DATA_SECTORS + 1))
    assert_read_fails(stack.upper, FIRST + DATA_SECTORS, DATA_SECTORS)

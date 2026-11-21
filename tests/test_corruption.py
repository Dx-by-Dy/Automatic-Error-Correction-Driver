"""Damage on the lower device is detected, and only where the damage is.

The driver keeps the metadata of the regions it used in RAM, so a test that damages metadata makes it
read the metadata again, as it would after a suspend. The metadata has two copies, and a read takes a
CRC from either, so damage to metadata is detected only when it is in both.
"""

import errno
import struct
import time

import pytest

from conftest import OTHER_NAME, UPPER_NAME, device_status, dmsetup_remove, kernel_messages, warned
from harness import (
    CRC_SIZE,
    DATA_SECTORS,
    METADATA_ENTRY_SIZE,
    REGION_SECTORS,
    SALT_OFFSET,
    SALT_SIZE,
    SECTOR_SIZE,
    BlockDevice,
    data_crc,
    format_device,
    metadata_offset,
    metadata_sector,
    metadata_sectors,
    pattern,
    physical_sector,
    region_sector,
    run,
)

# A chunk with written neighbours on both sides, all three in one metadata sector.
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
    stack.upper.flush_settled()
    return data


def copies(stack, logical):
    """The lower sectors of both copies of the metadata sector of a logical sector."""
    return metadata_sectors(logical, stack.lower_sectors)


def sector_of(data, logical):
    offset = (logical - (FIRST - DATA_SECTORS)) * SECTOR_SIZE
    return data[offset : offset + SECTOR_SIZE]


@pytest.mark.parametrize("in_chunk", range(DATA_SECTORS))
def test_data_corruption_fails_only_that_sector(stack, written, in_chunk):
    bad = FIRST + in_chunk
    stack.lower.flip_bit(physical_sector(bad, stack.lower_sectors), byte=100, bit=3)

    assert_read_fails(stack.upper, bad)
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)
    for logical in range(FIRST - DATA_SECTORS, FIRST + 2 * DATA_SECTORS):
        if logical != bad:
            assert stack.upper.read(logical) == sector_of(written, logical), f"sector {logical}"


@pytest.mark.parametrize("position", [(0, 0), (0, 7), (100, 0), (511, 7)], ids=str)
def test_any_bit_of_a_sector_is_covered(stack, written, position):
    byte, bit = position
    stack.lower.flip_bit(physical_sector(FIRST, stack.lower_sectors), byte=byte, bit=bit)
    assert_read_fails(stack.upper, FIRST)


@pytest.mark.parametrize("in_chunk", range(DATA_SECTORS))
def test_crc_corruption_fails_only_that_sector(stack, written, in_chunk):
    for sector in copies(stack, FIRST):
        stack.lower.flip_bit(sector, byte=metadata_offset(FIRST) + in_chunk * CRC_SIZE, bit=0)
    stack.drop_metadata()

    assert_read_fails(stack.upper, FIRST + in_chunk)
    for current in range(DATA_SECTORS):
        if current != in_chunk:
            logical = FIRST + current
            assert stack.upper.read(logical) == sector_of(written, logical), f"sector {logical}"


@pytest.mark.parametrize("copy", [0, 1], ids=["leading", "trailing"])
@pytest.mark.parametrize("in_chunk", [0, DATA_SECTORS - 1], ids=["first sector", "last sector"])
def test_crc_corruption_in_one_copy_is_covered_by_the_other(stack, written, copy, in_chunk):
    stack.lower.flip_bit(copies(stack, FIRST)[copy], byte=metadata_offset(FIRST) + in_chunk * CRC_SIZE, bit=0)
    stack.drop_metadata()
    assert stack.upper.read(FIRST - DATA_SECTORS, 3 * DATA_SECTORS) == written


def test_zeroed_metadata_is_detected(stack, written):
    """The scenario of the original tests.py, without damaging the entries of the neighbouring chunks."""
    for sector in copies(stack, FIRST):
        stack.lower.patch(sector, metadata_offset(FIRST), bytes(METADATA_ENTRY_SIZE))
    stack.drop_metadata()
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)
    assert stack.upper.read(FIRST + DATA_SECTORS) == sector_of(written, FIRST + DATA_SECTORS)


def test_a_zeroed_metadata_sector_fails_every_chunk_it_covers(stack, written):
    for sector in copies(stack, FIRST):
        stack.lower.write(sector, bytes(SECTOR_SIZE))
    stack.drop_metadata()
    for chunk_start in (FIRST - DATA_SECTORS, FIRST, FIRST + DATA_SECTORS):
        assert_read_fails(stack.upper, chunk_start, DATA_SECTORS)


@pytest.mark.parametrize("copy", [0, 1], ids=["leading", "trailing"])
def test_a_zeroed_metadata_sector_in_one_copy_fails_nothing(stack, written, copy):
    stack.lower.write(copies(stack, FIRST)[copy], bytes(SECTOR_SIZE))
    stack.drop_metadata()
    assert stack.upper.read(FIRST - DATA_SECTORS, 3 * DATA_SECTORS) == written


def test_the_entry_of_a_neighbour_does_not_cover_this_chunk(stack, written):
    neighbour = FIRST + DATA_SECTORS
    for sector in copies(stack, neighbour):
        stack.lower.flip_bit(sector, byte=metadata_offset(neighbour), bit=0)
    stack.drop_metadata()
    assert stack.upper.read(FIRST, DATA_SECTORS) == written[DATA_SECTORS * SECTOR_SIZE :][: DATA_SECTORS * SECTOR_SIZE]
    assert_read_fails(stack.upper, neighbour)


def test_restoring_the_data_clears_the_error(stack, written):
    target = physical_sector(FIRST, stack.lower_sectors)
    stack.lower.flip_bit(target)
    assert_read_fails(stack.upper, FIRST)
    stack.lower.flip_bit(target)
    assert stack.upper.read(FIRST) == sector_of(written, FIRST)


def test_rewriting_a_corrupted_sector_clears_the_error(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST, stack.lower_sectors))
    update = pattern("rewritten", 1)
    stack.upper.write(FIRST, update)
    stack.upper.flush()
    assert stack.upper.read(FIRST) == update


def settle_counts(stack):
    status = stack.status()
    return status["settle_reads"], status["settle_mismatches"]


@pytest.mark.parametrize("copy", [0, 1], ids=["leading", "trailing"])
def test_a_sector_whose_copies_differ_is_read_before_it_is_written(stack, written, copy):
    """As after a crash between the copies: the data matches one of them, and a write of it reads it first.

    With the other copy damaged, the data matches the trailing copy or the leading one; the read
    finds which, and after the write and its flush both copies hold the new CRC.
    """
    stack.lower.flip_bit(copies(stack, FIRST)[copy], byte=metadata_offset(FIRST), bit=0)
    stack.drop_metadata()
    before = settle_counts(stack)
    update = pattern("update", 1)
    stack.upper.write(FIRST, update)
    stack.upper.flush_settled()
    assert settle_counts(stack) == (before[0] + 1, before[1])
    lead, trail = (stack.lower.read(sector) for sector in copies(stack, FIRST))
    assert lead == trail
    assert stack.upper.read(FIRST) == update


def test_only_the_sectors_written_are_read_first(stack, written):
    """Copies that differ in another sector of the chunk are left alone by a write of this one.

    Neither read first, nor put into the trailing copy after the flush: the sector would then have the
    damaged CRC in both copies.
    """
    stack.lower.flip_bit(copies(stack, FIRST)[0], byte=metadata_offset(FIRST) + 5 * CRC_SIZE, bit=0)
    stack.drop_metadata()
    before = settle_counts(stack)
    update = pattern("update", 1)
    stack.upper.write(FIRST, update)
    stack.upper.flush_settled()
    assert settle_counts(stack) == before
    stack.drop_metadata()
    expected = bytearray(written[DATA_SECTORS * SECTOR_SIZE :][: DATA_SECTORS * SECTOR_SIZE])
    expected[:SECTOR_SIZE] = update
    assert stack.upper.read(FIRST, DATA_SECTORS) == expected


def test_a_sector_matching_neither_copy_is_counted_before_it_is_written(stack, written):
    """Damaged data with copies that differ: the read before the write counts it, and the write goes on."""
    stack.lower.flip_bit(copies(stack, FIRST)[0], byte=metadata_offset(FIRST), bit=0)
    stack.lower.flip_bit(physical_sector(FIRST, stack.lower_sectors), byte=100, bit=3)
    stack.drop_metadata()
    before = settle_counts(stack)
    update = pattern("update", 1)
    stack.upper.write(FIRST, update)
    stack.upper.flush_settled()
    assert settle_counts(stack) == (before[0] + 1, before[1] + 1)
    assert stack.upper.read(FIRST) == update


def test_write_to_a_neighbour_does_not_hide_corruption(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST, stack.lower_sectors))
    update = pattern("neighbour", 1)
    stack.upper.write(FIRST + 1, update)
    stack.upper.flush()
    assert stack.upper.read(FIRST + 1) == update
    assert_read_fails(stack.upper, FIRST)


def test_corruption_is_detected_after_recreating_the_device(stack, written):
    stack.lower.flip_bit(physical_sector(FIRST, stack.lower_sectors))
    stack.recreate_upper()
    assert_read_fails(stack.upper, FIRST)


def salt(stack):
    """The salt of the device, from the superblock of group 0."""
    return stack.lower.read(0)[SALT_OFFSET : SALT_OFFSET + SALT_SIZE]


def entry(stack, sector, logical):
    """The CRCs of the chunk of a logical sector in a copy of its metadata sector on the lower device."""
    offset = metadata_offset(logical)
    return list(struct.unpack("<8Q", stack.lower.read(sector)[offset : offset + METADATA_ENTRY_SIZE]))


def test_the_crcs_on_the_device_are_those_of_the_model(stack, written):
    """Each CRC runs over the salt, the logical sector as le64 and the data, as data_crc in harness.py."""
    for chunk_start in (FIRST - DATA_SECTORS, FIRST, FIRST + DATA_SECTORS):
        expected = [
            data_crc(salt(stack), logical, sector_of(written, logical))
            for logical in range(chunk_start, chunk_start + DATA_SECTORS)
        ]
        for sector in copies(stack, chunk_start):
            assert entry(stack, sector, chunk_start) == expected, f"chunk at {chunk_start}, lower sector {sector}"


def test_zeroed_chunk_is_detected(stack, written):
    stack.lower.write(physical_sector(FIRST, stack.lower_sectors), bytes(DATA_SECTORS * SECTOR_SIZE))
    for sector in copies(stack, FIRST):
        stack.lower.patch(sector, metadata_offset(FIRST), bytes(METADATA_ENTRY_SIZE))
    stack.drop_metadata()
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)


def test_chunk_copied_elsewhere_is_detected(stack, written):
    target = FIRST + DATA_SECTORS
    stack.lower.write(physical_sector(target, stack.lower_sectors), stack.lower.read(physical_sector(FIRST, stack.lower_sectors), DATA_SECTORS))
    offset = metadata_offset(FIRST)
    entry = stack.lower.read(metadata_sector(FIRST, stack.lower_sectors))[offset : offset + METADATA_ENTRY_SIZE]
    for sector in copies(stack, target):
        stack.lower.patch(sector, metadata_offset(target), entry)
    stack.drop_metadata()
    assert_read_fails(stack.upper, FIRST + DATA_SECTORS, DATA_SECTORS)


def test_sectors_swapped_inside_a_chunk_with_their_crcs_are_detected(stack, written):
    """The seed takes the logical sector, not only the chunk."""
    first, second = (physical_sector(FIRST + i, stack.lower_sectors) for i in (0, 1))
    data = [stack.lower.read(first), stack.lower.read(second)]
    stack.lower.write(first, data[1])
    stack.lower.write(second, data[0])
    for sector in copies(stack, FIRST):
        crcs = entry(stack, sector, FIRST)
        crcs[0], crcs[1] = crcs[1], crcs[0]
        stack.lower.patch(sector, metadata_offset(FIRST), struct.pack("<8Q", *crcs))
    stack.drop_metadata()
    assert_read_fails(stack.upper, FIRST)
    assert_read_fails(stack.upper, FIRST + 1)
    assert stack.upper.read(FIRST + 2) == sector_of(written, FIRST + 2)


def test_a_zeroed_region_with_its_chunks_written_is_detected(stack):
    """A region lost or trimmed whole, its leading metadata with it, while the bitmap says its chunks were written.

    The trailing copy of its metadata, in the next region, is left; the zeros match neither copy."""
    start = region_sector(1, stack.lower_sectors)
    data = pattern("region", 3 * DATA_SECTORS)
    stack.upper.write(start, data)
    stack.upper.flush_settled()
    region = stack.lower_layout.region_start(1)
    stack.lower.write(region, bytes(REGION_SECTORS * SECTOR_SIZE))
    stack.drop_metadata()
    for chunk_start in range(start, start + 3 * DATA_SECTORS, DATA_SECTORS):
        assert_read_fails(stack.upper, chunk_start, DATA_SECTORS)


def test_a_region_shifted_whole_with_its_metadata_is_detected(stack):
    """As a table off by a whole region, or a misdirected write of a region: data and leading metadata
    of region 0 over region 1, where the same chunk was written with other data."""
    index = CHUNK
    starts = [region_sector(region, stack.lower_sectors) + index * DATA_SECTORS for region in (0, 1)]
    for start in starts:
        stack.upper.write(start, pattern(start, DATA_SECTORS))
    stack.upper.flush_settled()
    device = stack.lower_layout
    assert device.trail_region(1) != 0, "the trailing copy of region 1 must stay out of the shift"
    stack.lower.write(device.region_start(1), stack.lower.read(device.region_start(0), REGION_SECTORS))
    stack.drop_metadata()
    assert_read_fails(stack.upper, starts[1], DATA_SECTORS)


def reformat(stack):
    """Formats the lower device again, a new salt and UUID, and puts the driver back on it."""
    stack.upper.close()
    dmsetup_remove(UPPER_NAME)
    format_device(stack.lower_path, force=True)
    run("dmsetup", "create", UPPER_NAME, stdin=stack.table)
    stack.upper = BlockDevice(stack.upper_path)


def test_a_chunk_from_another_device_is_detected(stack):
    """The same data in the same place with its CRCs, from a device of another salt: as a disk of an array
    put in the place of another one."""
    data = pattern("same", DATA_SECTORS)
    stack.upper.write(FIRST, data)
    stack.upper.flush_settled()
    old_salt = salt(stack)
    old = [stack.lower.read(sector) for sector in copies(stack, FIRST)]

    reformat(stack)
    assert salt(stack) != old_salt
    stack.upper.write(FIRST, data)
    stack.upper.flush_settled()
    assert stack.upper.read(FIRST, DATA_SECTORS) == data, "the positive control: the new device reads"
    for sector, contents in zip(copies(stack, FIRST), old):
        stack.lower.write(sector, contents)
    stack.drop_metadata()
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)


def test_every_damaged_sector_of_a_read_is_counted_and_logged(stack, written):
    """A read checks all its sectors, past the first damaged one: crc_mismatches counts the damaged
    sectors, and the log names the device as dmsetup does, the read and its first damaged sector."""
    for in_chunk in (1, 4, 6):
        stack.lower.flip_bit(physical_sector(FIRST + in_chunk, stack.lower_sectors), byte=7, bit=1)
    mismatches = device_status()["crc_mismatches"]
    assert_read_fails(stack.upper, FIRST, DATA_SECTORS)
    assert device_status()["crc_mismatches"] == mismatches + 3

    text = (
        f"dcorr {UPPER_NAME}: CRC mismatch in 3 of {DATA_SECTORS} sectors read at sector {FIRST}, "
        f"the first at sector {FIRST + 1}"
    )
    assert warned(lambda: assert_read_fails(stack.upper, FIRST, DATA_SECTORS), text)


# DEFAULT_RATELIMIT_BURST of the kernel: messages of one place in the code in 5 s.
RATELIMIT_BURST = 10


def test_a_flood_of_mismatches_is_counted_whole_and_logged_rate_limited(stack):
    chunks = 8 * RATELIMIT_BURST
    stack.upper.write(0, pattern("flood", chunks * DATA_SECTORS))
    stack.upper.flush_settled()
    for chunk in range(chunks):
        stack.lower.flip_bit(physical_sector(chunk * DATA_SECTORS, stack.lower_sectors), byte=0, bit=0)
    mismatches = device_status()["crc_mismatches"]

    with kernel_messages() as messages:
        for chunk in range(chunks):
            assert_read_fails(stack.upper, chunk * DATA_SECTORS, DATA_SECTORS)
    assert device_status()["crc_mismatches"] == mismatches + chunks
    logged = [message for message in messages if "CRC mismatch" in message]
    assert len(logged) <= 2 * RATELIMIT_BURST, f"{len(logged)} messages for {chunks} damaged reads"


# DEFAULT_RATELIMIT_INTERVAL of the kernel, with a margin: a new interval starts after it.
RATELIMIT_SECONDS = 5.5


@pytest.mark.parametrize(
    "flood",
    [
        "none",
        pytest.param(
            "on the other device",
            marks=pytest.mark.xfail(strict=True, reason="The rate limit of a message is shared by all devices"),
        ),
    ],
)
def test_a_flood_on_one_device_does_not_hide_the_errors_of_another(stack, other_stack, flood):
    """The messages are rate limited for each place in the code, and the state is static, so a failing device
    that floods the log hides the first error of a healthy one for the rest of the interval. The name of the
    device is in each message so that the user can tell them apart; each device needs a limit of its own.

    "none" is the positive control: with no flood the mismatch of the second device is logged.
    """
    chunks = 2 * RATELIMIT_BURST
    stack.upper.write(0, pattern("flood", chunks * DATA_SECTORS))
    stack.upper.flush_settled()
    for chunk in range(chunks):
        stack.lower.flip_bit(physical_sector(chunk * DATA_SECTORS, stack.lower_sectors), byte=0, bit=0)
    other_stack.upper.write(0, pattern("other", DATA_SECTORS))
    other_stack.upper.flush_settled()
    other_stack.lower.flip_bit(physical_sector(0, other_stack.lower_sectors), byte=0, bit=0)

    time.sleep(RATELIMIT_SECONDS)
    with kernel_messages() as messages:
        if flood != "none":
            for chunk in range(chunks):
                assert_read_fails(stack.upper, chunk * DATA_SECTORS, DATA_SECTORS)
        assert_read_fails(other_stack.upper, 0, DATA_SECTORS)
    assert any(f"dcorr {OTHER_NAME}: CRC mismatch" in message for message in messages), messages

"""The superblock: dcorrsetup writes it, the driver checks it, and the layout follows from it.

The header is built here by hand as well, with the layout and crc64_be of harness.py, so that the
driver is seen to take a header made apart from dcorrsetup, and to refuse each field that is wrong.
"""

import os
import struct

import pytest

from conftest import LOWER_NAME, TEST_DISK, UPPER_NAME, dmsetup_remove, kernel_messages, make_lower
from harness import (
    DATA_SECTORS,
    HEADER_SECTORS,
    REGION_DATA_SECTORS,
    TOOL,
    BlockDevice,
    capacity,
    crc64_be,
    format_device,
    layout,
    pattern,
    physical_sector,
    run,
    table_line,
)

LOWER_MIB = 16
# Offsets and formats of the fields of struct dcorr_superblock in src/dcorr-format.h.
FIELDS = {
    "version": (8, "<I"),
    "copy": (12, "<I"),
    "generation": (16, "<Q"),
    "flags": (24, "<Q"),
    "salt": (48, "16s"),
    "lower_sectors": (64, "<Q"),
    "capacity": (72, "<Q"),
    "chunk_sectors": (80, "<I"),
    "region_chunks": (84, "<I"),
    "metadata_entry_bytes": (88, "<I"),
    "bitmap_block_bits": (92, "<I"),
    "area_sectors": (96, "<Q"),
    "regions": (104, "<Q"),
    "middle_region": (112, "<Q"),
    "bitmap_blocks": (120, "<Q"),
}
CRC_OFFSET = 128


def header_crc(header):
    return crc64_be(0, bytes(header[:CRC_OFFSET]) + bytes(8) + bytes(header[CRC_OFFSET + 8 :]))


def get_field(header, name):
    offset, form = FIELDS[name]
    return struct.unpack_from(form, header, offset)[0]


def set_field(header, name, value):
    offset, form = FIELDS[name]
    struct.pack_into(form, header, offset, value)


def create(path, sectors, length=None):
    table = f"0 {capacity(sectors) if length is None else length} dcorr {path}\n"
    return run("dmsetup", "create", UPPER_NAME, stdin=table, check=False)


def dump(path, check=True):
    result = run(TOOL, "dump", path, check=check)
    return dict(line.split("=", 1) for line in result.stdout.splitlines()), result


class Lower:
    """A zeroed lower device, formatted unless told otherwise, and its two headers."""

    def __init__(self, sectors=LOWER_MIB * 2048, formatted=True):
        self.sectors = sectors
        self.path = make_lower(sectors)
        if formatted:
            format_device(self.path)

    def header(self, copy):
        device = BlockDevice(self.path)
        try:
            return bytearray(device.read(layout(self.sectors).copy_start(copy), HEADER_SECTORS))
        finally:
            device.close()

    def write_header(self, copy, header, fix_crc=True):
        if fix_crc:
            struct.pack_into("<Q", header, CRC_OFFSET, header_crc(header))
        device = BlockDevice(self.path)
        try:
            device.write(layout(self.sectors).copy_start(copy), bytes(header))
        finally:
            device.close()

    def change(self, which, **fields):
        header = self.header(which)
        for name, value in fields.items():
            set_field(header, name, value)
        self.write_header(which, header)

    def damage(self, copy):
        self.write_header(copy, bytearray(HEADER_SECTORS * 512), fix_crc=False)


@pytest.fixture
def lowers():
    """Makes lower devices; removes them and the driver on top afterwards."""

    def make(*args, **kwargs):
        return Lower(*args, **kwargs)

    yield make
    dmsetup_remove(UPPER_NAME)
    dmsetup_remove(LOWER_NAME)


def created(lower, **kwargs):
    """Puts the driver on a lower device; returns whether it was taken and the kernel messages."""
    with kernel_messages() as messages:
        result = create(lower.path, lower.sectors, **kwargs)
    return result.returncode == 0, messages


def test_the_header_built_by_the_tests_is_taken(lowers):
    """The positive control of the tests below: a header rewritten with the CRC of harness.py works."""
    assert crc64_be(0, b"123456789") == 0x6C40DF5F0B497347, "not CRC-64/ECMA-182"
    lower = lowers()
    for copy in range(2):
        header = lower.header(copy)
        assert struct.unpack_from("<Q", header, CRC_OFFSET)[0] == header_crc(header), "dcorrsetup computes another CRC"
        set_field(header, "generation", 1)
        lower.write_header(copy, header)
    taken, messages = created(lower)
    assert taken, messages


def test_a_device_without_a_superblock_is_refused(lowers):
    lower = lowers(formatted=False)
    taken, messages = created(lower)
    assert not taken
    assert any("no valid superblock: copy 0: no magic, copy 1: no magic" in message for message in messages)


@pytest.mark.parametrize(
    "fields, reason",
    [
        ({"version": 2}, "unsupported version"),
        ({"flags": 1}, "unknown flags"),
        ({"chunk_sectors": 16}, "parameters other than those of version 1"),
        ({"region_chunks": 2048}, "parameters other than those of version 1"),
        ({"bitmap_block_bits": 32768}, "parameters other than those of version 1"),
        ({"lower_sectors": LOWER_MIB * 2048 + 8}, "formatted for a device of another size"),
        ({"capacity": capacity(LOWER_MIB * 2048) - 8}, "a layout other than the one computed"),
        ({"regions": layout(LOWER_MIB * 2048).regions + 1}, "a layout other than the one computed"),
        ({"middle_region": 1}, "a layout other than the one computed"),
        ({"area_sectors": 4096}, "a layout other than the one computed"),
    ],
    ids=lambda value: next(iter(value)) if isinstance(value, dict) else None,
)
def test_a_wrong_field_in_both_copies_is_refused(lowers, fields, reason):
    lower = lowers()
    for copy in range(2):
        lower.change(copy, **fields)
    taken, messages = created(lower)
    assert not taken
    assert any(f"copy 0: {reason}, copy 1: {reason}" in message for message in messages), messages


def test_a_copy_with_the_number_of_the_other_is_refused(lowers):
    """A copy found where the other belongs, as by a misdirected write, is not taken for it."""
    lower = lowers()
    lower.change(0, copy=1)
    lower.change(1, copy=0)
    taken, messages = created(lower)
    assert not taken
    assert any("copy 0: the number of another copy, copy 1: the number of another copy" in m for m in messages)


def test_a_damaged_crc_is_refused(lowers):
    lower = lowers()
    for copy in range(2):
        header = lower.header(copy)
        header[200] ^= 1  # in the reserved bytes, which only the CRC covers
        lower.write_header(copy, header, fix_crc=False)
    taken, messages = created(lower)
    assert not taken
    assert any("copy 0: CRC mismatch, copy 1: CRC mismatch" in message for message in messages)


@pytest.mark.parametrize("copy", [0, 1])
def test_one_damaged_copy_is_covered_by_the_other(lowers, copy):
    """The device comes up from the other copy, warns, and holds the data written before."""
    lower = lowers()
    assert create(lower.path, lower.sectors).returncode == 0
    data = pattern("before", DATA_SECTORS)
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    try:
        upper.write(REGION_DATA_SECTORS * layout(lower.sectors).middle_region, data)
        upper.flush_settled()
    finally:
        upper.close()
    dmsetup_remove(UPPER_NAME)

    lower.damage(copy)
    taken, messages = created(lower)
    assert taken, messages
    assert any(f"copy {copy} of the superblock is not valid: no magic" in message for message in messages)
    assert any(f"superblock copy {1 - copy}, generation 1" in message for message in messages)
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    try:
        assert upper.read(REGION_DATA_SECTORS * layout(lower.sectors).middle_region, DATA_SECTORS) == data
    finally:
        upper.close()


def test_both_damaged_copies_are_refused(lowers):
    lower = lowers()
    lower.damage(0)
    lower.damage(1)
    taken, _ = created(lower)
    assert not taken


@pytest.mark.parametrize("newer", [0, 1])
def test_the_copy_with_the_larger_generation_is_taken(lowers, newer):
    lower = lowers()
    lower.change(newer, generation=2)
    taken, messages = created(lower)
    assert taken, messages
    assert any(f"superblock copy {newer}, generation 2" in message for message in messages), messages


def test_copies_that_differ_in_the_same_generation_warn(lowers):
    lower = lowers()
    lower.change(1, salt=os.urandom(16))
    taken, messages = created(lower)
    assert taken, messages
    assert any("differ in the same generation, taking copy 0" in message for message in messages)
    assert any("superblock copy 0, generation 1" in message for message in messages)


def test_copies_that_agree_do_not_warn(lowers):
    """The control of the test above."""
    lower = lowers()
    taken, messages = created(lower)
    assert taken, messages
    assert not [message for message in messages if "superblock" in message and "WARN" in message]


def test_a_device_of_another_size_is_refused(lowers):
    """The size of the device below must be the one it was formatted for."""
    lower = lowers()
    dmsetup_remove(LOWER_NAME)
    run("dmsetup", "create", LOWER_NAME, stdin=f"0 {lower.sectors + 2048} linear {TEST_DISK} 0\n")
    taken, messages = created(lower, length=capacity(lower.sectors))
    assert not taken
    assert any("copy 0: formatted for a device of another size" in message for message in messages), messages


def smallest_device():
    sectors = 12000
    while not layout(sectors):
        sectors += DATA_SECTORS
    return sectors


@pytest.mark.parametrize("change", [-DATA_SECTORS, 0], ids=["too small", "smallest"])
def test_the_smallest_device(lowers, change):
    """Two regions, the second with one chunk; one chunk less, and neither the tool nor the driver takes it."""
    sectors = smallest_device() + change
    lower = lowers(sectors, formatted=False)
    result = run(TOOL, "format", lower.path, check=False)
    if change:
        assert result.returncode != 0 and "too small" in result.stderr
        taken, messages = created(lower, length=8)
        assert not taken
        assert any("The device below is too small" in message for message in messages), messages
    else:
        assert result.returncode == 0, result.stderr
        assert capacity(sectors) == REGION_DATA_SECTORS + DATA_SECTORS
        taken, messages = created(lower)
        assert taken, messages


@pytest.mark.parametrize(
    "sectors", [9 * 2048, LOWER_MIB * 2048, LOWER_MIB * 2048 + 300, 100 * 2048], ids=lambda s: f"{s} sectors"
)
def test_dcorrsetup_gives_the_layout_of_the_tests(lowers, sectors):
    lower = lowers(sectors)
    fields, _ = dump(lower.path)
    expected = layout(sectors)
    assert fields["copy0"] == fields["copy1"] == "valid"
    assert int(fields["copy1_start"]) == expected.copy_start(1)
    for name in ("lower_sectors", "area_sectors", "capacity", "regions", "middle_region", "bitmap_blocks"):
        assert int(fields[name]) == getattr(expected, name), name
    assert table_line(lower.path) == f"0 {expected.capacity} dcorr {lower.path}\n"
    taken, messages = created(lower)
    assert taken, messages


def test_every_region_lies_where_the_layout_says(lowers):
    """A chunk at the start and at the end of each region lands where harness.py puts it.

    Copy 1 of the superblock lies between two regions, so this covers both sides of it.
    """
    lower = lowers()
    expected = layout(lower.sectors)
    assert expected.middle_region not in (0, expected.regions)
    assert create(lower.path, lower.sectors).returncode == 0
    starts = []
    for region in range(expected.regions):
        first = region * REGION_DATA_SECTORS
        last = min(first + REGION_DATA_SECTORS, expected.capacity) - DATA_SECTORS
        starts += [first, last]
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    below = BlockDevice(lower.path)
    try:
        for start in starts:
            upper.write(start, pattern(start, DATA_SECTORS))
        upper.flush_settled()
        for start in starts:
            assert below.read(physical_sector(start, lower.sectors), DATA_SECTORS) == pattern(start, DATA_SECTORS), start
    finally:
        upper.close()
        below.close()


def test_a_large_device_with_a_larger_area(tmp_path):
    """On a sparse file of 40 GiB the bitmap needs more than 1 MiB, so the area grows to 2 MiB.

    Only the areas and the chunks written take space in the file.
    """
    image = tmp_path / "large.img"
    with open(image, "wb") as file:
        file.truncate(40 << 30)
    loop = run("losetup", "--find", "--show", str(image)).stdout.strip()
    try:
        sectors = int(run("blockdev", "--getsz", loop).stdout)
        expected = layout(sectors)
        assert expected.area_sectors == 2 * 2048 and expected.bitmap_blocks > 255
        format_device(loop)
        fields, _ = dump(loop)
        for name in ("area_sectors", "capacity", "regions", "middle_region", "bitmap_blocks"):
            assert int(fields[name]) == getattr(expected, name), name
        run("dmsetup", "create", UPPER_NAME, stdin=table_line(loop))
        upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
        below = BlockDevice(loop)
        starts = [0, expected.middle_region * REGION_DATA_SECTORS, expected.capacity - DATA_SECTORS]
        try:
            for start in starts:
                upper.write(start, pattern(start, DATA_SECTORS))
            upper.flush_settled()
            for start in starts:
                assert below.read(physical_sector(start, sectors), DATA_SECTORS) == pattern(start, DATA_SECTORS)
        finally:
            upper.close()
            below.close()
    finally:
        dmsetup_remove(UPPER_NAME)
        run("losetup", "--detach", loop, check=False)


def test_format_keeps_a_valid_superblock_without_force(lowers):
    lower = lowers()
    before, _ = dump(lower.path)
    result = run(TOOL, "format", lower.path, check=False)
    assert result.returncode != 0 and "--force" in result.stderr
    assert dump(lower.path)[0]["uuid"] == before["uuid"]
    format_device(lower.path, force=True)
    assert dump(lower.path)[0]["uuid"] != before["uuid"]


def test_format_refuses_a_device_in_use(lowers):
    lower = lowers()
    assert create(lower.path, lower.sectors).returncode == 0
    result = run(TOOL, "format", "--force", lower.path, check=False)
    assert result.returncode != 0 and "in use" in result.stderr


def test_dump_of_a_device_without_a_superblock_fails(lowers):
    lower = lowers(formatted=False)
    fields, result = dump(lower.path, check=False)
    assert result.returncode != 0
    assert fields["copy0"] == fields["copy1"] == "no magic"

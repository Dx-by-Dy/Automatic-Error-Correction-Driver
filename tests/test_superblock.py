"""The superblock: dcorrsetup writes it into the header of every group, the driver checks the copies of
groups 0 and 1, and the layout follows from it.

The superblock is built here by hand as well, with the layout and crc64_be of harness.py, so that the
driver is seen to take one made apart from dcorrsetup, and to refuse each field that is wrong.
"""

import os
import struct

import pytest

from conftest import LOWER_NAME, TEST_DISK, UPPER_NAME, dmsetup_remove, kernel_messages, make_lower
from harness import (
    BITMAP_BLOCK_SECTORS,
    BITMAP_BLOCK_SIZE,
    BITMAP_HEADER_SIZE,
    COLUMN_SLOTS_PER_REGION,
    DATA_COLUMNS,
    DATA_SECTORS,
    DEFAULT_GROUP_SECTORS,
    GROUP_HEADER_SECTORS,
    GROUP_SECTORS,
    GROUP_SIZES,
    REGION_CAPACITY,
    REGION_CHUNKS,
    REGION_SECTORS,
    SUPERBLOCK_SECTORS,
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

LOWER_MIB = 32  # two groups of 16 MiB
# Offsets and formats of the fields of struct dcorr_superblock in src/dcorr-format.h.
FIELDS = {
    "version": (8, "<I"),
    "group": (12, "<I"),
    "generation": (16, "<Q"),
    "flags": (24, "<Q"),
    "uuid": (32, "16s"),
    "salt": (48, "16s"),
    "lower_sectors": (64, "<Q"),
    "capacity": (72, "<Q"),
    "chunk_sectors": (80, "<I"),
    "region_chunks": (84, "<I"),
    "metadata_entry_bytes": (88, "<I"),
    "bitmap_block_bits": (92, "<I"),
    "columns": (96, "<I"),
    "parity_columns": (100, "<I"),
    "header_sectors": (104, "<Q"),
    "group_sectors": (112, "<Q"),
    "groups": (120, "<Q"),
    "group_regions": (128, "<Q"),
    "last_group_regions": (136, "<Q"),
    "bitmap_blocks": (144, "<Q"),
}
CRC_OFFSET = 152
# The layout fields that dump prints and harness.py computes.
LAYOUT_FIELDS = ("lower_sectors", "group_sectors", "groups", "group_regions", "last_group_regions", "capacity", "bitmap_blocks")
NO_GROUP_1 = "no valid copy at the start of group 1 for any size of a group"


def superblock_crc(superblock):
    return crc64_be(0, bytes(superblock[:CRC_OFFSET]) + bytes(8) + bytes(superblock[CRC_OFFSET + 8 :]))


def bitmap_block_crc(block, salt):
    """The CRC of a block of the bitmap: over the salt of the device, then over the block with crc zeroed."""
    return crc64_be(crc64_be(0, salt), bytes(8) + bytes(block[8:]))


def get_field(superblock, name):
    offset, form = FIELDS[name]
    return struct.unpack_from(form, superblock, offset)[0]


def set_field(superblock, name, value):
    offset, form = FIELDS[name]
    struct.pack_into(form, superblock, offset, value)


def create(path, sectors, length=None, group_sectors=GROUP_SECTORS):
    table = f"0 {capacity(sectors, group_sectors) if length is None else length} dcorr {path}\n"
    return run("dmsetup", "create", UPPER_NAME, stdin=table, check=False)


def dump(path, check=True):
    result = run(TOOL, "dump", path, check=check)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line), result


class Lower:
    """A zeroed lower device, formatted unless told otherwise, and the superblocks of its groups."""

    def __init__(self, sectors=LOWER_MIB * 2048, formatted=True, group_sectors=GROUP_SECTORS):
        self.sectors = sectors
        self.group_sectors = group_sectors
        self.path = make_lower(sectors)
        if formatted:
            format_device(self.path, group_sectors=group_sectors)

    @property
    def layout(self):
        return layout(self.sectors, self.group_sectors)

    def read(self, sector, count):
        device = BlockDevice(self.path)
        try:
            return bytearray(device.read(sector, count))
        finally:
            device.close()

    def superblock(self, group):
        return self.read(self.layout.group_start(group), SUPERBLOCK_SECTORS)

    def write_superblock(self, group, superblock, fix_crc=True):
        if fix_crc:
            struct.pack_into("<Q", superblock, CRC_OFFSET, superblock_crc(superblock))
        device = BlockDevice(self.path)
        try:
            device.write(self.layout.group_start(group), bytes(superblock))
        finally:
            device.close()

    def change(self, which, **fields):
        """Changes fields of the superblock of a group; not named group, which is a field."""
        superblock = self.superblock(which)
        for name, value in fields.items():
            set_field(superblock, name, value)
        self.write_superblock(which, superblock)

    def damage(self, group):
        self.write_superblock(group, bytearray(SUPERBLOCK_SECTORS * 512), fix_crc=False)


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
    kwargs.setdefault("group_sectors", lower.group_sectors)
    with kernel_messages() as messages:
        result = create(lower.path, lower.sectors, **kwargs)
    return result.returncode == 0, messages


def logged(messages, text):
    return any(text in message for message in messages)


def write_and_flush(path, writes):
    upper = BlockDevice(path)
    try:
        for start, data in writes:
            upper.write(start, data)
        upper.flush_settled()
    finally:
        upper.close()


def read_back(path, writes):
    upper = BlockDevice(path)
    try:
        for start, data in writes:
            assert upper.read(start, len(data) // 512) == data, f"sector {start}"
    finally:
        upper.close()


def test_the_superblock_built_by_the_tests_is_taken(lowers):
    """The positive control of the tests below: superblocks rewritten with the CRC of harness.py work."""
    assert crc64_be(0, b"123456789") == 0x6C40DF5F0B497347, "not CRC-64/ECMA-182"
    lower = lowers()
    for group in range(2):
        superblock = lower.superblock(group)
        assert get_field(superblock, "group") == group
        assert struct.unpack_from("<Q", superblock, CRC_OFFSET)[0] == superblock_crc(superblock), "another CRC"
        set_field(superblock, "generation", 1)
        lower.write_superblock(group, superblock)
    taken, messages = created(lower)
    assert taken, messages


def test_a_device_without_a_superblock_is_refused(lowers):
    lower = lowers(formatted=False)
    taken, messages = created(lower)
    assert not taken
    assert logged(messages, f"no valid superblock: group 0: no magic, group 1: {NO_GROUP_1}"), messages


WRONG_FIELDS = [
    ({"version": 2}, "unsupported version"),
    ({"flags": 1}, "unknown flags"),
    ({"chunk_sectors": 16}, "parameters other than those of version 1"),
    ({"region_chunks": 2048}, "parameters other than those of version 1"),
    ({"bitmap_block_bits": 32768}, "parameters other than those of version 1"),
    ({"columns": 16}, "parameters other than those of version 1"),
    ({"parity_columns": 3}, "parameters other than those of version 1"),
    ({"header_sectors": 4096}, "parameters other than those of version 1"),
    ({"group_sectors": 24 * 2048}, "a size of a group not in the list"),
    ({"lower_sectors": LOWER_MIB * 2048 + 8}, "formatted for a device of another size"),
    ({"capacity": capacity(LOWER_MIB * 2048) - 8}, "a layout other than the one computed"),
    ({"groups": 3}, "a layout other than the one computed"),
    ({"group_regions": 4}, "a layout other than the one computed"),
    ({"last_group_regions": 2}, "a layout other than the one computed"),
    ({"bitmap_blocks": 2}, "a layout other than the one computed"),
]


def field_id(value):
    return next(iter(value)) if isinstance(value, dict) else None


@pytest.mark.parametrize("fields, reason", WRONG_FIELDS, ids=field_id)
def test_a_wrong_field_in_both_copies_is_refused(lowers, fields, reason):
    lower = lowers()
    for group in range(2):
        lower.change(group, **fields)
    taken, messages = created(lower)
    assert not taken
    assert logged(messages, f"group 0: {reason}, group 1: "), messages


@pytest.mark.parametrize(
    "fields, reason",
    WRONG_FIELDS
    + [
        ({"group": 2}, "the number of another group"),
        ({"group_sectors": 32 * 2048}, "a size of a group other than the one of its place"),
    ],
    ids=field_id,
)
def test_a_wrong_field_in_group_1_is_seen(lowers, fields, reason):
    """The copy of group 1 is checked as that of group 0 is, and the device comes up from group 0."""
    lower = lowers()
    lower.change(1, **fields)
    taken, messages = created(lower)
    assert taken, messages
    assert logged(messages, f"the superblock of group 1 is not valid: {reason}"), messages


def test_a_group_size_with_too_few_groups_is_refused(lowers):
    """Groups of 32 MiB on 32 MiB make one group: the copy of group 0 is refused for it."""
    lower = lowers()
    lower.change(0, group_sectors=32 * 2048)
    lower.change(1, version=2)
    taken, messages = created(lower)
    assert not taken
    assert logged(messages, "group 0: too few groups for its size of a group"), messages


def test_copies_with_the_numbers_swapped_are_refused(lowers):
    """A copy found where another belongs, as by a misdirected write, is not taken for it."""
    lower = lowers()
    lower.change(0, group=1)
    lower.change(1, group=0)
    taken, messages = created(lower)
    assert not taken
    assert logged(messages, f"group 0: the number of another group, group 1: {NO_GROUP_1}"), messages


def test_a_damaged_crc_is_refused(lowers):
    lower = lowers()
    for group in range(2):
        superblock = lower.superblock(group)
        superblock[200] ^= 1  # in the reserved bytes, which only the CRC covers
        lower.write_superblock(group, superblock, fix_crc=False)
    taken, messages = created(lower)
    assert not taken
    assert logged(messages, f"group 0: CRC mismatch, group 1: {NO_GROUP_1}"), messages


@pytest.mark.parametrize("group", [0, 1])
def test_one_damaged_copy_is_covered_by_the_other(lowers, group):
    """The device comes up from the other copy, warns, and holds the data written before in both groups."""
    lower = lowers()
    assert create(lower.path, lower.sectors).returncode == 0
    writes = [(0, pattern("group 0", DATA_SECTORS)), (lower.layout.group_capacity, pattern("group 1", DATA_SECTORS))]
    write_and_flush(f"/dev/mapper/{UPPER_NAME}", writes)
    dmsetup_remove(UPPER_NAME)

    lower.damage(group)
    taken, messages = created(lower)
    assert taken, messages
    assert logged(messages, f"the superblock of group {group} is not valid: no magic"), messages
    assert logged(messages, f"superblock of group {1 - group}, generation 1"), messages
    read_back(f"/dev/mapper/{UPPER_NAME}", writes)


@pytest.mark.parametrize("group_mib", [16, 32, 64, 1024], ids=lambda mib: f"{mib} MiB")
def test_group_1_is_found_for_each_size_when_group_0_is_damaged(lowers, group_mib):
    """With group 0 gone the size of a group is not known: the start of group 1 is probed for each size,
    from the smallest, and the smaller ones land inside group 0."""
    group_sectors = group_mib * 2048
    sectors = min(5 * group_sectors // 2, 2048 * 2048)
    lower = lowers(sectors, group_sectors=group_sectors)
    assert create(lower.path, lower.sectors, group_sectors=group_sectors).returncode == 0
    starts = [0, lower.layout.group_capacity - DATA_SECTORS, lower.layout.group_capacity, lower.layout.capacity - DATA_SECTORS]
    writes = [(start, pattern(start, DATA_SECTORS)) for start in starts]
    write_and_flush(f"/dev/mapper/{UPPER_NAME}", writes)
    dmsetup_remove(UPPER_NAME)

    lower.damage(0)
    taken, messages = created(lower)
    assert taken, messages
    assert logged(messages, f"superblock of group 1, generation 1, groups of {group_sectors} sectors"), messages
    read_back(f"/dev/mapper/{UPPER_NAME}", writes)


def test_a_format_with_larger_groups_wipes_group_1_of_the_smaller_sizes(lowers):
    """Formatted with groups of 16 MiB, then of 32 MiB: the copy of group 1 of the first format would lie
    in the data of group 0 and be taken by the probe, so the second format wipes it."""
    lower = lowers(64 * 2048)
    stale = lower.superblock(1)
    format_device(lower.path, force=True, group_sectors=32 * 2048)
    assert lower.read(16 * 2048, SUPERBLOCK_SECTORS) == bytes(SUPERBLOCK_SECTORS * 512)
    lower.group_sectors = 32 * 2048
    lower.damage(0)
    taken, messages = created(lower)
    assert taken, messages
    assert logged(messages, f"superblock of group 1, generation 1, groups of {32 * 2048} sectors"), messages
    dmsetup_remove(UPPER_NAME)

    # The positive control: put the stale copy back, and the probe takes it, with the layout of 16 MiB.
    device = BlockDevice(lower.path)
    try:
        device.write(16 * 2048, bytes(stale))
    finally:
        device.close()
    taken, messages = created(lower, group_sectors=16 * 2048)
    assert taken, messages
    assert logged(messages, f"groups of {16 * 2048} sectors"), messages


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
    assert logged(messages, f"superblock of group {newer}, generation 2"), messages


@pytest.mark.parametrize("field", ["salt", "uuid"])
def test_copies_that_differ_in_the_same_generation_warn(lowers, field):
    """A copy of another device of the same size in group 1, as a header written to the wrong device."""
    lower = lowers()
    lower.change(1, **{field: os.urandom(16)})
    taken, messages = created(lower)
    assert taken, messages
    assert logged(messages, "differ in the same generation, taking group 0"), messages
    assert logged(messages, "superblock of group 0, generation 1"), messages


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
    assert logged(messages, "group 0: formatted for a device of another size"), messages


# A full group, then a short one of the smallest size: its header and two whole regions.
SMALLEST = GROUP_SECTORS + GROUP_HEADER_SECTORS + 2 * REGION_SECTORS


@pytest.mark.parametrize("change", [-DATA_SECTORS, 0], ids=["too small", "smallest"])
def test_the_smallest_device(lowers, change):
    """Two groups, the second short with two regions; a chunk less, and neither the tool nor the driver
    takes it."""
    sectors = SMALLEST + change
    lower = lowers(sectors, formatted=False)
    result = run(TOOL, "format", "--group-size", "16M", lower.path, check=False)
    if change:
        assert layout(sectors) is None
        assert result.returncode != 0 and "too small" in result.stderr
        taken, messages = created(lower, length=8)
        assert not taken
        assert logged(messages, "no valid superblock"), messages
    else:
        assert result.returncode == 0, result.stderr
        assert capacity(sectors) == (layout(sectors).group_regions + 2) * REGION_CAPACITY
        assert layout(sectors).groups == 2 and layout(sectors).last_group_regions == 2
        taken, messages = created(lower)
        assert taken, messages


@pytest.mark.parametrize(
    "sectors, group_mib",
    [
        (SMALLEST, 16),
        (LOWER_MIB * 2048, 16),
        (LOWER_MIB * 2048 + 300, 16),
        (42 * 2048, 16),  # a short last group of two regions
        (100 * 2048, 16),
        (100 * 2048, 32),
        (2048 * 2048, 1024),
    ],
    ids=lambda value: str(value),
)
def test_dcorrsetup_gives_the_layout_of_the_tests(lowers, sectors, group_mib):
    lower = lowers(sectors, group_sectors=group_mib * 2048)
    fields, _ = dump(lower.path)
    expected = lower.layout
    assert fields["group0"] == fields["group1"] == "valid"
    assert int(fields["group1_start"]) == expected.group_start(1)
    for name in LAYOUT_FIELDS:
        assert int(fields[name]) == getattr(expected, name), name
    assert int(fields["header_sectors"]) == GROUP_HEADER_SECTORS
    assert table_line(lower.path) == f"0 {expected.capacity} dcorr {lower.path}\n"
    taken, messages = created(lower)
    assert taken, messages


@pytest.mark.parametrize("group_mib", [16, 1024], ids=lambda mib: f"{mib} MiB")
def test_the_header_of_every_group_holds_its_superblock_and_bitmaps(lowers, group_mib):
    """Every group: a superblock with its number; the leading bitmap of the group and the trailing one of
    the group before, empty, numbered, each with a CRC that starts from the salt; the dirty stripes zero."""
    group_sectors = group_mib * 2048
    lower = lowers(2048 * 2048 if group_mib == 1024 else 42 * 2048, group_sectors=group_sectors)
    device = lower.layout
    salt = get_field(lower.superblock(0), "salt")
    for group in range(device.groups):
        superblock = lower.superblock(group)
        assert get_field(superblock, "group") == group
        assert struct.unpack_from("<Q", superblock, CRC_OFFSET)[0] == superblock_crc(superblock)
        for name in LAYOUT_FIELDS:
            assert get_field(superblock, name) == getattr(device, name), name
        assert get_field(superblock, "salt") == salt
        blocks = [(device.lead_bitmap_start(group), group, 0), (device.trail_bitmap_start(group), group, 1)]
        for start, covered, role in blocks:
            for index in range(device.bitmap_blocks):
                block = lower.read(start + index * BITMAP_BLOCK_SECTORS, BITMAP_BLOCK_SECTORS)
                crc, generation, holder, number, kind = struct.unpack_from("<QQQII", block)
                assert (generation, holder, number, kind) == (1, covered, index, role), (group, role, index)
                assert crc == bitmap_block_crc(block, salt), (group, role, index)
                assert crc != crc64_be(0, bytes(8) + bytes(block[8:])), "the salt is not in the CRC"
                assert block[BITMAP_HEADER_SIZE:] == bytes(BITMAP_BLOCK_SIZE - BITMAP_HEADER_SIZE)
        assert lower.read(device.dirty_start(group), 2 * BITMAP_BLOCK_SECTORS) == bytes(2 * BITMAP_BLOCK_SIZE)


@pytest.mark.parametrize("size", ["3M", "8M", "24M", "8G", "0M", "16", "16K"])
def test_dcorrsetup_refuses_a_size_of_a_group_not_in_the_list(lowers, size):
    lower = lowers(formatted=False)
    result = run(TOOL, "format", "--group-size", size, lower.path, check=False)
    assert result.returncode != 0 and "power of two" in result.stderr, result.stderr


def test_dcorrsetup_formats_with_groups_of_1_gib_by_default(lowers):
    lower = lowers(2048 * 2048, formatted=False)
    run(TOOL, "format", lower.path)
    fields, _ = dump(lower.path)
    assert int(fields["group_sectors"]) == DEFAULT_GROUP_SECTORS
    assert int(fields["group_regions"]) == 248 and int(fields["groups"]) == 2
    assert int(fields["capacity"]) == 2 * 248 * REGION_CAPACITY


def region_chunks_of_data(device, region):
    """The first and the last logical chunk of a region, in sectors."""
    first = device.region_logical(region)
    group, index = divmod(region, device.group_regions)
    chunks = min(REGION_CHUNKS, device.data_slots(group) - index * REGION_CHUNKS)
    return first, first + (chunks - 1) * DATA_SECTORS


def test_every_region_lies_where_the_layout_says(lowers):
    """A chunk at the start and at the end of the data of each region lands where harness.py puts it.

    The device is two full groups and a short one, so this covers the borders of the groups and of the
    data columns, which fall inside a region.
    """
    lower = lowers(42 * 2048)
    device = lower.layout
    assert device.groups == 3 and device.last_group_regions == 2
    assert create(lower.path, lower.sectors).returncode == 0
    starts = []
    for region in range(device.regions):
        starts += region_chunks_of_data(device, region)
    assert starts[-1] == device.capacity - DATA_SECTORS
    writes = [(start, pattern(start, DATA_SECTORS)) for start in starts]
    write_and_flush(f"/dev/mapper/{UPPER_NAME}", writes)
    below = BlockDevice(lower.path)
    try:
        for start, data in writes:
            assert below.read(physical_sector(start, lower.sectors), DATA_SECTORS) == data, start
    finally:
        below.close()


def test_data_never_lands_in_the_parity_columns_nor_outside_the_regions(lowers):
    """The whole device written: the slots of the parity columns and the unused end of every group stay
    zero, and the headers keep the superblocks."""
    sectors = 45 * 2048  # three groups, the last short with two regions and an unused end of 3.75 MiB
    lower = lowers(sectors)
    device = lower.layout
    assert device.groups == 3
    assert create(lower.path, lower.sectors).returncode == 0
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    try:
        for start in range(0, device.capacity, 2048):
            upper.write(start, pattern(start, min(2048, device.capacity - start)))
        upper.flush_settled()
    finally:
        upper.close()

    zero_slot = bytes(DATA_SECTORS * 512)
    below = BlockDevice(lower.path)
    try:
        for group in range(device.groups):
            first = group * device.group_regions * REGION_CHUNKS
            data = device.data_slots(group)
            slots = device.regions_of_group(group) * REGION_CHUNKS
            assert slots - data == 2 * slots // 32
            for slot in range(first + data, first + slots):
                assert below.read(device.slot_sector(slot), DATA_SECTORS) == zero_slot, f"slot {slot}"
            end = device.region_start(group * device.group_regions + device.regions_of_group(group) - 1) + REGION_SECTORS
            limit = device.group_start(group + 1) if group + 1 < device.groups else sectors
            if group + 1 < device.groups:
                assert end < limit
            assert below.read(end, limit - end) == bytes((limit - end) * 512), f"after the regions of group {group}"
            assert below.read(device.group_start(group))[:8] == b"dm-dcorr"
    finally:
        below.close()
    assert device.data_slots(0) == DATA_COLUMNS * COLUMN_SLOTS_PER_REGION * device.group_regions


@pytest.mark.parametrize("group_mib", [1024, 4096], ids=lambda mib: f"{mib} MiB")
def test_a_large_device(tmp_path, group_mib):
    """A sparse file of 40 GiB: chunks at the borders of the groups land where harness.py puts them.

    Only the headers and the chunks written take space in the file.
    """
    group_sectors = group_mib * 2048
    image = tmp_path / "large.img"
    with open(image, "wb") as file:
        file.truncate(40 << 30)
    loop = run("losetup", "--find", "--show", str(image)).stdout.strip()
    try:
        sectors = int(run("blockdev", "--getsz", loop).stdout)
        expected = layout(sectors, group_sectors)
        format_device(loop, group_sectors=group_sectors)
        fields, _ = dump(loop)
        for name in LAYOUT_FIELDS:
            assert int(fields[name]) == getattr(expected, name), name
        run("dmsetup", "create", UPPER_NAME, stdin=table_line(loop))
        upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
        below = BlockDevice(loop)
        starts = []
        for group in (0, 1, expected.groups - 1):
            starts += [group * expected.group_capacity, (group + 1) * expected.group_capacity - DATA_SECTORS]
        starts = sorted(set(min(start, expected.capacity - DATA_SECTORS) for start in starts))
        try:
            for start in starts:
                upper.write(start, pattern(start, DATA_SECTORS))
            upper.flush_settled()
            for start in starts:
                assert below.read(physical_sector(start, sectors, group_sectors), DATA_SECTORS) == pattern(
                    start, DATA_SECTORS
                ), start
        finally:
            upper.close()
            below.close()
    finally:
        dmsetup_remove(UPPER_NAME)
        run("losetup", "--detach", loop, check=False)


def test_format_keeps_a_valid_superblock_without_force(lowers):
    lower = lowers()
    before, _ = dump(lower.path)
    result = run(TOOL, "format", "--group-size", "16M", lower.path, check=False)
    assert result.returncode != 0 and "--force" in result.stderr
    assert dump(lower.path)[0]["uuid"] == before["uuid"]
    format_device(lower.path, force=True)
    assert dump(lower.path)[0]["uuid"] != before["uuid"]


def test_format_keeps_a_superblock_found_only_in_group_1(lowers):
    """Without force the format looks for group 1 as the driver does, so a damaged group 0 is not enough."""
    lower = lowers()
    lower.damage(0)
    result = run(TOOL, "format", "--group-size", "16M", lower.path, check=False)
    assert result.returncode != 0 and "--force" in result.stderr


def test_format_refuses_a_device_in_use(lowers):
    lower = lowers()
    assert create(lower.path, lower.sectors).returncode == 0
    result = run(TOOL, "format", "--force", "--group-size", "16M", lower.path, check=False)
    assert result.returncode != 0 and "in use" in result.stderr


def test_dump_of_a_device_without_a_superblock_fails(lowers):
    lower = lowers(formatted=False)
    fields, result = dump(lower.path, check=False)
    assert result.returncode != 0
    assert fields["group0"] == "no magic"
    assert fields["group1"] == NO_GROUP_1

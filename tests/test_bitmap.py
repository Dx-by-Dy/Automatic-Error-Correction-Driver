"""The bitmap of written chunks: a chunk never written reads as zeros, a bit reaches the device with a flush,
and the two copies of a block of the bitmap cover each other.

The lower devices here are filled with random data before they are formatted, as a device that is only
formatted, never zeroed, would be: what the slots and the metadata hold must not matter for a chunk never
written.
"""

import os
import struct

import pytest

from conftest import (
    FAULTY_NAME,
    LOWER_NAME,
    UPPER_NAME,
    device_status,
    dmsetup_remove,
    kernel_messages,
    make_lower,
    wait_for_write_back,
)
from harness import (
    BITMAP_BLOCK_SECTORS,
    BITMAP_BLOCK_SIZE,
    BITMAP_LEAD,
    BITMAP_TRAIL,
    DATA_SECTORS,
    SALT_OFFSET,
    SALT_SIZE,
    SECTOR_SIZE,
    BitmapBlock,
    BlockDevice,
    bitmap_block_sector,
    bitmap_place,
    capacity,
    crc64_be,
    format_device,
    layout,
    pattern,
    run,
)

LOWER_MIB = 48  # three groups of 16 MiB, one block of the bitmap each
ROLES = {"leading": BITMAP_LEAD, "trailing": BITMAP_TRAIL}


def fill_random(path, sectors):
    run("dd", "if=/dev/urandom", f"of={path}", "bs=1M", "oflag=direct", "iflag=count_bytes", f"count={sectors * 512}")


class Device:
    """The driver on a lower device filled with random data, then formatted."""

    def __init__(self, lower_mib=LOWER_MIB, lower=None, raw=None):
        self.sectors = lower_mib * 2048
        self.path = lower or make_lower(self.sectors)
        # Where the tests read and write the lower device themselves, below any faulty target.
        self.raw = raw or self.path
        fill_random(self.path, self.sectors)
        format_device(self.path)
        self.layout = layout(self.sectors)
        self.salt = self.read_lower(0, 1)[SALT_OFFSET : SALT_OFFSET + SALT_SIZE]
        self.upper = None
        self.messages = self.create()

    @property
    def capacity(self):
        return capacity(self.sectors)

    def create(self, readonly=False):
        """Puts the driver on the lower device; returns the kernel messages of the constructor."""
        with kernel_messages() as messages:
            run(
                "dmsetup", "create", *(["--readonly"] if readonly else []), UPPER_NAME,
                stdin=f"0 {self.capacity} dcorr {self.path}\n",
            )
        self.upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}", readonly)
        return messages

    def remove(self):
        if self.upper:
            self.upper.close()
            self.upper = None
        dmsetup_remove(UPPER_NAME)

    def recreate(self, readonly=False):
        self.remove()
        return self.create(readonly)

    def read_lower(self, sector, count):
        lower = BlockDevice(self.raw)
        try:
            return lower.read(sector, count)
        finally:
            lower.close()

    def write_lower(self, sector, data):
        lower = BlockDevice(self.raw)
        try:
            lower.write(sector, data)
        finally:
            lower.close()

    def block(self, group, role, index=0):
        start = bitmap_block_sector(self.layout, group, index, role)
        return BitmapBlock.parse(self.read_lower(start, BITMAP_BLOCK_SECTORS))

    def write_block(self, group, role, data, index=0):
        self.write_lower(bitmap_block_sector(self.layout, group, index, role), data)

    def damage_block(self, group, role, index=0):
        """Flips a bit of the bits of a copy, leaving its CRC."""
        data = bytearray(self.block(group, role, index).pack())
        data[BITMAP_BLOCK_SIZE - 1] ^= 1
        self.write_block(group, role, bytes(data), index)

    def bit(self, logical, role):
        group, index, bit = bitmap_place(self.layout, logical)
        return self.block(group, role, index).bit(bit)


@pytest.fixture
def device():
    created = Device()
    yield created
    created.remove()
    dmsetup_remove(LOWER_NAME)


def flushed(device, writes):
    """Writes and flushes, and waits for the trailing copies, so that the lower device may be looked at."""
    for start, data in writes:
        device.upper.write(start, data)
    device.upper.flush_settled()


def logged(messages, text):
    return any(text in message for message in messages)


def read_fails(device, sector, count=DATA_SECTORS):
    try:
        device.upper.read(sector, count)
    except OSError:
        return True
    return False


def test_a_device_of_random_data_reads_zeros_once_formatted(device):
    """Formatting is enough: every chunk reads as zeros, without a read of the lower device or its metadata.

    The positive control is the driver before the bitmap: it read the random data and failed its CRC.
    """
    assert device.upper.read(0, device.capacity) == bytes(device.capacity * SECTOR_SIZE)
    status = device_status()
    assert status["metadata_loads"] == 0, status
    assert status["unwritten_reads"] >= device.capacity // DATA_SECTORS, status


# (sector, sectors) written to chunks never written: one sector inside a chunk, a whole chunk, a run across
# a chunk boundary, the last chunk of group 0 and the first of group 1.
FIRST_WRITES = [(5 * DATA_SECTORS + 3, 1), (9 * DATA_SECTORS, DATA_SECTORS), (12 * DATA_SECTORS + 6, 4)]


def first_writes(device):
    group_end = device.layout.group_capacity
    return [(start, pattern(f"first {start}", sectors)) for start, sectors in
            [*FIRST_WRITES, (group_end - 2, 1), (group_end + 1, 2)]]


def expected_chunks(writes):
    """The chunks the writes touch, as they read: the data written, zeros around it."""
    chunks = {}
    for start, data in writes:
        for offset in range(len(data) // SECTOR_SIZE):
            chunk, index = divmod(start + offset, DATA_SECTORS)
            image = chunks.setdefault(chunk, bytearray(DATA_SECTORS * SECTOR_SIZE))
            image[index * SECTOR_SIZE : (index + 1) * SECTOR_SIZE] = data[offset * SECTOR_SIZE :][:SECTOR_SIZE]
    return chunks


def test_a_first_write_reads_back_with_zeros_around_it(device):
    """A chunk written for the first time is written whole, the sectors not written as zeros.

    Without that, the sectors around a write hold random data that fails its CRC once the bit is set. The
    metadata of such a chunk is random as well, and is not read to settle its copies.
    """
    writes = first_writes(device)
    flushed(device, writes)
    status = device_status()
    assert (status["settle_reads"], status["settle_mismatches"]) == (0, 0), status
    for when in ("before", "after"):
        for chunk, image in expected_chunks(writes).items():
            assert device.upper.read(chunk * DATA_SECTORS, DATA_SECTORS) == image, f"chunk {chunk} {when}"
        device.recreate()


def test_a_bit_reaches_the_device_only_with_a_flush(device):
    """Written back by age, the data is on the device but not its bit; a flush writes both copies of the
    block, with the next generation, the leading one first."""
    start = 7 * DATA_SECTORS
    device.upper.write(start, pattern("seven", DATA_SECTORS))
    wait_for_write_back()
    for role in ROLES.values():
        block = device.block(0, role)
        assert (block.generation, block.bit(7)) == (1, False), role

    device.upper.flush_settled()
    for name, role in ROLES.items():
        block = device.block(0, role)
        assert block.valid(device.salt), name
        assert (block.generation, block.group, block.index, block.role) == (2, 0, 0, role), name
        assert [n for n in range(64) if block.bit(n)] == [7], name
    assert not device.block(1, BITMAP_LEAD).bit(0)

    device.upper.flush_settled()
    assert device.block(0, BITMAP_LEAD).generation == 2, "a flush with no new bit rewrote the block"


@pytest.mark.parametrize("written_back", [False, True], ids=["in the cache", "written back"])
def test_a_reload_keeps_the_bits_the_old_table_sets(device, written_back):
    """dmsetup reload builds the new table while the old one is live; the bits the old one sets after its
    last flush, at the write back by age or at its suspend, must reach the new one, or the chunk reads as zeros
    under it and a partial write there fills the rest with zeros."""
    start, sixth = 7 * DATA_SECTORS, pattern("sixth", 1)
    data = pattern("seven", DATA_SECTORS)
    device.upper.write(start, data)
    if written_back:
        wait_for_write_back()
    run("dmsetup", "reload", UPPER_NAME, stdin=f"0 {device.capacity} dcorr {device.path}\n")
    run("dmsetup", "resume", UPPER_NAME)
    assert device.upper.read(start, DATA_SECTORS) == data
    device.upper.write(start + 6, sixth)
    expected = data[: 6 * SECTOR_SIZE] + sixth + data[7 * SECTOR_SIZE :]
    device.recreate()
    assert device.upper.read(start, DATA_SECTORS) == expected


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("readonly", [False, True], ids=["writable", "read only table"])
def test_one_damaged_copy_is_covered_and_repaired(device, role, readonly):
    """A block valid in one copy is taken from it; the next flush writes the other, unless the table is read
    only."""
    start = 3 * DATA_SECTORS
    data = pattern("covered", DATA_SECTORS)
    flushed(device, [(start, data)])
    device.remove()
    device.damage_block(0, ROLES[role])
    messages = device.create(readonly)
    assert logged(messages, f"has only its {'leading' if role == 'trailing' else 'trailing'} copy valid"), messages
    assert device_status()["single_blocks"] == 1
    assert device.upper.read(start, DATA_SECTORS) == data

    if not readonly:
        device.upper.flush_settled()
    device.remove()
    block = device.block(0, ROLES[role])
    assert block.valid(device.salt) != readonly, "repaired with a read only table" if readonly else "not repaired"
    if not readonly:
        other = device.block(0, BITMAP_TRAIL if role == "leading" else BITMAP_LEAD)
        assert block.generation == other.generation and block.bits == other.bits
        assert block.bit(3)
    device.create()


@pytest.mark.parametrize("older", ROLES)
def test_the_copy_with_the_larger_generation_is_taken(device, older):
    """A copy left behind by a crash between the two writes of a block is valid, but older."""
    first, second = 3 * DATA_SECTORS, 4 * DATA_SECTORS
    flushed(device, [(first, pattern("first", DATA_SECTORS))])
    stale = device.block(0, ROLES[older])
    flushed(device, [(second, pattern("second", DATA_SECTORS))])
    device.remove()
    device.write_block(0, ROLES[older], stale.pack())
    device.create()
    assert device_status()["single_blocks"] == 0
    assert device.upper.read(second, DATA_SECTORS) == pattern("second", DATA_SECTORS)


@pytest.mark.parametrize("older", ROLES)
@pytest.mark.parametrize("then", ["a new bit", "a flush alone"])
def test_an_older_copy_is_rewritten_before_the_newer_is_lost(device, older, then):
    """Of two valid copies the newer is taken, but the older stays on the device until the block changes:
    once the newer copy is lost, the older one alone reads the chunks written in between as zeros, with no
    error. A block found with one valid copy is repaired by the next flush; one with an older copy has to be
    as well.

    "a new bit" is the positive control: a first write to another chunk of the block changes it, so the
    flush writes both copies, and the chunk survives the loss of the newer one.
    """
    first, second, third = 3 * DATA_SECTORS, 4 * DATA_SECTORS, 5 * DATA_SECTORS
    flushed(device, [(first, pattern("first", DATA_SECTORS))])
    stale = device.block(0, ROLES[older])
    flushed(device, [(second, pattern("second", DATA_SECTORS))])
    device.remove()
    device.write_block(0, ROLES[older], stale.pack())
    device.create()
    flushed(device, [(third, pattern("third", DATA_SECTORS))] if then == "a new bit" else [])
    device.remove()
    device.damage_block(0, BITMAP_TRAIL if older == "leading" else BITMAP_LEAD)
    device.create()
    assert device_status()["single_blocks"] == 1
    assert device.upper.read(second, DATA_SECTORS) == pattern("second", DATA_SECTORS), "read as zeros"


@pytest.mark.xfail(strict=True, reason="A zeroed chunk in a read only range reads its old data")
@pytest.mark.parametrize("how", ["discard", "write zeroes"])
def test_a_zeroed_chunk_in_a_read_only_block_never_reads_its_old_data(device, how):
    """A discard or a write zeroes leaves the old data and its CRCs below, and only the bit says the chunk
    reads as zeros. In a block invalid in both copies every chunk is read as written and the CRC decides, and
    the old data passes it. An error would be right, or zeros; the old contents of a zeroed range are not.

    The positive control is a chunk never written in the same range, which fails its CRC there, see
    test_a_block_invalid_in_both_copies_makes_its_range_read_only; here the chunk reads as zeros before.
    """
    start = 3 * DATA_SECTORS
    old = pattern("old", DATA_SECTORS)
    flushed(device, [(start, old)])
    if how == "discard":
        device.upper.discard(start, DATA_SECTORS)
    else:
        device.upper.zeroout(start, DATA_SECTORS)
    device.upper.flush_settled()
    assert device.upper.read(start, DATA_SECTORS) == bytes(DATA_SECTORS * SECTOR_SIZE)
    device.remove()
    for role in ROLES.values():
        device.damage_block(0, role)
    device.create()
    assert device_status()["read_only_blocks"] == 1
    if read_fails(device, start):
        return
    assert device.upper.read(start, DATA_SECTORS) != old, "the old data of a zeroed chunk read back"


# A copy of the leading block of group 0 with one thing wrong, its CRC right otherwise, and a generation
# that would win.
WRONG_PLACES = {
    "group": dict(group=1),
    "index": dict(index=1),
    "role": dict(role=BITMAP_TRAIL),
    "salt": dict(),
    "nothing": dict(),
}


@pytest.mark.parametrize("wrong", WRONG_PLACES)
def test_a_block_of_another_place_or_device_is_not_taken(device, wrong):
    """A block is checked for its group, its index, its role, and its CRC starts from the salt of the device.

    The wrong copy is empty with a large generation, so taken it would lose the chunk written; "nothing"
    is the positive control, the same copy with nothing wrong, which is taken.
    """
    start = 3 * DATA_SECTORS
    data = pattern("kept", DATA_SECTORS)
    flushed(device, [(start, data)])
    device.remove()
    block = device.block(0, BITMAP_LEAD)
    block.generation = 100
    for name, value in WRONG_PLACES[wrong].items():
        setattr(block, name, value)
    if wrong == "nothing":
        block.bits = bytes(len(block.bits))
    device.write_block(0, BITMAP_LEAD, block.pack(os.urandom(SALT_SIZE) if wrong == "salt" else device.salt))
    device.create()
    if wrong == "nothing":
        assert device_status()["single_blocks"] == 0
        assert device.upper.read(start, DATA_SECTORS) == bytes(DATA_SECTORS * SECTOR_SIZE)
    else:
        assert device_status()["single_blocks"] == 1
        assert device.upper.read(start, DATA_SECTORS) == data


def test_a_block_invalid_in_both_copies_makes_its_range_read_only(device):
    """Its chunks are read as written, so the CRC decides, never silent zeros; writes there fail, and the
    other groups go on."""
    written = 3 * DATA_SECTORS
    never = 40 * DATA_SECTORS
    elsewhere = device.layout.group_capacity + 3 * DATA_SECTORS
    data = pattern("kept", DATA_SECTORS)
    flushed(device, [(written, data)])
    device.remove()
    for role in ROLES.values():
        device.damage_block(0, role)
    messages = device.create()
    assert logged(messages, "block 0 of the bitmap of group 0 is invalid in both copies"), messages
    assert device_status()["read_only_blocks"] == 1

    assert device.upper.read(written, DATA_SECTORS) == data
    assert read_fails(device, never), "a chunk never written read without its CRC failing"
    with pytest.raises(OSError):
        device.upper.write(written, pattern("refused", DATA_SECTORS))
    assert device_status()["refused_writes"] >= 1
    flushed(device, [(elsewhere, pattern("elsewhere", DATA_SECTORS))])
    device.recreate()
    assert device.upper.read(elsewhere, DATA_SECTORS) == pattern("elsewhere", DATA_SECTORS)
    assert device.upper.read(written, DATA_SECTORS) == data
    for role in ROLES.values():
        assert not device.block(0, role).valid(device.salt), "a block invalid in both copies was written"


def test_a_discard_touching_a_read_only_block_fails_whole(device):
    """A discard across the end of a group whose block is invalid in both copies fails, also in the next group."""
    start = device.layout.group_capacity - 2 * DATA_SECTORS
    data = pattern("kept", 4 * DATA_SECTORS)
    flushed(device, [(start, data)])
    device.remove()
    for role in ROLES.values():
        device.damage_block(0, role)
    device.create()
    before = device_status()

    with pytest.raises(OSError):
        device.upper.discard(start, 4 * DATA_SECTORS)
    status = device_status()
    assert status["refused_writes"] == before["refused_writes"] + 1
    assert status["discarded_chunks"] == before["discarded_chunks"]
    assert device.upper.read(start, 4 * DATA_SECTORS) == data, "a chunk of the next group was discarded"


SUPERBLOCK_CRC_OFFSET = 152


def superblock_crc(superblock):
    return crc64_be(0, bytes(superblock[:SUPERBLOCK_CRC_OFFSET]) + bytes(8) + bytes(superblock[SUPERBLOCK_CRC_OFFSET + 8 :]))


# How the superblock of group 2 is changed, the offset and the bytes, and the reason in the log.
SUPERBLOCK_CHANGES = {
    "zeroed": (None, None, "no magic"),
    "another device": (32, os.urandom(16), "the copy of another device"),
    "another generation": (16, struct.pack("<Q", 7), "another generation"),
    "nothing": (16, struct.pack("<Q", 1), None),
}


@pytest.mark.parametrize("change", SUPERBLOCK_CHANGES)
def test_the_superblock_of_every_other_group_is_checked(device, change):
    """The superblocks of groups 2 and on are read with the bitmap; one that is wrong is counted and named
    in the log, and the device still works."""
    offset, value, reason = SUPERBLOCK_CHANGES[change]
    device.remove()
    start = device.layout.group_start(2)
    superblock = bytearray(device.read_lower(start, 8))
    if offset is None:
        superblock = bytearray(len(superblock))
    else:
        superblock[offset : offset + len(value)] = value
        struct.pack_into("<Q", superblock, SUPERBLOCK_CRC_OFFSET, superblock_crc(superblock))
    device.write_lower(start, bytes(superblock))
    messages = device.create()
    assert device_status()["bad_superblocks"] == (0 if reason is None else 1)
    if reason:
        assert logged(messages, f"the superblock of group 2 is not valid: {reason}"), messages
    flushed(device, [(0, pattern("works", DATA_SECTORS))])


@pytest.fixture
def dusty():
    """The driver on dm-dust on a lower device of random data, formatted."""
    sectors = LOWER_MIB * 2048
    lower = make_lower(sectors)
    run("dmsetup", "create", FAULTY_NAME, stdin=f"0 {sectors} dust {lower} 0 512\n")
    created = Device(lower=f"/dev/mapper/{FAULTY_NAME}", raw=lower)
    yield created
    created.remove()
    dmsetup_remove(FAULTY_NAME)
    dmsetup_remove(LOWER_NAME)


def fail_writes(sector):
    for words in (("addbadblock", sector, 1), ("enable",)):
        run("dmsetup", "message", FAULTY_NAME, "0", *map(str, words))


def test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write(dusty):
    """A flush promises the data is there, and without its bit it would read as zeros after a crash. The
    block stays dirty, so the next flush writes it."""
    start = 3 * DATA_SECTORS
    data = pattern("flushed", DATA_SECTORS)
    fail_writes(bitmap_block_sector(dusty.layout, 0, 0, BITMAP_LEAD))
    dusty.upper.write(start, data)
    with pytest.raises(OSError):
        dusty.upper.flush()
    assert device_status()["bitmap_write_errors"] == 1
    assert not dusty.bit(start, BITMAP_LEAD) and not dusty.bit(start, BITMAP_TRAIL)

    dusty.upper.flush_settled()
    assert dusty.bit(start, BITMAP_LEAD) and dusty.bit(start, BITMAP_TRAIL)
    dusty.recreate()
    assert dusty.upper.read(start, DATA_SECTORS) == data


def test_a_second_copy_that_fails_to_write_is_counted(dusty):
    """The first copy is on the device then, so the flush succeeds."""
    start = 3 * DATA_SECTORS
    data = pattern("flushed", DATA_SECTORS)
    fail_writes(bitmap_block_sector(dusty.layout, 0, 0, BITMAP_TRAIL))
    dusty.upper.write(start, data)
    dusty.upper.flush_settled()
    assert device_status()["bitmap_write_errors"] == 1
    assert dusty.bit(start, BITMAP_LEAD) and not dusty.bit(start, BITMAP_TRAIL)
    dusty.recreate()
    assert dusty.upper.read(start, DATA_SECTORS) == data

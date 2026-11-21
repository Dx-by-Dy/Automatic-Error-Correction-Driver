"""Lost writes: acknowledged by the lower device, never on its medium.

A faulty device sits between the driver and the lower device: `linear` everywhere, and dm-flakey with
`drop_writes`, always down, over the sectors whose writes are to be lost; reads go through. It is loaded
after a write from above and before its write back, by age, so that only the write back is lost, then
the plain table again.

The threat model says what to expect: the data of a write back lost passes as the old contents until the
flush after it, as the trailing copy still holds the old CRC, and fails after it; a first write lost
fails at once; a lost copy of metadata or of a block of the bitmap is covered by the other copy; data lost
with both copies of its metadata passes as old for ever.
"""

import errno

import pytest

from conftest import (
    FAULTY_NAME,
    LOWER_NAME,
    UPPER_NAME,
    create_dcorr,
    device_status,
    dmsetup_remove,
    make_lower,
    wait_for_write_back,
)
from harness import (
    BITMAP_BLOCK_SECTORS,
    BITMAP_LEAD,
    BITMAP_TRAIL,
    DATA_SECTORS,
    BitmapBlock,
    BlockDevice,
    bitmap_block_sector,
    capacity,
    layout,
    metadata_sector,
    pattern,
    physical_sector,
    run,
    trail_sector,
)

LOWER_MIB = 32
# A chunk in region 0, written by the fixture with its neighbours; and one never written.
CHUNK = 5
FIRST = CHUNK * DATA_SECTORS
NEVER = 20 * DATA_SECTORS


class LossyStack:
    """The driver on a faulty device that loses the writes to the ranges given, on a zeroed lower device."""

    def __init__(self):
        self.lower_sectors = LOWER_MIB * 2048
        self.lower_path = make_lower(self.lower_sectors)
        run("dmsetup", "create", FAULTY_NAME, stdin=self.table([]))
        create_dcorr(f"/dev/mapper/{FAULTY_NAME}", self.lower_sectors)
        self.table_line = f"0 {capacity(self.lower_sectors)} dcorr /dev/mapper/{FAULTY_NAME}\n"
        self.upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
        self.lower = BlockDevice(self.lower_path)

    @property
    def layout(self):
        return layout(self.lower_sectors)

    def table(self, ranges):
        """`linear` everywhere, dm-flakey dropping writes over the (start, sectors) ranges."""
        lines = []
        position = 0
        for start, sectors in sorted(ranges):
            if start > position:
                lines.append(f"{position} {start - position} linear {self.lower_path} {position}")
            lines.append(f"{start} {sectors} flakey {self.lower_path} {start} 0 1 1 drop_writes")
            position = start + sectors
        if position < self.lower_sectors:
            lines.append(f"{position} {self.lower_sectors - position} linear {self.lower_path} {position}")
        return "\n".join(lines) + "\n"

    def lose(self, *ranges):
        """From now on, writes to these ranges of the lower device are acknowledged and lost."""
        run("dmsetup", "suspend", FAULTY_NAME)
        run("dmsetup", "reload", FAULTY_NAME, stdin=self.table(ranges))
        run("dmsetup", "resume", FAULTY_NAME)

    def heal(self):
        self.lose()

    def write_back_lost(self, start, data, *ranges):
        """Writes into the cache, then lets the write back by age happen while the ranges lose writes."""
        self.upper.write(start, data)
        self.lose(*ranges)
        wait_for_write_back()
        self.heal()

    def recreate_upper(self):
        self.upper.close()
        dmsetup_remove(UPPER_NAME)
        run("dmsetup", "create", UPPER_NAME, stdin=self.table_line)
        self.upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")

    def data(self, logical):
        """The range of the data slot of the chunk of a logical sector on the lower device."""
        return physical_sector(logical - logical % DATA_SECTORS, self.lower_sectors), DATA_SECTORS

    def lead(self, logical):
        return metadata_sector(logical, self.lower_sectors), 1

    def trail(self, logical):
        return trail_sector(logical, self.lower_sectors), 1

    def remove(self):
        self.upper.close()
        self.lower.close()
        for name in (UPPER_NAME, FAULTY_NAME, LOWER_NAME):
            dmsetup_remove(name)


@pytest.fixture
def lossy():
    stack = LossyStack()
    stack.upper.write(FIRST - DATA_SECTORS, pattern("old", 3 * DATA_SECTORS))
    stack.upper.flush_settled()
    yield stack
    stack.remove()


OLD = pattern("old", 3 * DATA_SECTORS)[DATA_SECTORS * 512 :][: DATA_SECTORS * 512]


def assert_read_fails(device, sector, count=DATA_SECTORS):
    with pytest.raises(OSError) as error:
        device.read(sector, count)
    assert error.value.errno == errno.EIO


@pytest.mark.parametrize("sectors", [DATA_SECTORS, 1], ids=["whole chunk", "one sector"])
def test_lost_data_of_a_rewrite_reads_old_until_the_flush_then_fails(lossy, sectors):
    """Before the flush the trailing copy holds the CRC of the old data, so the old data passes; the flush
    puts the CRC of the new data into it, and then the chunk fails, also after the target is created again."""
    slot = lossy.data(FIRST)
    lossy.write_back_lost(FIRST, pattern("new", sectors), slot)
    assert lossy.lower.read(*slot) == OLD, "dm-flakey did not drop the write back"

    assert lossy.upper.read(FIRST, DATA_SECTORS) == OLD
    lossy.upper.flush_settled()
    assert_read_fails(lossy.upper, FIRST, sectors)
    lossy.recreate_upper()
    assert_read_fails(lossy.upper, FIRST, sectors)
    if sectors < DATA_SECTORS:
        assert lossy.upper.read(FIRST + sectors, DATA_SECTORS - sectors) == OLD[sectors * 512 :]


def test_lost_data_of_a_first_write_fails_at_once(lossy):
    """The bit is set once the write back is acknowledged; the zeros below match neither copy, as the CRC of
    zeros starts from the seed."""
    slot = lossy.data(NEVER)
    lossy.write_back_lost(NEVER, pattern("new", DATA_SECTORS), slot)
    assert lossy.lower.read(*slot) == bytes(DATA_SECTORS * 512), "dm-flakey did not drop the write back"

    assert_read_fails(lossy.upper, NEVER)
    lossy.upper.flush_settled()
    lossy.recreate_upper()
    assert_read_fails(lossy.upper, NEVER)


def test_a_lost_leading_copy_is_covered_by_the_trailing_one(lossy):
    """The data reaches the device and its leading metadata sector does not: the trailing copy, written from
    RAM after the flush, covers it; the next write back finds the copies different and settles them."""
    new = pattern("new", DATA_SECTORS)
    lead = lossy.lead(FIRST)
    before = lossy.lower.read(*lead)
    lossy.write_back_lost(FIRST, new, lead)
    assert lossy.lower.read(*lead) == before, "dm-flakey did not drop the leading copy"

    assert lossy.upper.read(FIRST, DATA_SECTORS) == new
    lossy.upper.flush_settled()
    lossy.recreate_upper()
    assert lossy.upper.read(FIRST, DATA_SECTORS) == new
    assert lossy.lower.read(*lead) != lossy.lower.read(*lossy.trail(FIRST))

    status = device_status()
    newer = pattern("newer", DATA_SECTORS)
    lossy.upper.write(FIRST, newer)
    lossy.upper.flush_settled()
    after = device_status()
    assert (after["settle_reads"], after["settle_mismatches"]) == (
        status["settle_reads"] + 1,
        status["settle_mismatches"],
    )
    assert lossy.lower.read(*lead) == lossy.lower.read(*lossy.trail(FIRST))
    lossy.recreate_upper()
    assert lossy.upper.read(FIRST, DATA_SECTORS) == newer


def test_data_lost_with_both_copies_of_its_metadata_passes_as_old(lossy):
    """The blind spot of the threat model, pinned: nothing on the device tells the old data from a lost write.
    TODO.md, "A lost write passes as the old contents"; the parity of the correction stage may find it."""
    ranges = (lossy.data(FIRST), lossy.lead(FIRST), lossy.trail(FIRST))
    lossy.upper.write(FIRST, pattern("new", DATA_SECTORS))
    lossy.lose(*ranges)
    wait_for_write_back()
    lossy.upper.flush_settled()
    lossy.heal()
    lossy.recreate_upper()
    assert lossy.upper.read(FIRST, DATA_SECTORS) == OLD


@pytest.mark.parametrize("role", [BITMAP_LEAD, BITMAP_TRAIL], ids=["leading", "trailing"])
def test_a_lost_copy_of_a_block_of_the_bitmap_is_covered_by_the_other(lossy, role):
    """A first write whose bit reaches only one copy of its block: the other copy keeps its older generation,
    and the newer one is taken when the target is created again."""
    block = (bitmap_block_sector(lossy.layout, 0, 0, role), BITMAP_BLOCK_SECTORS)
    before = BitmapBlock.parse(lossy.lower.read(*block))
    new = pattern("new", DATA_SECTORS)
    lossy.upper.write(NEVER, new)
    lossy.lose(block)
    lossy.upper.flush_settled()
    lossy.heal()
    assert BitmapBlock.parse(lossy.lower.read(*block)) == before, "dm-flakey did not drop the copy"

    lossy.recreate_upper()
    assert lossy.upper.read(NEVER, DATA_SECTORS) == new


@pytest.mark.parametrize("trailing", ["written", "lost"])
def test_old_data_put_back_fails_once_the_new_was_read(lossy, trailing):
    """The trailing copy of a rewrite is lost, as a crash after the flush and before the trailing copy leaves
    it: the leading copy has the CRC of the new data and the trailing one that of the old. Once the target is
    created again the new data reads and is flushed, so it is durable; yet the trailing copy keeps the old CRC
    until the chunk is written again, and the old data, put back below by a drive that lost the write from its
    cache, would pass for ever. So the read that matched only the leading copy hands the chunk to the worker to
    settle.

    "written" is the positive control: with both copies new, the old data put back fails its CRC.
    """
    new = pattern("new", DATA_SECTORS)
    lossy.upper.write(FIRST, new)
    if trailing == "lost":
        lossy.lose(lossy.trail(FIRST))
    lossy.upper.flush_settled()
    lossy.heal()
    lossy.recreate_upper()
    assert lossy.upper.read(FIRST, DATA_SECTORS) == new
    lossy.upper.flush_settled()

    lossy.lower.write(lossy.data(FIRST)[0], OLD)
    assert_read_fails(lossy.upper, FIRST)

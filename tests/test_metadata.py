"""The metadata in RAM: what it saves on the lower device, and when the driver reads it again.

The driver keeps the metadata areas of the regions it used, METADATA_AREAS of them with both copies,
reads an area whole the first time a chunk of its region needs it, and forgets them all on a suspend.
The trailing copy is written once the lower device has flushed after the write back, so an area
with chunks written since stays in RAM until then; when half the areas are busy, the driver flushes
and writes the trailing copies by itself.

udev reads the start and the end of a device when it is created and after each resume, which reads
the metadata of the first and the last region. So the tests that count reads of metadata use the
regions between them. A chunk never written reads as zeros without its metadata, so they write the
chunks they read first.
"""

import os

from conftest import wait_for_write_back
from harness import (
    DATA_SECTORS,
    REGION_DATA_SECTORS,
    SECTOR_SIZE,
    lower_mib_for_regions,
    metadata_sectors,
    pattern,
    region_sector,
)

# METADATA_AREAS and METADATA_CROWDED in src/metadata.h.
METADATA_AREAS = 32
METADATA_CROWDED = METADATA_AREAS // 2
CHUNK = 5
FIRST = REGION_DATA_SECTORS + CHUNK * DATA_SECTORS


def lower_reads(stack):
    """Reads the lower device has completed, from its statistics in sysfs."""
    name = os.path.basename(os.path.realpath(stack.lower_path))
    with open(f"/sys/block/{name}/stat") as stat:
        return int(stat.read().split()[0])


def loads(stack):
    return stack.status()["metadata_loads"]


def written_and_flushed(stack, start, data):
    stack.upper.write(start, data)
    stack.upper.flush()


def written_then_dropped(stack, starts):
    """Writes a chunk at each start and flushes, then makes the driver forget the metadata."""
    for start in starts:
        stack.upper.write(start, pattern(start, DATA_SECTORS))
    stack.upper.flush_settled()
    stack.drop_metadata()


def test_the_trailing_copy_is_written_after_a_flush(stack):
    """Written back by age, the chunk has its leading copy; the trailing one waits for a flush."""
    lead, trail = metadata_sectors(FIRST, stack.lower_sectors)
    stack.upper.write(FIRST, pattern("data", DATA_SECTORS))
    wait_for_write_back()
    assert stack.lower.read(lead) != bytes(SECTOR_SIZE)
    assert stack.lower.read(trail) == bytes(SECTOR_SIZE), "the trailing copy came before a flush"
    stack.upper.flush_settled()
    assert stack.lower.read(trail) == stack.lower.read(lead)
    assert stack.status()["crowded_flushes"] == 0


def test_a_write_back_reads_nothing_when_the_metadata_is_in_ram(stack):
    """A partial write of a chunk and a write of its neighbour need the other CRCs of their sector.

    With the region in RAM after the first write, neither reads the lower device.
    """
    original = pattern("original", 2 * DATA_SECTORS)
    written_and_flushed(stack, FIRST, original)
    before = lower_reads(stack)
    one = pattern("one", 1)
    written_and_flushed(stack, FIRST + 1, one)
    neighbour = pattern("neighbour", DATA_SECTORS)
    written_and_flushed(stack, FIRST + 2 * DATA_SECTORS, neighbour)
    assert lower_reads(stack) == before
    expected = bytearray(original)
    expected[512:1024] = one
    for index in range(2 * DATA_SECTORS):  # each on its own, so each CRC is checked
        assert stack.upper.read(FIRST + index) == expected[index * 512 :][:512]
    assert stack.upper.read(FIRST + 2 * DATA_SECTORS, DATA_SECTORS) == neighbour


def test_a_read_takes_one_lower_read_when_the_metadata_is_in_ram(stack):
    data = pattern("data", DATA_SECTORS)
    written_and_flushed(stack, FIRST, data)
    before = lower_reads(stack)
    assert stack.upper.read(FIRST, DATA_SECTORS) == data
    assert lower_reads(stack) == before + 1


def test_a_region_is_read_once(make_stack):
    """Reads of many chunks of a region read its metadata once, and another region reads its own.

    Five whole regions, so that udev, which reads the end of the device after the resume, keeps away
    from regions 1 and 2.
    """
    stack = make_stack(lower_mib_for_regions(5))
    chunks = [region_sector(1, stack.lower_sectors) + chunk * DATA_SECTORS
              for chunk in range(0, REGION_DATA_SECTORS // DATA_SECTORS, 97)]
    written_then_dropped(stack, [*chunks, region_sector(2, stack.lower_sectors)])
    first = loads(stack)
    for start in chunks:
        stack.upper.read(start, DATA_SECTORS)
    assert loads(stack) == first + 1
    stack.upper.read(region_sector(2, stack.lower_sectors), DATA_SECTORS)
    assert loads(stack) == first + 2


def test_a_suspend_drops_the_metadata(stack):
    written_then_dropped(stack, [FIRST])
    stack.upper.read(FIRST, DATA_SECTORS)
    first = loads(stack)
    stack.upper.read(FIRST, DATA_SECTORS)
    assert loads(stack) == first, "the region was read again without a suspend"
    stack.drop_metadata()
    first = loads(stack)
    stack.upper.read(FIRST, DATA_SECTORS)
    assert loads(stack) == first + 1


def test_the_least_recently_used_region_is_dropped(make_stack):
    """With every area in use, a new region takes the place of the one used longest ago.

    Regions 1 to METADATA_AREAS fill the areas, pushing out what udev read. Region 1 is used again
    just before one more region comes, so region 2 has to go instead.
    """
    last = METADATA_AREAS + 1
    stack = make_stack(lower_mib_for_regions(last + 2))
    written_then_dropped(stack, [region_sector(region, stack.lower_sectors) for region in range(1, last + 1)])

    def read_region(region):
        stack.upper.read(region_sector(region, stack.lower_sectors), DATA_SECTORS)

    for region in range(1, last):
        read_region(region)
    first = loads(stack)
    read_region(1)
    assert loads(stack) == first, "an area was dropped before all were in use"
    read_region(last)
    assert loads(stack) == first + 1
    read_region(1)
    assert loads(stack) == first + 1, "the area used last was dropped"
    read_region(2)
    assert loads(stack) == first + 2, "the area used longest ago is still there"


def test_data_is_right_after_its_region_was_dropped(make_stack):
    """Chunks written in more regions than there are areas read back right once they are read again."""
    regions = METADATA_AREAS + 2
    stack = make_stack(lower_mib_for_regions(regions))

    def start(region):
        return region_sector(region, stack.lower_sectors) + CHUNK * DATA_SECTORS

    for region in range(regions):
        written_and_flushed(stack, start(region), pattern(region, DATA_SECTORS))
    for region in range(regions):
        partial = pattern(f"partial {region}", 1)
        written_and_flushed(stack, start(region) + 3, partial)
    assert loads(stack) > regions, "no area was dropped, so this tested nothing"
    stack.drop_metadata()
    for region in range(regions):
        expected = bytearray(pattern(region, DATA_SECTORS))
        expected[3 * 512 : 4 * 512] = pattern(f"partial {region}", 1)
        for index in range(DATA_SECTORS):
            sector = start(region) + index
            assert stack.upper.read(sector) == expected[index * 512 :][:512], f"region {region}, sector {index}"


def test_the_driver_flushes_by_itself_when_half_the_areas_are_pinned(make_stack):
    """Chunks written back by age in many regions, with no flush from above, pin their areas.

    Fewer regions than METADATA_CROWDED leave the trailing copies unwritten; more make the driver
    flush and write them, and the data reads back right after the metadata is read again. There are
    more regions than areas, so without the flush the write back would wait for an area for ever.
    """
    regions = METADATA_AREAS + 4
    stack = make_stack(lower_mib_for_regions(regions + 2))

    def start(region):
        return region_sector(region, stack.lower_sectors) + CHUNK * DATA_SECTORS

    for region in range(1, METADATA_CROWDED - 2):
        stack.upper.write(start(region), pattern(region, DATA_SECTORS))
    wait_for_write_back()
    assert stack.status()["crowded_flushes"] == 0
    lead, trail = metadata_sectors(start(1), stack.lower_sectors)
    assert stack.lower.read(trail) == bytes(SECTOR_SIZE), "a trailing copy was written with few areas pinned"

    for region in range(METADATA_CROWDED - 2, regions):
        stack.upper.write(start(region), pattern(region, DATA_SECTORS))
    wait_for_write_back()
    assert stack.status()["crowded_flushes"] > 0
    assert stack.lower.read(trail) == stack.lower.read(lead)

    stack.upper.flush()
    stack.drop_metadata()
    for region in range(1, regions):
        assert stack.upper.read(start(region), DATA_SECTORS) == pattern(region, DATA_SECTORS), f"region {region}"

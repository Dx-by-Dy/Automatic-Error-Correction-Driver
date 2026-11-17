"""Helpers shared by the tests: the on-disk layout and direct I/O on block devices."""

import fcntl
import functools
import mmap
import os
import signal
import struct
import subprocess
from dataclasses import dataclass

HANG_FILE = "/run/dcorr-tests.hung"
HANG_EXIT_CODE = 3
KILL_GRACE_SECONDS = 20
FIO_SECONDS = 300

SECTOR_SIZE = 512
DATA_SECTORS = 8
CHUNK_SIZE = DATA_SECTORS * SECTOR_SIZE
CRC_SIZE = 8
# The metadata of a chunk: a CRC per data sector, CHUNKS_PER_METADATA_SECTOR chunks to a sector.
METADATA_ENTRY_SIZE = DATA_SECTORS * CRC_SIZE
CHUNKS_PER_METADATA_SECTOR = SECTOR_SIZE // METADATA_ENTRY_SIZE
# A region: [trailing copy of the metadata of the region before | leading copy of its own | its slots].
# The trailing copy of the last region of a group is in the first region of the group.
REGION_CHUNKS = 1024
REGION_METADATA_SECTORS = REGION_CHUNKS // CHUNKS_PER_METADATA_SECTOR
REGION_DATA_SECTORS = REGION_CHUNKS * DATA_SECTORS
REGION_DATA_OFFSET = 2 * REGION_METADATA_SECTORS
REGION_SECTORS = REGION_DATA_OFFSET + REGION_DATA_SECTORS
# The lower device is a sequence of groups: [header of 1 MiB | whole regions | unused]. The last group may
# be short, with at least MIN_GROUP_REGIONS regions. The slots of a group are cut into 32 columns; the first
# 30 hold the data, in order, the last 2 are kept for parity. A copy of src/dcorr-format.h of its own, so
# that the tests check the layout of the driver.
SUPERBLOCK_SECTORS = 8
SUPERBLOCK_SIZE = SUPERBLOCK_SECTORS * SECTOR_SIZE
BITMAP_BLOCK_SECTORS = 8
BITMAP_BLOCK_SIZE = BITMAP_BLOCK_SECTORS * SECTOR_SIZE
BITMAP_HEADER_SIZE = 32
BITMAP_BLOCK_BITS = (BITMAP_BLOCK_SIZE - BITMAP_HEADER_SIZE) * 8
GROUP_HEADER_SECTORS = 2048
COLUMNS = 32
PARITY_COLUMNS = 2
DATA_COLUMNS = COLUMNS - PARITY_COLUMNS
COLUMN_SLOTS_PER_REGION = REGION_CHUNKS // COLUMNS
REGION_CAPACITY = DATA_COLUMNS * COLUMN_SLOTS_PER_REGION * DATA_SECTORS
MIN_GROUPS = 2
MIN_GROUP_REGIONS = 2
GROUP_SIZES = [16 * 2048 << shift for shift in range(9)]  # 16 MiB to 4 GiB
DEFAULT_GROUP_SECTORS = 1024 * 2048
# The size of a group the tests format with, unless told otherwise: the smallest, so that a device of a few
# tens of MiB has several groups.
GROUP_SECTORS = GROUP_SIZES[0]

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "dcorrsetup")


def group_regions(sectors):
    """Whole regions a group, or a short last one, of this many sectors holds after its header."""
    return max(sectors - GROUP_HEADER_SECTORS, 0) // REGION_SECTORS


def bitmap_blocks(regions):
    """Blocks of one copy of the bitmap of written chunks of a group of this many regions."""
    return -(-regions * REGION_CHUNKS // BITMAP_BLOCK_BITS)


@dataclass(frozen=True)
class Layout:
    """Where everything lies on a lower device of a given size."""

    lower_sectors: int
    group_sectors: int
    groups: int
    group_regions: int
    last_group_regions: int
    capacity: int
    bitmap_blocks: int

    @property
    def group_capacity(self):
        """Logical sectors of a group that is not short."""
        return self.group_regions * REGION_CAPACITY

    @property
    def regions(self):
        return (self.groups - 1) * self.group_regions + self.last_group_regions

    def group_start(self, group):
        """First sector of a group, where its header and its superblock are."""
        return group * self.group_sectors

    def regions_of_group(self, group):
        return self.last_group_regions if group == self.groups - 1 else self.group_regions

    def region_start(self, region):
        group, index = divmod(region, self.group_regions)
        return self.group_start(group) + GROUP_HEADER_SECTORS + index * REGION_SECTORS

    def trail_region(self, region):
        """The region that holds the trailing copy of the metadata of this one, in the same group."""
        group, index = divmod(region, self.group_regions)
        return group * self.group_regions + (index + 1) % self.regions_of_group(group)

    def slot(self, logical):
        """The slot of the chunk of a logical sector, numbered across the regions of the device."""
        group, in_group = divmod(logical, self.group_capacity)
        return group * self.group_regions * REGION_CHUNKS + in_group // DATA_SECTORS

    def data_slots(self, group):
        """Slots of a group in its data columns, its first ones."""
        return self.regions_of_group(group) * COLUMN_SLOTS_PER_REGION * DATA_COLUMNS

    def region_logical(self, region):
        """The logical sector of the first chunk of a region, None if the region holds only parity."""
        group, index = divmod(region, self.group_regions)
        if index * REGION_CHUNKS >= self.data_slots(group):
            return None
        return group * self.group_capacity + index * REGION_CHUNKS * DATA_SECTORS

    def slot_sector(self, slot):
        """First sector of a slot on the lower device."""
        region, index = divmod(slot, REGION_CHUNKS)
        return self.region_start(region) + REGION_DATA_OFFSET + index * DATA_SECTORS

    def lead_bitmap_start(self, group):
        return self.group_start(group) + SUPERBLOCK_SECTORS

    def trail_bitmap_start(self, group):
        """The trailing copy of the bitmap of a group, in the header of the next group."""
        holder = (group + 1) % self.groups
        return self.group_start(holder) + SUPERBLOCK_SECTORS + self.bitmap_blocks * BITMAP_BLOCK_SECTORS

    def dirty_start(self, group):
        return self.group_start(group) + SUPERBLOCK_SECTORS + 2 * self.bitmap_blocks * BITMAP_BLOCK_SECTORS


@functools.cache
def layout(lower_sectors, group_sectors=GROUP_SECTORS):
    """The layout of a lower device, None if it holds fewer than MIN_GROUPS groups."""
    assert group_sectors in GROUP_SIZES, f"{group_sectors} is not a size of a group"
    full, rest = divmod(lower_sectors, group_sectors)
    regions = group_regions(group_sectors)
    last = group_regions(rest)
    short = last >= MIN_GROUP_REGIONS
    groups = full + short
    if groups < MIN_GROUPS:
        return None
    last_regions = last if short else regions
    capacity = ((groups - 1) * regions + last_regions) * REGION_CAPACITY
    return Layout(lower_sectors, group_sectors, groups, regions, last_regions, capacity, bitmap_blocks(regions))


def capacity(lower_sectors, group_sectors=GROUP_SECTORS):
    """Logical size in sectors of a device on top of a lower device of this size."""
    return layout(lower_sectors, group_sectors).capacity


def lower_mib_for_regions(regions, group_sectors=GROUP_SECTORS):
    """The smallest lower device in MiB with at least this many regions, every one holding data."""
    mib = 1
    while True:
        device = layout(mib * 2048, group_sectors)
        if device and device.regions >= regions and all(device.region_logical(r) is not None for r in range(regions)):
            return mib
        mib += 1


def lower_mib_for_capacity(mib, group_sectors=GROUP_SECTORS):
    """The smallest lower device in MiB whose device on top holds at least this many MiB."""
    lower = mib
    while not layout(lower * 2048, group_sectors) or capacity(lower * 2048, group_sectors) < mib * 2048:
        lower += 1
    return lower


def region_sector(region, lower_sectors, group_sectors=GROUP_SECTORS):
    """The logical sector of the first chunk of a region."""
    logical = layout(lower_sectors, group_sectors).region_logical(region)
    assert logical is not None, f"region {region} holds no data"
    return logical


def physical_sector(logical, lower_sectors, group_sectors=GROUP_SECTORS):
    """Sector on the lower device that holds a logical data sector."""
    device = layout(lower_sectors, group_sectors)
    return device.slot_sector(device.slot(logical)) + logical % DATA_SECTORS


def metadata_sector(logical, lower_sectors, group_sectors=GROUP_SECTORS):
    """Sector on the lower device that holds the leading copy of the CRCs for a logical data sector,
    among other chunks."""
    device = layout(lower_sectors, group_sectors)
    region, index = divmod(device.slot(logical), REGION_CHUNKS)
    return device.region_start(region) + REGION_METADATA_SECTORS + index // CHUNKS_PER_METADATA_SECTOR


def trail_sector(logical, lower_sectors, group_sectors=GROUP_SECTORS):
    """Sector on the lower device that holds the trailing copy of the CRCs for a logical data sector."""
    device = layout(lower_sectors, group_sectors)
    region, index = divmod(device.slot(logical), REGION_CHUNKS)
    return device.region_start(device.trail_region(region)) + index // CHUNKS_PER_METADATA_SECTOR


def metadata_sectors(logical, lower_sectors, group_sectors=GROUP_SECTORS):
    """Both copies of the metadata sector of a logical data sector: the leading one, then the trailing one."""
    return metadata_sector(logical, lower_sectors, group_sectors), trail_sector(logical, lower_sectors, group_sectors)


def metadata_offset(logical):
    """Offset in bytes of the entry of the chunk of a logical sector in its metadata sector.

    A group adds a multiple of CHUNKS_PER_METADATA_SECTOR chunks to the capacity and to the slots, so
    the offset does not depend on the layout."""
    return logical // DATA_SECTORS % CHUNKS_PER_METADATA_SECTOR * METADATA_ENTRY_SIZE


def queue_limit(path, name):
    """A limit of the queue of a block device, from sysfs, as an integer."""
    device = os.path.basename(os.path.realpath(path))
    with open(f"/sys/block/{device}/queue/{name}") as limit:
        return int(limit.read())


def format_device(path, force=False, group_sectors=GROUP_SECTORS):
    """Writes a fresh superblock to a device with dcorrsetup, with groups of the size given."""
    run(TOOL, "format", *(["--force"] if force else []), "--group-size", f"{group_sectors // 2048}M", path)


def table_line(path):
    """The table line of dmsetup for a formatted device, from dcorrsetup."""
    return run(TOOL, "table", path).stdout


CRC64_POLY = 0x42F0E1EBA9EA3693
CRC64_TABLE = []
for _byte in range(256):
    _crc = _byte << 56
    for _ in range(8):
        _crc = (_crc << 1 ^ CRC64_POLY if _crc & 1 << 63 else _crc << 1) & (1 << 64) - 1
    CRC64_TABLE.append(_crc)


def crc64_be(crc, data):
    """crc64_be of the kernel: CRC-64/ECMA-182, no reflection, no final xor, continuing crc."""
    for byte in data:
        crc = CRC64_TABLE[(crc >> 56 ^ byte) & 0xFF] ^ crc << 8 & (1 << 64) - 1
    return crc


BITMAP_LEAD = 0
BITMAP_TRAIL = 1
SALT_OFFSET = 48
SALT_SIZE = 16


def data_crc(salt, logical, data):
    """The CRC of a data sector: over the salt of the device, the logical sector as le64, then the data."""
    return crc64_be(crc64_be(0, salt), struct.pack("<Q", logical) + bytes(data))


def bitmap_block_crc(block, salt):
    """The CRC of a block of the bitmap: over the salt of the device, then over the block with crc zeroed."""
    return crc64_be(crc64_be(0, salt), bytes(8) + bytes(block[8:]))


@dataclass
class BitmapBlock:
    """A block of the bitmap of written chunks, struct dcorr_bitmap_block of src/dcorr-format.h."""

    crc: int
    generation: int
    group: int
    index: int
    role: int
    bits: bytes

    @classmethod
    def parse(cls, data):
        crc, generation, group, index, role = struct.unpack_from("<QQQII", data)
        return cls(crc, generation, group, index, role, bytes(data[BITMAP_HEADER_SIZE:BITMAP_BLOCK_SIZE]))

    def valid(self, salt):
        return self.crc == bitmap_block_crc(self.pack(fix_crc=False), salt)

    def pack(self, salt=None, fix_crc=True):
        """The block as on the device, with the CRC computed from the salt if one is given."""
        data = bytearray(struct.pack("<QQQII", self.crc, self.generation, self.group, self.index, self.role))
        data += self.bits
        if fix_crc and salt is not None:
            struct.pack_into("<Q", data, 0, bitmap_block_crc(data, salt))
        return bytes(data)

    def bit(self, number):
        return bool(self.bits[number // 8] >> (number % 8) & 1)


def bitmap_place(layout, logical):
    """The group of the chunk of a logical sector, its block of the bitmap and its bit in the block."""
    group, in_group = divmod(logical, layout.group_capacity)
    index, bit = divmod(in_group // DATA_SECTORS, BITMAP_BLOCK_BITS)
    return group, index, bit


def bitmap_block_sector(layout, group, index, role):
    """Where a copy of a block of the bitmap of a group lies on the lower device."""
    start = layout.lead_bitmap_start(group) if role == BITMAP_LEAD else layout.trail_bitmap_start(group)
    return start + index * BITMAP_BLOCK_SECTORS


def pattern(seed, sectors):
    """Reproducible data in which every sector differs from all the others."""
    data = bytearray()
    for sector in range(sectors):
        block = f"{seed}:{sector}:".encode() * 64
        data += block[:SECTOR_SIZE].ljust(SECTOR_SIZE, b"#")
    return bytes(data)


def declare_hang(reason):
    """Ends the run at once: stuck I/O never finishes, so no later test could pass.

    Leaves the kernel's view of the hang in its log and tells deploy/vm/guest.sh about it.
    A thread stuck in the kernel keeps this process alive after its exit, which is why the
    wrapper has to be told, and why all descriptors are closed: otherwise the SSH session
    would stay open for as long as the process exists.
    """
    test = os.environ.get("PYTEST_CURRENT_TEST", "no test running")
    message = f"\nHANG in {test}: {reason}\n"
    os.write(2, message.encode())
    for dump in ("w", "t"):  # blocked tasks, then all tasks and the busy workqueues
        with open("/proc/sysrq-trigger", "w") as trigger:
            trigger.write(dump)
    with open(HANG_FILE, "w") as file:
        file.write(message)
    os.closerange(0, 1024)
    os._exit(HANG_EXIT_CODE)


def run(*cmd, timeout=120, check=True, stdin=None):
    """Runs a command in its own process group; a process that survives SIGKILL is a hang."""
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        try:
            process.communicate(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            declare_hang(f"{cmd[0]} is still alive {KILL_GRACE_SECONDS}s after SIGKILL")
        raise
    result = subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


def fio(path, timeout=FIO_SECONDS, **options):
    defaults = {
        "name": "load",
        "filename": path,
        "direct": 1,
        "ioengine": "libaio",
        "group_reporting": 1,
    }
    arguments = [f"--{key}={value}" for key, value in (defaults | options).items()]
    result = run("fio", *arguments, timeout=timeout, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


BLKDISCARD = 0x1277  # _IO(0x12, 119) of <linux/fs.h>
BLKZEROOUT = 0x127F  # _IO(0x12, 127) of <linux/fs.h>


class BlockDevice:
    """Sector-addressed I/O that bypasses the page cache.

    The page cache would hide reads from the driver, and a buffered write to the lower
    device would write back a whole 4 KiB block, damaging the neighbouring sectors.
    """

    def __init__(self, path, readonly=False):
        self.path = path
        self.fd = os.open(path, (os.O_RDONLY if readonly else os.O_RDWR) | os.O_DIRECT)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read(self, sector, count=1):
        """Returns the sectors read, fewer than requested at the end of the device."""
        size = count * SECTOR_SIZE
        with mmap.mmap(-1, _page_aligned(size)) as buffer:
            done = os.preadv(self.fd, [memoryview(buffer)[:size]], sector * SECTOR_SIZE)
            return buffer[:done]

    def write(self, sector, data, flags=0):
        """Writes whole sectors; flags=os.RWF_DSYNC makes it a FUA write."""
        assert len(data) % SECTOR_SIZE == 0, "writes must be whole sectors"
        with mmap.mmap(-1, _page_aligned(len(data))) as buffer:
            buffer[: len(data)] = data
            done = os.pwritev(
                self.fd, [memoryview(buffer)[: len(data)]], sector * SECTOR_SIZE, flags
            )
        assert done == len(data), f"short write: {done} of {len(data)} bytes"

    def discard(self, sector, count):
        """Discards sectors with the BLKDISCARD ioctl, as blkdiscard does; raises OSError if it fails."""
        fcntl.ioctl(self.fd, BLKDISCARD, struct.pack("QQ", sector * SECTOR_SIZE, count * SECTOR_SIZE))

    def zeroout(self, sector, count):
        """Zeroes sectors with the BLKZEROOUT ioctl, as blkdiscard -z does: write zeroes where the device
        has it, ordinary writes of zeros otherwise; raises OSError if it fails."""
        fcntl.ioctl(self.fd, BLKZEROOUT, struct.pack("QQ", sector * SECTOR_SIZE, count * SECTOR_SIZE))

    def flush(self):
        """Makes the writes so far durable; only then are they sure to be on the device below."""
        os.fsync(self.fd)

    def flush_settled(self):
        """A flush after which the driver leaves the device below alone.

        The driver completes a flush once the data is durable, and writes the trailing copy of the
        metadata after that. Its worker takes the second flush only once that is done, so a test
        that looks at the device below or damages it waits for it this way.
        """
        self.flush()
        self.flush()

    def patch(self, sector, offset, data):
        """Replaces bytes inside one sector, leaving the rest of the device untouched."""
        contents = bytearray(self.read(sector))
        contents[offset : offset + len(data)] = data
        assert len(contents) == SECTOR_SIZE, "a patch must stay inside the sector"
        self.write(sector, bytes(contents))

    def flip_bit(self, sector, byte=0, bit=0):
        """Flips one bit of a sector, leaving the rest of the device untouched."""
        data = bytearray(self.read(sector))
        data[byte] ^= 1 << bit
        self.write(sector, bytes(data))


def _page_aligned(size):
    return (size + mmap.PAGESIZE - 1) // mmap.PAGESIZE * mmap.PAGESIZE

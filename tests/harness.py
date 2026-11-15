"""Helpers shared by the tests: the on-disk layout and direct I/O on block devices."""

import functools
import mmap
import os
import signal
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
# A region: [trailing copy of the metadata of the region before | leading copy of its own | its data].
# The trailing copy of the last region is in region 0.
REGION_CHUNKS = 1024
REGION_METADATA_SECTORS = REGION_CHUNKS // CHUNKS_PER_METADATA_SECTOR
REGION_DATA_SECTORS = REGION_CHUNKS * DATA_SECTORS
REGION_DATA_OFFSET = 2 * REGION_METADATA_SECTORS
REGION_SECTORS = REGION_DATA_OFFSET + REGION_DATA_SECTORS
# The lower device: [area, copy 0 | regions 0 .. M - 1 | area, copy 1 | regions M .. R - 1], M = R // 2.
# An area is the header of the superblock and the blocks of the bitmap, rounded up to 1 MiB.
# A copy of src/dcorr-format.h of its own, so that the tests check the layout of the driver.
HEADER_SECTORS = 8
HEADER_SIZE = HEADER_SECTORS * SECTOR_SIZE
BITMAP_BLOCK_SECTORS = 8
BITMAP_BLOCK_BITS = (BITMAP_BLOCK_SECTORS * SECTOR_SIZE - 32) * 8
AREA_ALIGN_SECTORS = 2048
MIN_REGIONS = 2

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "dcorrsetup")


def regions_capacity(sectors):
    """Logical sectors that regions laid out over this many sectors hold: whole regions, and the whole
    chunks that fit into a last short one after its metadata areas."""
    regions, rest = divmod(sectors, REGION_SECTORS)
    last = max(rest - REGION_DATA_OFFSET, 0) // DATA_SECTORS * DATA_SECTORS
    return regions * REGION_DATA_SECTORS + last


def bitmap_blocks(capacity):
    return -(-(capacity // DATA_SECTORS) // BITMAP_BLOCK_BITS)


def area_sectors(capacity):
    sectors = HEADER_SECTORS + bitmap_blocks(capacity) * BITMAP_BLOCK_SECTORS
    return -(-sectors // AREA_ALIGN_SECTORS) * AREA_ALIGN_SECTORS


@dataclass(frozen=True)
class Layout:
    """Where everything lies on a lower device of a given size."""

    lower_sectors: int
    area_sectors: int
    capacity: int
    regions: int
    middle_region: int
    bitmap_blocks: int

    def copy_start(self, copy):
        """First sector of an area of the superblock."""
        return 0 if copy == 0 else self.area_sectors + self.middle_region * REGION_SECTORS

    def region_start(self, region):
        return (
            self.area_sectors
            + region * REGION_SECTORS
            + (self.area_sectors if region >= self.middle_region else 0)
        )


@functools.cache
def layout(lower_sectors):
    """The layout of a lower device, None if it is too small."""
    area = area_sectors(0)
    while True:
        if lower_sectors <= 2 * area:
            return None
        capacity = regions_capacity(lower_sectors - 2 * area)
        if area_sectors(capacity) <= area:
            break
        area = area_sectors(capacity)
    regions = -(-capacity // REGION_DATA_SECTORS)
    if regions < MIN_REGIONS:
        return None
    return Layout(lower_sectors, area, capacity, regions, regions // 2, bitmap_blocks(capacity))


def capacity(lower_sectors):
    """Logical size in sectors of a device on top of a lower device of this size."""
    return layout(lower_sectors).capacity


def lower_mib_for_regions(regions):
    """The smallest lower device in MiB with at least this many whole regions of data."""
    mib = 1
    while not layout(mib * 2048) or capacity(mib * 2048) < regions * REGION_DATA_SECTORS:
        mib += 1
    return mib


def physical_sector(logical, lower_sectors):
    """Sector on the lower device that holds a logical data sector."""
    region, in_region = divmod(logical, REGION_DATA_SECTORS)
    return layout(lower_sectors).region_start(region) + REGION_DATA_OFFSET + in_region


def metadata_sector(logical, lower_sectors):
    """Sector on the lower device that holds the leading copy of the CRCs for a logical data sector,
    among other chunks."""
    region, in_region = divmod(logical, REGION_DATA_SECTORS)
    return (
        layout(lower_sectors).region_start(region)
        + REGION_METADATA_SECTORS
        + in_region // DATA_SECTORS // CHUNKS_PER_METADATA_SECTOR
    )


def trail_sector(logical, lower_sectors):
    """Sector on the lower device that holds the trailing copy of the CRCs for a logical data sector."""
    region, in_region = divmod(logical, REGION_DATA_SECTORS)
    device = layout(lower_sectors)
    holder = 0 if region + 1 == device.regions else region + 1
    return device.region_start(holder) + in_region // DATA_SECTORS // CHUNKS_PER_METADATA_SECTOR


def metadata_sectors(logical, lower_sectors):
    """Both copies of the metadata sector of a logical data sector: the leading one, then the trailing one."""
    return metadata_sector(logical, lower_sectors), trail_sector(logical, lower_sectors)


def metadata_offset(logical):
    """Offset in bytes of the entry of the chunk of a logical sector in its metadata sector."""
    return logical // DATA_SECTORS % CHUNKS_PER_METADATA_SECTOR * METADATA_ENTRY_SIZE


def format_device(path, force=False):
    """Writes a fresh superblock to a device with dcorrsetup."""
    run(TOOL, "format", *(["--force"] if force else []), path)


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


class BlockDevice:
    """Sector-addressed I/O that bypasses the page cache.

    The page cache would hide reads from the driver, and a buffered write to the lower
    device would write back a whole 4 KiB block, damaging the neighbouring sectors.
    """

    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDWR | os.O_DIRECT)

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

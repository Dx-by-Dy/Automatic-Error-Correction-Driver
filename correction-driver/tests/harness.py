"""Helpers shared by the tests: the on-disk layout and direct I/O on block devices."""

import mmap
import os
import signal
import subprocess

HANG_FILE = "/run/corrdm-tests.hung"
HANG_EXIT_CODE = 3
KILL_GRACE_SECONDS = 20
FIO_SECONDS = 300

SECTOR_SIZE = 512
DATA_SECTORS = 8
METADATA_SECTORS = 1
CHUNK_SECTORS = DATA_SECTORS + METADATA_SECTORS
CHUNK_SIZE = DATA_SECTORS * SECTOR_SIZE
CRC_SIZE = 8


def physical_sector(logical):
    """Sector on the lower device that holds a logical data sector."""
    return logical // DATA_SECTORS * CHUNK_SECTORS + logical % DATA_SECTORS


def metadata_sector(logical):
    """Sector on the lower device that holds the CRCs for a logical data sector."""
    return logical // DATA_SECTORS * CHUNK_SECTORS + DATA_SECTORS


def capacity(lower_sectors):
    """Logical size in sectors of a device on top of a lower device of this size."""
    return lower_sectors // CHUNK_SECTORS * DATA_SECTORS


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

    def flip_bit(self, sector, byte=0, bit=0):
        """Flips one bit of a sector, leaving the rest of the device untouched."""
        data = bytearray(self.read(sector))
        data[byte] ^= 1 << bit
        self.write(sector, bytes(data))


def _page_aligned(size):
    return (size + mmap.PAGESIZE - 1) // mmap.PAGESIZE * mmap.PAGESIZE

"""Fixtures: a fresh dcorr device per test, and a check of the kernel log around each test.

Tests run as root in the development VM, see deploy/vm.sh. Each device sits on a small
dm-linear region of the test disk, so zeroing it for every test stays fast.
"""

import errno
import os
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

import pytest

from harness import BlockDevice, capacity, declare_hang, format_device, layout, run

TEST_DISK = "/dev/vdb"
REINIT_DEVICE = "dcorr"
LOWER_NAME = "dcorr-test-lower"
UPPER_NAME = "dcorr-test"
# The crash tests put dm-log-writes between the driver and the lower device, with a log of its own.
LOG_NAME = "dcorr-test-log"
LOG_DEVICE_NAME = "dcorr-test-logdev"
# The tests of lower device errors put dm-dust or dm-flakey there.
FAULTY_NAME = "dcorr-test-faulty"
# Removed in this order, the devices on top first.
TEST_DEVICES = (UPPER_NAME, LOG_NAME, FAULTY_NAME, LOG_DEVICE_NAME, LOWER_NAME)
DEFAULT_LOWER_MIB = 32  # two groups of 16 MiB, the size harness.py formats with

HUNG_TASK_SECONDS = 30
TEST_SECONDS = 180
# CACHE_AGE_MS in src/cache.h, with a margin.
WRITE_BACK_SECONDS = 3
SLOW_TEST_SECONDS = 600

KERNEL_REPORT = re.compile(
    r"BUG:|WARNING:|Oops|UBSAN:|blocked for more than|Kernel panic|possible circular locking"
)

# Bugs already recorded in TODO.md. They are listed after the run and do not fail a test;
# any other report does. Delete an entry when its bug is fixed.
KNOWN_KERNEL_REPORTS = {
}

known_report_counts = {}
kernel_log_overruns = 0


def dmsetup_remove(name):
    run("dmsetup", "remove", "--retry", name, check=False)


def device_exists(name):
    return run("dmsetup", "info", name, check=False).returncode == 0


STATUS_FIELDS = (
    "map_waits",
    "free_waits",
    "busy_waits",
    "read_waits",
    "dirty",
    "failed",
    "metadata_loads",
    "metadata_waits",
    "trail_errors",
    "crowded_flushes",
    "barriers",
    "settle_reads",
    "settle_mismatches",
    "unwritten_reads",
    "read_only_blocks",
    "single_blocks",
    "bad_superblocks",
    "bitmap_write_errors",
    "refused_writes",
    "discards",
    "discarded_chunks",
)


def device_status(name=UPPER_NAME):
    """The counters of the driver in dmsetup status, see dm_status in dm-dcorr.c.

    map_waits: reads that waited in dm_map for a place among the parts in flight;
    free_waits: writes that waited for a free entry of the cache;
    busy_waits: writes that waited for an entry under write back;
    read_waits: reads of the lower device that waited for the write back of their chunk;
    dirty: entries with data not yet on the lower device; failed: entries whose write back failed;
    metadata_loads: metadata areas of regions read from the lower device;
    metadata_waits: waits for a metadata area to be let go, as all were in use;
    trail_errors: sectors of the trailing copy of the metadata that failed to write;
    crowded_flushes: flushes the driver made by itself, as too many metadata areas were busy;
    barriers: flushes it made before writing back a chunk written back since the last flush;
    settle_reads: chunks it read before a write back, as their two copies of the metadata differed;
    settle_mismatches: sectors so read that matched neither copy, or did not read;
    unwritten_reads: chunks read as zeros without a read of the lower device, as never written;
    read_only_blocks: blocks of the bitmap invalid in both copies when the device was created;
    single_blocks: blocks of the bitmap with one valid copy then, repaired by the next flush;
    bad_superblocks: copies of the superblock of groups 2 and on that are invalid or differ;
    bitmap_write_errors: copies of blocks of the bitmap that failed to write;
    refused_writes: writes and discards refused in the range of a block invalid in both copies;
    discards: discards that reached the target, those covering no whole chunk among them;
    discarded_chunks: whole chunks they covered, which read as zeros since.
    """
    fields = run("dmsetup", "status", name).stdout.split()
    assert fields[2] == "dcorr", fields
    return dict(zip(STATUS_FIELDS, map(int, fields[3:]), strict=True))


def wait_for_write_back(name=UPPER_NAME, seconds=WRITE_BACK_SECONDS):
    """Waits until the cache has written everything back by age, without a flush."""
    deadline = time.monotonic() + seconds
    while device_status(name)["dirty"]:
        assert time.monotonic() < deadline, "the cache did not write back by age"
        time.sleep(0.1)


def drop_metadata(name=UPPER_NAME):
    """Makes the driver forget the metadata it keeps in RAM, as a suspend does.

    A test that changes metadata on the lower device needs it, or the driver goes on with the copy.
    After the resume udev reads the start and the end of the device, which reads the metadata of
    the first region and of the last one again, and of the one before it when the end of the device is
    near the start of the last region; the other regions stay out of RAM.
    """
    run("dmsetup", "suspend", name)
    run("dmsetup", "resume", name)
    run("udevadm", "settle")


def pytest_terminal_summary(terminalreporter):
    if known_report_counts:
        terminalreporter.section("known kernel reports, see TODO.md")
        for item, count in sorted(known_report_counts.items()):
            terminalreporter.write_line(f"{count:5} {item}")
    if kernel_log_overruns:
        terminalreporter.write_line(
            f"Kernel log overran {kernel_log_overruns} times, some reports may have been missed",
            yellow=True,
        )


@pytest.fixture(scope="session", autouse=True)
def environment():
    """Refuses to run outside the VM and frees the test disk."""
    if subprocess.run(["systemd-detect-virt", "--vm", "--quiet"]).returncode != 0:
        pytest.exit("not a virtual machine, refusing to overwrite the test disk", returncode=2)
    if os.geteuid() != 0:
        pytest.exit("the tests must run as root", returncode=2)
    if "dcorr" not in run("dmsetup", "targets").stdout:
        pytest.exit("the dcorr target is not loaded, run: deploy/vm.sh reinit", returncode=2)
    for name in (*TEST_DEVICES, REINIT_DEVICE):
        if device_exists(name):
            dmsetup_remove(name)
    # Report stuck tasks soon and every time, so a hang is in the log before the test gives up.
    run("sysctl", f"kernel.hung_task_timeout_secs={HUNG_TASK_SECONDS}", "kernel.hung_task_warnings=-1")


@pytest.fixture(autouse=True)
def watchdog(request):
    """Declares a hang when a test overruns, even with its main thread stuck in the kernel."""
    limit = SLOW_TEST_SECONDS if request.node.get_closest_marker("slow") else TEST_SECONDS
    timer = threading.Timer(limit, declare_hang, [f"the test is still running after {limit}s"])
    timer.daemon = True
    timer.start()
    yield
    timer.cancel()


@pytest.fixture(autouse=True)
def kernel_log(watchdog):
    """Fails the test on a kernel report that TODO.md does not know about."""
    fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    os.lseek(fd, 0, os.SEEK_END)
    yield
    unknown = []
    for message in read_kmsg(fd):
        if not KERNEL_REPORT.search(message):
            continue
        for item, known in KNOWN_KERNEL_REPORTS.items():
            if known.search(message):
                known_report_counts[item] = known_report_counts.get(item, 0) + 1
                break
        else:
            unknown.append(message)
    os.close(fd)
    assert not unknown, "kernel reports:\n" + "\n".join(unknown)


@contextmanager
def kernel_messages():
    """Collects into a list the kernel messages logged while the block runs."""
    fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    os.lseek(fd, 0, os.SEEK_END)
    messages = []
    try:
        yield messages
    finally:
        messages.extend(read_kmsg(fd))
        os.close(fd)


def read_kmsg(fd):
    global kernel_log_overruns
    while True:
        try:
            record = os.read(fd, 8192).decode(errors="replace")
        except OSError as error:
            if error.errno == errno.EAGAIN:
                return
            if error.errno == errno.EPIPE:  # the ring buffer overran our position
                kernel_log_overruns += 1
                continue
            raise
        yield record.partition(";")[2].partition("\n")[0]


@dataclass
class Stack:
    """A dcorr device on top of a fresh, zeroed and formatted lower device."""

    lower_sectors: int
    lower_path: str
    upper_path: str
    table: str
    lower: BlockDevice | None = None
    upper: BlockDevice | None = None

    @property
    def sectors(self):
        return capacity(self.lower_sectors)

    @property
    def lower_layout(self):
        return layout(self.lower_sectors)

    def status(self):
        return device_status()

    def drop_metadata(self):
        drop_metadata()

    def map_waits(self):
        """How many times the driver made a read wait for a place among the parts in flight."""
        return self.status()["map_waits"]

    def open(self):
        self.lower = BlockDevice(self.lower_path)
        self.upper = BlockDevice(self.upper_path)

    def close(self):
        for device in (self.upper, self.lower):
            if device:
                device.close()

    def recreate_upper(self):
        """Removes the dcorr device and creates it again on the same data."""
        self.upper.close()
        dmsetup_remove(UPPER_NAME)
        run("dmsetup", "create", UPPER_NAME, stdin=self.table)
        self.upper = BlockDevice(self.upper_path)


def create_dcorr(path, lower_sectors, format=True):
    """Puts the driver on a device as UPPER_NAME, formatting the device first unless told otherwise."""
    if format:
        format_device(path)
    run("dmsetup", "create", UPPER_NAME, stdin=f"0 {capacity(lower_sectors)} dcorr {path}\n")


def make_lower(sectors, name=LOWER_NAME, offset_mib=0):
    """A zeroed dm-linear region of the test disk, at the start unless told otherwise."""
    run("dmsetup", "create", name, stdin=f"0 {sectors} linear {TEST_DISK} {offset_mib * 2048}\n")
    path = f"/dev/mapper/{name}"
    # Direct, so that nothing of this stays in the page cache of the test disk.
    run("dd", "if=/dev/zero", f"of={path}", "bs=1M", "oflag=direct", "iflag=count_bytes", f"count={sectors * 512}")
    return path


@pytest.fixture
def make_stack():
    """Creates a device of the requested size; for the usual size use `stack`."""
    stacks = []

    def create(lower_mib=DEFAULT_LOWER_MIB):
        sectors = lower_mib * 2048
        lower_path = make_lower(sectors)
        format_device(lower_path)
        table = f"0 {capacity(sectors)} dcorr {lower_path}\n"
        run("dmsetup", "create", UPPER_NAME, stdin=table)
        stack = Stack(sectors, lower_path, f"/dev/mapper/{UPPER_NAME}", table)
        stack.open()
        stacks.append(stack)
        return stack

    yield create

    for stack in stacks:
        stack.close()
    dmsetup_remove(UPPER_NAME)
    dmsetup_remove(LOWER_NAME)


@pytest.fixture
def stack(make_stack):
    return make_stack()

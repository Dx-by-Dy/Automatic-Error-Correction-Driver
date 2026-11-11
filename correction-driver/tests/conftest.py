"""Fixtures: a fresh corrdm device per test, and a check of the kernel log around each test.

Tests run as root in the development VM, see deploy/vm.sh. Each device sits on a small
dm-linear region of the test disk, so zeroing it for every test stays fast.
"""

import errno
import os
import re
import subprocess
import threading
from dataclasses import dataclass

import pytest

from harness import BlockDevice, capacity, declare_hang, run

TEST_DISK = "/dev/vdb"
REINIT_DEVICE = "corrdm"
LOWER_NAME = "corrdm-test-lower"
UPPER_NAME = "corrdm-test"
# The crash tests put dm-log-writes between the driver and the lower device, with a log of its own.
LOG_NAME = "corrdm-test-log"
LOG_DEVICE_NAME = "corrdm-test-logdev"
# The tests of lower device errors put dm-dust or dm-flakey there.
FAULTY_NAME = "corrdm-test-faulty"
# Removed in this order, the devices on top first.
TEST_DEVICES = (UPPER_NAME, LOG_NAME, FAULTY_NAME, LOG_DEVICE_NAME, LOWER_NAME)
DEFAULT_LOWER_MIB = 16

HUNG_TASK_SECONDS = 30
TEST_SECONDS = 180
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


STATUS_FIELDS = ("map_waits", "free_waits", "busy_waits", "dirty", "failed")


def device_status(name=UPPER_NAME):
    """The counters of the driver in dmsetup status, see dm_status in corrdm.c.

    map_waits: reads that waited in dm_map for a place among the parts in flight;
    free_waits: writes that waited for a free entry of the cache;
    busy_waits: writes that waited for an entry under write back;
    dirty: entries with data not yet on the lower device; failed: entries whose write back failed.
    """
    fields = run("dmsetup", "status", name).stdout.split()
    assert fields[2] == "corrdm", fields
    return dict(zip(STATUS_FIELDS, map(int, fields[3:]), strict=True))


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
    if "corrdm" not in run("dmsetup", "targets").stdout:
        pytest.exit("the corrdm target is not loaded, run: deploy/vm.sh reinit", returncode=2)
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
    """A corrdm device on top of a fresh, zeroed lower device."""

    lower_sectors: int
    lower_path: str
    upper_path: str
    table: str
    lower: BlockDevice | None = None
    upper: BlockDevice | None = None

    @property
    def sectors(self):
        return capacity(self.lower_sectors)

    def status(self):
        return device_status()

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
        """Removes the corrdm device and creates it again on the same data."""
        self.upper.close()
        dmsetup_remove(UPPER_NAME)
        run("dmsetup", "create", UPPER_NAME, stdin=self.table)
        self.upper = BlockDevice(self.upper_path)


def make_lower(sectors, name=LOWER_NAME, offset_mib=0):
    """A zeroed dm-linear region of the test disk, at the start unless told otherwise."""
    run("dmsetup", "create", name, stdin=f"0 {sectors} linear {TEST_DISK} {offset_mib * 2048}\n")
    path = f"/dev/mapper/{name}"
    # Direct, so that nothing of this stays in the page cache of the test disk.
    run("dd", "if=/dev/zero", f"of={path}", "bs=1M", "oflag=direct", f"count={sectors // 2048}")
    return path


@pytest.fixture
def make_stack():
    """Creates a device of the requested size; for the usual size use `stack`."""
    stacks = []

    def create(lower_mib=DEFAULT_LOWER_MIB):
        sectors = lower_mib * 2048
        lower_path = make_lower(sectors)
        table = f"0 {sectors} corrdm {lower_path}\n"
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

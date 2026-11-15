"""I/O when memory is short: failed allocations in the driver, and the limit on parts in flight.

Failures come from the kernel's fault injection, limited to one thread and to allocations whose
stack passes through given code, so nothing else in the system is affected.
"""

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import FAULTY_NAME, LOWER_NAME, UPPER_NAME, device_status, dmsetup_remove, make_lower
from harness import DATA_SECTORS, REGION_DATA_SECTORS, BlockDevice, declare_hang, fio, pattern, run

FAULTS = "/sys/kernel/debug"
IO_SECONDS = 15
RECOVERY_SECONDS = 30
STUCK = object()

SECTORS = 64 * DATA_SECTORS

# MAX_PARTS_IN_FLIGHT in src/dm-dcorr.h.
MAX_PARTS_IN_FLIGHT = 4096
LIMIT_LOWER_MIB = 64
LIMIT_READ_MIB = 32
LIMIT_SECONDS = 3
READ_DELAY_MS = 100
# A part gives its place back just before its bio completes, so the device may count a few more for a moment.
COMPLETING = 64


def text_symbols():
    symbols = []
    with open("/proc/kallsyms") as kallsyms:
        for line in kallsyms:
            fields = line.split()
            symbols.append((int(fields[0], 16), fields[1], fields[2], fields[3:]))
    return sorted(symbols, key=lambda symbol: symbol[0])


def function_range(name):
    """The addresses of a kernel or driver function, up to the next symbol."""
    symbols = text_symbols()
    for index, (address, _, symbol, _) in enumerate(symbols):
        if symbol == name:
            return address, symbols[index + 1][0]
    pytest.fail(f"no symbol {name}")


def driver_range():
    """The addresses of the code of the driver."""
    addresses = [
        address
        for address, kind, _, module in text_symbols()
        if kind in "tT" and module == ["[dm_dcorr]"]
    ]
    return min(addresses), max(addresses) + 4096


def write_attribute(fault, name, value):
    with open(f"{FAULTS}/{fault}/{name}", "w") as file:
        file.write(str(value))


class Injection:
    """Makes allocations fail for a thread doing I/O."""

    def __init__(self):
        self.armed = []
        self.thread = None

    def arm(self, fault, code_range, interval=1, times=1, this_thread=True):
        """Fails `times` allocations, each the `interval`-th one whose stack passes `code_range`.

        The kernel keeps counting across tests, so an interval picks a varying allocation. Writes
        allocate in the worker of the cache, not in the thread that writes, so for them
        this_thread=False fails the allocations of any task, still only through `code_range`.
        """
        settings = {
            "require-start": code_range[0],
            "require-end": code_range[1],
            "ignore-gfp-wait": "N",
            "task-filter": "Y" if this_thread else "N",
            "verbose": 0,
            "interval": interval,
            "times": times,
            "probability": 100,
        }
        if fault == "fail_page_alloc":
            settings = {"min-order": 0, "ignore-gfp-highmem": "N"} | settings
        for name, value in settings.items():
            write_attribute(fault, name, value)
        self.armed.append(fault)

    def fired(self, fault):
        """Whether all the failures asked for have happened."""
        with open(f"{FAULTS}/{fault}/times") as file:
            return int(file.read()) == 0

    def disarm(self):
        for fault in self.armed:
            write_attribute(fault, "probability", 0)
            write_attribute(fault, "times", 0)
        self.armed = []

    def run(self, io):
        """Returns the result of `io` or its OSError, or STUCK if it does not finish in time."""
        outcome = []

        def body():
            with open("/proc/thread-self/make-it-fail", "w") as file:
                file.write("1")
            try:
                outcome.append(io())
            except OSError as error:
                outcome.append(error)

        self.thread = threading.Thread(target=body, daemon=True)
        self.thread.start()
        self.thread.join(IO_SECONDS)
        return outcome[0] if outcome else STUCK

    def finish(self):
        """With failures off, all stuck I/O must end; otherwise no later test could pass."""
        self.disarm()
        if self.thread:
            self.thread.join(RECOVERY_SECONDS)
            if self.thread.is_alive():
                declare_hang(f"I/O is stuck {RECOVERY_SECONDS}s after the failed allocations ended")


@pytest.fixture
def injection():
    """Request it after `stack`, so that I/O has ended before the device goes away."""
    current = Injection()
    yield current
    current.finish()


def write_and_flush(device, data):
    device.write(0, data)
    device.flush()


def written_and_flushed(stack, data):
    """The data on the lower device, so that reads go through the driver to it."""
    write_and_flush(stack.upper, data)


@pytest.mark.parametrize("operation", ["read", "write"])
def test_io_takes_nothing_from_slab_in_the_driver(stack, injection, operation):
    """Every slab allocation whose stack passes the driver fails, and the request must not notice."""
    old, new = pattern(1, SECTORS), pattern(2, SECTORS)
    written_and_flushed(stack, old)
    injection.arm("failslab", driver_range(), times=-1, this_thread=operation == "read")
    if operation == "write":
        outcome = injection.run(lambda: write_and_flush(stack.upper, new))
        assert not isinstance(outcome, OSError), outcome
        expected = new
    else:
        outcome = injection.run(lambda: stack.upper.read(0, SECTORS))
        assert outcome == old
        expected = old
    injection.disarm()
    assert stack.upper.read(0, SECTORS) == expected


@pytest.mark.slow
def test_write_goes_on_with_only_the_bio_reserve(stack, injection):
    """All new bios of this thread fail, as when memory is short, so only the reserves are left.

    A write takes more bios than the reserve of the driver holds, and it must still finish.
    """
    injection.arm("failslab", function_range("bio_alloc_bioset"), times=-1)
    outcome = injection.run(lambda: stack.upper.write(0, pattern(1, 2048)))
    assert outcome is not STUCK
    assert not isinstance(outcome, OSError), outcome


def test_ordinary_load_does_not_wait(stack):
    """16 requests of 128 KiB at a time are 512 parts, far below the limit, so none waits for it."""
    fio(stack.upper_path, rw="randrw", bs="128k", size="8m", iodepth=16, time_based=1, runtime=5)
    assert stack.map_waits() == 0


@pytest.fixture
def slow_reads():
    """The driver on dm-delay, which holds every read of the lower device back READ_DELAY_MS.

    The metadata of the regions read is in RAM first: a read waits in dm_map for the metadata of its
    region, so with it read late the load would come to the limit only after it.
    """
    sectors = LIMIT_LOWER_MIB * 2048
    lower = make_lower(sectors)
    run("dmsetup", "create", FAULTY_NAME, stdin=f"0 {sectors} delay {lower} 0 {READ_DELAY_MS} {lower} 0 0\n")
    run("dmsetup", "create", UPPER_NAME, stdin=f"0 {sectors} dcorr /dev/mapper/{FAULTY_NAME}\n")
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    for region in range(-(-LIMIT_READ_MIB * 2048 // REGION_DATA_SECTORS)):
        upper.read(region * REGION_DATA_SECTORS)
    upper.close()
    yield f"/dev/mapper/{UPPER_NAME}"
    for name in (UPPER_NAME, FAULTY_NAME, LOWER_NAME):
        dmsetup_remove(name)


def parts_in_flight():
    """Parts of the driver in flight, from the statistics of its device in sysfs.

    Device mapper counts a part from the end of dm_map, once it has its place, to its completion. The
    statistics of dm-delay cannot be used: it counts a bio only once it is sent on after the delay.
    """
    name = os.path.basename(os.path.realpath(f"/dev/mapper/{UPPER_NAME}"))
    with open(f"/sys/block/{name}/inflight") as inflight:
        return sum(int(count) for count in inflight.read().split())


@pytest.mark.slow
def test_parts_in_flight_stay_under_the_limit(slow_reads):
    """fio asks for 32 reads of 1 MiB at a time, 8192 parts, from a lower device that answers late.

    The parts in flight come up to the limit and never pass it, and dm_map waits for places. How much memory the driver takes under load is measured with the baseline, on a kernel
    without KASAN and kmemleak, which hold freed bios back.
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        load = executor.submit(
            fio, slow_reads, rw="read", bs="1m", size=f"{LIMIT_READ_MIB}m", iodepth=32, time_based=1, runtime=LIMIT_SECONDS
        )
        most = 0
        while not load.done():
            most = max(most, parts_in_flight())
            time.sleep(0.02)
        load.result()
    assert most > MAX_PARTS_IN_FLIGHT // 2, f"at most {most} in flight, the load did not reach the limit"
    assert most <= MAX_PARTS_IN_FLIGHT + COMPLETING, f"{most} in flight"
    assert device_status()["map_waits"] > 0

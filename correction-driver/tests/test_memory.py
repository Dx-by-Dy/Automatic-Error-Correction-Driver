"""I/O when memory is short: failed allocations in the driver, and the memory requests hold.

Failures come from the kernel's fault injection, limited to one thread and to allocations whose
stack passes through given code, so nothing else in the system is affected.
"""

import threading
import time

import pytest

from harness import DATA_SECTORS, declare_hang, fio, pattern

FAULTS = "/sys/kernel/debug"
IO_SECONDS = 15
RECOVERY_SECONDS = 30
STUCK = object()

SECTORS = 64 * DATA_SECTORS

MEMORY_FIO_SECONDS = 15
MEMORY_LOWER_MIB = 512
MEMORY_MARGIN_MIB = 512


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
        if kind in "tT" and module == ["[correction_driver]"]
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


@pytest.mark.parametrize("interval", [1, 7, 13, 29, 53])
@pytest.mark.parametrize("operation", ["read", "write"])
def test_failed_page_allocation_does_not_fail_the_io(stack, injection, operation, interval):
    """One metadata page fails to allocate at a varying place, and the reserve must take its place.

    A request of 64 chunks takes 64 pages, so every interval here lands within it.
    """
    old, new = pattern(1, SECTORS), pattern(2, SECTORS)
    written_and_flushed(stack, old)
    injection.arm(
        "fail_page_alloc", function_range("trn_p_rq_init"), interval=interval, this_thread=operation == "read"
    )
    if operation == "write":
        outcome = injection.run(lambda: write_and_flush(stack.upper, new))
        assert not isinstance(outcome, OSError), outcome
        expected = new
    else:
        outcome = injection.run(lambda: stack.upper.read(0, SECTORS))
        assert outcome == old
        expected = old
    assert injection.fired("fail_page_alloc"), "no allocation failed, so this tested nothing"
    injection.disarm()
    assert stack.upper.read(0, SECTORS) == expected


def test_write_goes_on_with_only_the_page_reserve(stack, injection):
    """All new metadata pages of this thread fail, so only the reserve of the driver is left.

    A write of 1 MiB takes 256 pages, more than the reserve holds, so parts must wait for pages
    that others give back, and it must still finish.
    """
    data = pattern(1, 2048)
    injection.arm("fail_page_alloc", function_range("trn_p_rq_init"), times=-1, this_thread=False)
    outcome = injection.run(lambda: write_and_flush(stack.upper, data))
    assert outcome is not STUCK
    assert not isinstance(outcome, OSError), outcome
    assert injection.run(lambda: stack.upper.read(0, 2048)) == data


@pytest.mark.slow
def test_write_goes_on_with_only_the_bio_reserve(stack, injection):
    """All new bios of this thread fail, as when memory is short, so only the reserves are left.

    A write takes more bios than the reserve of the driver holds, and it must still finish.
    """
    injection.arm("failslab", function_range("bio_alloc_bioset"), times=-1)
    outcome = injection.run(lambda: stack.upper.write(0, pattern(1, 2048)))
    assert outcome is not STUCK
    assert not isinstance(outcome, OSError), outcome


def available_kib():
    with open("/proc/meminfo") as meminfo:
        for line in meminfo:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    pytest.fail("no MemAvailable")


def test_ordinary_load_does_not_wait(stack):
    """16 requests of 128 KiB at a time are 512 parts, far below the limit, so none waits for it."""
    fio(stack.upper_path, rw="randrw", bs="128k", size="8m", iodepth=16, time_based=1, runtime=5)
    assert stack.map_waits() == 0


def memory_taken_mib(path):
    """How far the available memory falls under a load of many large requests."""
    before = available_kib()
    load = threading.Thread(
        target=fio,
        args=(path,),
        kwargs={
            "rw": "write",
            "bs": "1m",
            "size": "256m",
            "numjobs": 8,
            "iodepth": 128,
            "time_based": 1,
            "runtime": MEMORY_FIO_SECONDS,
        },
    )
    load.start()
    lowest = before
    while load.is_alive():
        lowest = min(lowest, available_kib())
        time.sleep(0.2)
    load.join()
    return (before - lowest) // 1024


# TODO.md: test_memory_of_requests_in_flight_is_limited is unstable
@pytest.mark.unstable
@pytest.mark.slow
def test_memory_of_requests_in_flight_is_limited(make_stack):
    """fio takes the same memory on either device, so the difference is what the driver holds.

    The load is far above the size of the cache, so writes must have waited for free entries.
    """
    stack = make_stack(MEMORY_LOWER_MIB)
    on_lower = memory_taken_mib(stack.lower_path)
    time.sleep(3)
    on_upper = memory_taken_mib(stack.upper_path)
    assert on_upper - on_lower < MEMORY_MARGIN_MIB, f"lower {on_lower} MiB, upper {on_upper} MiB"
    assert stack.status()["free_waits"] > 0

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

    def arm(self, fault, code_range, interval=1, times=1):
        """Fails `times` allocations, each the `interval`-th one whose stack passes `code_range`.

        The kernel keeps counting across tests, so an interval picks a varying allocation.
        """
        settings = {
            "require-start": code_range[0],
            "require-end": code_range[1],
            "ignore-gfp-wait": "N",
            "task-filter": "Y",
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


@pytest.mark.known_hang
def test_failed_first_allocation_keeps_the_bio(stack, injection):
    """TODO.md: "A failed allocation of req loses the bio". The first allocation is req."""
    injection.arm("failslab", driver_range())
    outcome = injection.run(lambda: stack.upper.read(0, DATA_SECTORS))
    assert outcome is not STUCK


@pytest.mark.xfail(strict=True, reason="TODO.md: A failed allocation of req loses the bio")
@pytest.mark.parametrize("fault", ["failslab", "fail_page_alloc"])
@pytest.mark.parametrize("operation", ["read", "write"])
def test_failed_allocation_does_not_fail_the_io(stack, injection, fault, operation):
    """Only allocations for the parts fail, so this does not lose the bio as the test above."""
    old, new = pattern(1, SECTORS), pattern(2, SECTORS)
    stack.upper.write(0, old)
    injection.arm(fault, function_range("trn_p_rq_init"))
    if operation == "write":
        outcome = injection.run(lambda: stack.upper.write(0, new))
        assert not isinstance(outcome, OSError), outcome
        assert stack.upper.read(0, SECTORS) == new
    else:
        assert injection.run(lambda: stack.upper.read(0, SECTORS)) == old


@pytest.mark.parametrize("interval", [1, 7, 13, 29, 53, 97])
@pytest.mark.parametrize("operation", ["read", "write"])
def test_failed_allocation_leaves_the_device_usable(stack, injection, operation, interval):
    """Fails one allocation at a varying place: the request is correct, or reports an error.

    Several parts of the request may be in flight then, which the error path has to wind down.
    """
    old, new = pattern(1, SECTORS), pattern(2, SECTORS)
    stack.upper.write(0, old)
    injection.arm("failslab", function_range("trn_p_rq_init"), interval=interval)
    if operation == "write":
        outcome = injection.run(lambda: stack.upper.write(0, new))
    else:
        outcome = injection.run(lambda: stack.upper.read(0, SECTORS))
    assert outcome is not STUCK
    assert injection.fired("failslab"), "no allocation failed, so this tested nothing"
    injection.disarm()

    after = stack.upper.read(0, SECTORS)
    if operation == "read":
        assert after == old
        assert isinstance(outcome, OSError) or outcome == old
    elif not isinstance(outcome, OSError):
        assert after == new


@pytest.mark.slow
@pytest.mark.xfail(strict=True, reason="TODO.md: Several bios from one bioset in one context")
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


@pytest.mark.slow
@pytest.mark.xfail(strict=True, reason="TODO.md: No limit on requests in flight")
def test_memory_of_requests_in_flight_is_limited(make_stack):
    """fio takes the same memory on either device, so the difference is what the driver holds."""
    stack = make_stack(MEMORY_LOWER_MIB)
    on_lower = memory_taken_mib(stack.lower_path)
    time.sleep(3)
    on_upper = memory_taken_mib(stack.upper_path)
    assert on_upper - on_lower < MEMORY_MARGIN_MIB, f"lower {on_lower} MiB, upper {on_upper} MiB"

"""The device and the module come and go cleanly, also with I/O in flight."""

import os
import re
import threading
import time
from pathlib import Path

import pytest

from conftest import LOWER_NAME, UPPER_NAME, dmsetup_remove
from harness import fio, run

MODULE = "correction_driver"
MODULE_FILE = Path(__file__).resolve().parents[1] / f"{MODULE}.ko"
KMEMLEAK = "/sys/kernel/debug/kmemleak"
LOAD_MIB = 64
SUSPEND_LOAD_MIB = 480  # with its metadata, within the first 512 MiB of the test disk
CYCLES_PAUSE = 0.2
KMEMLEAK_MIN_AGE_SECONDS = 6
# kmemleak reported a leak only some scans after it, a few seconds apart.
KMEMLEAK_SCAN_SECONDS = 5
KMEMLEAK_SCANS = 3


def verified_load(path, **options):
    """fio that writes the area and checks it back, failing on any I/O error or wrong data."""
    defaults = {
        "rw": "randwrite",
        "bs": "16k",
        "size": f"{LOAD_MIB // 4}m",  # each of the 4 jobs in an area of its own
        "iodepth": 32,
        "numjobs": 4,
        "offset_increment": f"{LOAD_MIB // 4}m",
        "verify": "crc32c",
        "verify_fatal": 1,
        "loops": 3,
    }
    fio(path, **(defaults | options))


def under_load(stack, action, **options):
    """Runs the action over and over while fio writes and verifies, until fio is done.

    Any exception of the load, even one before fio starts, fails the test.
    """
    errors = []

    def load():
        try:
            verified_load(stack.upper_path, **options)
        except BaseException as error:  # reported by the test thread
            errors.append(error)

    thread = threading.Thread(target=load)
    thread.start()
    cycles = 0
    while thread.is_alive():
        action()
        cycles += 1
        time.sleep(CYCLES_PAUSE)
    thread.join()
    if errors:
        raise errors[0]
    return cycles


@pytest.fixture
def loaded(make_stack):
    return make_stack(LOAD_MIB + 8)


@pytest.mark.slow
def test_suspend_and_resume_under_load(make_stack):
    """A suspend waits for the writes in flight, also those that may wait in dm_map for the cache.

    4 jobs of 128 requests of 1 MiB keep 512 MiB in flight, far more than the cache holds, and
    each job has an area of 120 MiB, so that it keeps that many in flight. Whether writes wait for
    a free entry depends on how fast the write back is, so it is not checked here, see TODO.md.
    """

    def suspend_and_resume():
        run("dmsetup", "suspend", UPPER_NAME)
        run("dmsetup", "resume", UPPER_NAME)

    stack = make_stack(SUSPEND_LOAD_MIB + 8)
    area = f"{SUSPEND_LOAD_MIB // 4}m"
    options = {"bs": "1m", "iodepth": 128, "size": area, "offset_increment": area, "loops": 1}
    assert under_load(stack, suspend_and_resume, **options) > 0


@pytest.mark.slow
def test_table_reload_under_load(loaded):
    """A reload builds a new target and destroys the old one, with I/O going on."""

    def reload():
        run("dmsetup", "reload", UPPER_NAME, stdin=loaded.table)
        run("dmsetup", "resume", UPPER_NAME)

    assert under_load(loaded, reload) > 0


def module_loaded():
    return any(line.split()[0] == MODULE for line in run("lsmod").stdout.splitlines()[1:])


def test_module_unloads_only_without_devices(stack):
    assert run("rmmod", MODULE, check=False).returncode != 0, "unloaded under a device"
    assert module_loaded()

    stack.close()
    dmsetup_remove(UPPER_NAME)
    try:
        run("rmmod", MODULE)
        assert not module_loaded()
    finally:
        if not module_loaded():
            run("insmod", str(MODULE_FILE))
    stack.recreate_upper()
    assert stack.upper.read(0, 8) == bytes(8 * 512)


def kmemleak(command):
    with open(KMEMLEAK, "w") as file:
        file.write(command)


def kmemleak_reports_of_the_driver():
    """The objects kmemleak reports with the driver in the stack of their allocation."""
    for _ in range(KMEMLEAK_SCANS):
        kmemleak("scan")
        time.sleep(KMEMLEAK_SCAN_SECONDS)
    with open(KMEMLEAK) as file:
        report = file.read().strip()
    leaks = re.split(r"\n(?=unreferenced object)", report) if report else []
    return [leak for leak in leaks if f"[{MODULE}]" in leak]


RESCUERS = ("kworker/R-transformation_wq", "kworker/R-corrdm_write_back")


def resources_of_the_driver():
    """What a device of the driver holds that can be seen from outside: the rescuer threads of its
    two workqueues. Other kworkers keep the name of the last workqueue they served, so only rescuers
    count. Its tables are small enough for kmalloc, so they are not in /proc/vmallocinfo.
    """
    comms = run("ps", "-eo", "comm").stdout.split()
    return tuple(comms.count(name) for name in RESCUERS)


@pytest.mark.slow
def test_nothing_leaks(make_stack):
    """A device that did I/O leaves nothing behind once removed.

    The workqueues are seen directly, and must be there while the device is. kmemleak looks for
    the rest, but it misses a leaked context and the pages of the cache, which it does not track: freed bios keep a pointer to it
    in their per-bio data, and reused ones still hold it. Checked while the module is loaded, as
    the names of its functions are gone once it is unloaded.
    """
    if not os.path.exists(KMEMLEAK):
        pytest.fail("kmemleak is not available, see KERNEL_ARGS in deploy/vm/config.sh")
    kmemleak("clear")
    before = resources_of_the_driver()
    stack = make_stack(LOAD_MIB + 8)
    verified_load(stack.upper_path, loops=1)
    during = resources_of_the_driver()
    assert all(now > then for now, then in zip(during, before)), (before, during)
    stack.close()
    dmsetup_remove(UPPER_NAME)
    dmsetup_remove(LOWER_NAME)
    assert resources_of_the_driver() == before

    time.sleep(KMEMLEAK_MIN_AGE_SECONDS)  # kmemleak reports only objects older than 5 seconds
    leaks = kmemleak_reports_of_the_driver()
    assert not leaks, "\n\n".join(leaks)

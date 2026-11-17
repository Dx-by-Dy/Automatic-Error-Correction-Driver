"""The arguments and the table of the device mapper target."""

import os

import pytest

from conftest import LOWER_NAME, UPPER_NAME, dmsetup_remove, make_lower
from harness import DATA_SECTORS, BlockDevice, capacity, format_device, pattern, physical_sector, run


@pytest.fixture
def lower():
    sectors = 32 * 2048  # two groups
    path = make_lower(sectors)
    format_device(path)
    yield path, sectors
    dmsetup_remove(UPPER_NAME)
    dmsetup_remove(LOWER_NAME)


def create(table):
    return run("dmsetup", "create", UPPER_NAME, stdin=table + "\n", check=False)


@pytest.mark.parametrize(
    "arguments",
    ["", "{path} extra", "/dev/mapper/no-such-device"],
    ids=["no arguments", "too many arguments", "missing device"],
)
def test_bad_arguments_are_rejected(lower, arguments):
    path, sectors = lower
    assert create(f"0 {sectors} dcorr {arguments.format(path=path)}").returncode != 0


def test_device_takes_the_usable_length(lower):
    path, sectors = lower
    assert create(f"0 {capacity(sectors)} dcorr {path}").returncode == 0
    assert int(run("blockdev", "--getsz", f"/dev/mapper/{UPPER_NAME}").stdout) == capacity(sectors)


@pytest.mark.parametrize("change", [DATA_SECTORS, -DATA_SECTORS], ids=["longer", "shorter"])
def test_a_length_other_than_the_capacity_is_rejected(lower, change):
    path, sectors = lower
    assert create(f"0 {capacity(sectors) + change} dcorr {path}").returncode != 0


def major_minor(path):
    device = os.stat(os.path.realpath(path)).st_rdev
    return f"{os.major(device)}:{os.minor(device)}"


def test_table_shows_the_lower_device(lower):
    """As every target: the lower device as major:minor."""
    path, sectors = lower
    assert create(f"0 {capacity(sectors)} dcorr {path}").returncode == 0
    fields = run("dmsetup", "table", UPPER_NAME).stdout.split()
    assert fields == ["0", str(capacity(sectors)), "dcorr", major_minor(path)]


def test_the_table_loads_again_as_dmsetup_gives_it(lower):
    """A table saved with dmsetup table creates the device again, on the same data."""
    path, sectors = lower
    assert create(f"0 {capacity(sectors)} dcorr {path}").returncode == 0
    data = pattern("saved", DATA_SECTORS)
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    try:
        upper.write(0, data)
        upper.flush()
    finally:
        upper.close()
    saved = run("dmsetup", "table", UPPER_NAME).stdout.strip()
    dmsetup_remove(UPPER_NAME)
    assert create(saved).returncode == 0
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    try:
        assert upper.read(0, DATA_SECTORS) == data
    finally:
        upper.close()


def test_target_may_start_after_sector_0(lower):
    path, sectors = lower
    start = DATA_SECTORS * 8
    table = f"0 {start} zero\n{start} {capacity(sectors)} dcorr {path}"
    assert create(table).returncode == 0
    data = pattern(1, DATA_SECTORS)
    upper = BlockDevice(f"/dev/mapper/{UPPER_NAME}")
    below = BlockDevice(path)
    try:
        upper.write(start, data)
        upper.flush()
        assert below.read(physical_sector(0, sectors), DATA_SECTORS) == data
    finally:
        upper.close()
        below.close()

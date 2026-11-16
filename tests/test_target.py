"""The arguments and the table of the device mapper target."""

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


@pytest.mark.xfail(strict=True, reason="TODO.md: dmsetup table does not show the device")
def test_table_shows_the_lower_device(lower):
    path, sectors = lower
    assert create(f"0 {capacity(sectors)} dcorr {path}").returncode == 0
    fields = run("dmsetup", "table", UPPER_NAME).stdout.split()
    assert len(fields) == 4, fields


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

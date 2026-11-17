"""The arguments and the table of the device mapper target."""

import os

import pytest

from conftest import LOWER_NAME, UPPER_NAME, dmsetup_remove, kernel_messages, make_lower
from harness import (
    DATA_SECTORS,
    SECTOR_SIZE,
    BlockDevice,
    capacity,
    format_device,
    pattern,
    physical_sector,
    queue_limit,
    run,
)


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


def test_the_limits_are_those_of_a_chunk_over_the_lower_device(lower):
    """Sectors of 512 bytes, a chunk as the physical block and the minimal I/O; the limits of the lower
    device that do not depend on the layout stacked; no polling and no stable pages."""
    path, sectors = lower
    assert create(f"0 {capacity(sectors)} dcorr {path}").returncode == 0
    upper = f"/dev/mapper/{UPPER_NAME}"
    chunk = DATA_SECTORS * SECTOR_SIZE
    assert queue_limit(upper, "logical_block_size") == SECTOR_SIZE
    assert queue_limit(upper, "physical_block_size") == chunk
    assert queue_limit(upper, "minimum_io_size") == chunk
    assert queue_limit(upper, "optimal_io_size") == 0
    assert queue_limit(upper, "max_hw_sectors_kb") == queue_limit(path, "max_hw_sectors_kb")
    assert queue_limit(upper, "io_poll") == 0
    assert queue_limit(upper, "stable_writes") == 0


def loop_device(image, sector_size=SECTOR_SIZE):
    return run("losetup", "--find", "--show", "--sector-size", str(sector_size), str(image)).stdout.strip()


def test_a_lower_device_with_4k_logical_blocks_is_refused(tmp_path):
    """The metadata is written in sectors of 512 bytes. The same image, formatted, loads over a loop device
    with sectors of 512 bytes, as a control, and is refused over one with sectors of 4 KiB."""
    sectors = 32 * 2048
    image = tmp_path / "lower.img"
    with open(image, "wb") as file:
        file.truncate(sectors * SECTOR_SIZE)
    table = f"0 {capacity(sectors)} dcorr {{}}"
    loop = loop_device(image)
    try:
        format_device(loop)
        assert create(table.format(loop)).returncode == 0
        dmsetup_remove(UPPER_NAME)
    finally:
        run("losetup", "-d", loop)

    loop = loop_device(image, 4096)
    try:
        assert queue_limit(loop, "logical_block_size") == 4096
        with kernel_messages() as messages:
            assert create(table.format(loop)).returncode != 0
        assert any("logical blocks of 4096 bytes" in message for message in messages), messages
    finally:
        dmsetup_remove(UPPER_NAME)
        run("losetup", "-d", loop)

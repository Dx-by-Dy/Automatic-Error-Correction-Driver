"""fio under load: verified writes on separate areas, and jobs competing for the same chunks."""

import pytest

from harness import SECTOR_SIZE, fio

LOWER_MIB = 512
BLOCK_SIZES = ["512", "4k", "16k", "32k", "64k", "128k", "1m"]

OVERLAP_MIB = 64
OVERLAP_RUNTIME = 20
OVERLAP_IODEPTH = 32


def fio_verify(path, **options):
    fio(path, rw="randwrite", verify="crc32c", do_verify=1, verify_fatal=1, **options)


@pytest.mark.slow
@pytest.mark.parametrize("bs", BLOCK_SIZES)
def test_single_job(make_stack, bs):
    stack = make_stack(LOWER_MIB)
    size = "8m" if bs == "512" else "128m"
    fio_verify(stack.upper_path, bs=bs, size=size, iodepth=16)


@pytest.mark.slow
@pytest.mark.parametrize("bs", BLOCK_SIZES)
def test_parallel_jobs_on_separate_areas(make_stack, bs):
    stack = make_stack(LOWER_MIB)
    fio_verify(
        stack.upper_path,
        bs=bs,
        size="2m" if bs == "512" else "32m",
        offset_increment="48m",
        numjobs=8,
        iodepth=32,
    )


def compete_for_the_same_chunks(make_stack, bs, numjobs, rw):
    """All jobs use the same area, as the competitive benchmarks in the README do.

    Their writes overlap, so fio cannot verify the contents, but each chunk must still hold
    data matching its CRC, as a chunk lock keeps a write's data and CRC together. A read that
    meets a write in a chunk would fail with a CRC mismatch without the lock, and fio reports it.
    """
    stack = make_stack(LOWER_MIB)
    fio(
        stack.upper_path,
        timeout=OVERLAP_RUNTIME + 60,
        rw=rw,
        bs=bs,
        size=f"{OVERLAP_MIB}m",
        numjobs=numjobs,
        iodepth=OVERLAP_IODEPTH,
        time_based=1,
        runtime=OVERLAP_RUNTIME,
    )
    sectors = OVERLAP_MIB * 1024 * 1024 // SECTOR_SIZE
    assert len(stack.upper.read(0, sectors)) == sectors * SECTOR_SIZE


# A request takes one workqueue item per 4 KiB chunk, and the workqueue runs 1024 items at a
# time. These loads stay within that: numjobs * iodepth * chunks per request <= 1024.
@pytest.mark.slow
@pytest.mark.parametrize("rw", ["write", "randwrite"])
@pytest.mark.parametrize("bs,numjobs", [("4k", 8), ("16k", 8), ("4k", 32)], ids=str)
def test_jobs_competing_within_the_worker_limit(make_stack, bs, numjobs, rw):
    compete_for_the_same_chunks(make_stack, bs, numjobs, rw)


# Readers and writers must exclude each other: without that, a read sees the data of a write
# and the CRC from before it.
@pytest.mark.slow
@pytest.mark.parametrize("bs", ["512", "4k", "32k"])
def test_reads_and_writes_competing(make_stack, bs):
    compete_for_the_same_chunks(make_stack, bs, 8, "randrw")


# These loads take more items than the workqueue runs at a time, so they hang if a worker ever
# sleeps on a chunk: the items that would release it stay queued behind the sleeping ones.
@pytest.mark.slow
@pytest.mark.parametrize("rw", ["write", "randwrite"])
@pytest.mark.parametrize("bs,numjobs", [("32k", 8), ("16k", 32), ("1m", 8)], ids=str)
def test_jobs_competing_beyond_the_worker_limit(make_stack, bs, numjobs, rw):
    compete_for_the_same_chunks(make_stack, bs, numjobs, rw)

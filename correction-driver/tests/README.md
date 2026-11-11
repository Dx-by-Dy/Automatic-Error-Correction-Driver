# Driver tests

185 tests in pytest. They run as root in the development VM and refuse to run anywhere else,
as they overwrite `/dev/vdb`. The VM is described in [deploy/README.md](../../deploy/README.md).

Keep this file up to date when adding or removing tests.

## Running

```bash
deploy/vm.sh test                                     # all 185 tests, about 18 minutes
deploy/vm.sh test -m "not slow"                       # the fast ones: 146 tests, about 3 minutes
deploy/vm.sh test -k corruption                       # by name
deploy/vm.sh test test_fio.py::test_single_job -v     # one test
```

`deploy/vm.sh test` copies the working tree to the VM, rebuilds and reloads the driver, then runs
pytest through `deploy/vm/guest.sh`. Logs go to `~/vms/corrdm/logs/`: the test output and the kernel log of the run.

| Exit code | Meaning |
| --------- | ------- |
| 0 | All tests passed or failed as expected |
| 1 | A test failed |
| 3 | A hang: the VM stays stuck for inspection, recover with `deploy/vm.sh reset` |
| 124 | Nothing finished in `CORRDM_TEST_TIMEOUT` (30 minutes), which should not happen |

## How a test runs

**Device.** The `stack` fixture gives each test a new device, `make_stack(lower_mib)` one of a chosen
size. The stack is `corrdm-test` (the driver) on `corrdm-test-lower` (`dm-linear` over the start of
`/dev/vdb`). The lower device is zeroed first, 16 MiB by default. Two files build stacks of their own, with a
third layer between the two: `test_crash.py` puts `dm-log-writes` there (`corrdm-test-log`, its log on
`corrdm-test-logdev` at 256 MiB of `/dev/vdb`), `test_lower_errors.py` puts `dm-dust` or `dm-flakey` there
(`corrdm-test-faulty`).

**I/O.** `BlockDevice` in `harness.py` reads and writes whole sectors with `O_DIRECT`. The page cache
would hide reads from the driver, and a buffered write to the lower device writes a whole 4 KiB block
back, damaging its neighbours. Tests damage data through `stack.lower` and use it through `stack.upper`.
A write through the driver is sure to be on the lower device only after `flush()`, so a test that looks at the
lower device, or damages it, flushes first. A failed write may be reported by the write or by the flush.

**Layout.** `harness.py` has its own copy of the on-disk layout: 8 data sectors, then 1 metadata sector
with 8 CRCs of 8 bytes each. A change of layout has to be made there as well.

**Kernel log.** Each test reads the kernel log it caused. An unknown `BUG`, `WARNING`, `Oops`, KASAN,
UBSAN, lockdep or hung task report fails the test. `KNOWN_KERNEL_REPORTS` in `conftest.py` lists the
reports of bugs already in `TODO.md`: they are counted at the end of the run and do not fail it.
Remove an entry when its bug is fixed.

**Hangs.** A hang ends the whole run, as stuck I/O never finishes and no later test could pass. There
are two ways to detect one, and both print the test name and dump blocked tasks and busy workqueues to
the kernel log (sysrq `w` and `t`):

- a command is still alive 20 seconds after `SIGKILL`, once its timeout has passed;
- the test overruns its limit: 180 seconds, or 600 for `slow` tests. A separate thread watches this,
  so it also works with the test itself stuck in a read.

During the run `kernel.hung_task_timeout_secs` is lowered to 30.

**Markers.** `slow` takes more than a few seconds. `known_hang` hangs the guest and runs only on request.

**Known bugs.** A test for a known bug is a strict `xfail`, with the title of its `TODO.md` item as the
reason: when the bug is fixed the test fails until the mark is removed. A bug that hangs the guest
cannot be `xfail`, as it would end the run, so it gets `known_hang`.

## What is tested

### `test_data.py`: data reads back unchanged and lands where the layout says (76 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_capacity_excludes_metadata` | 1 | The device size is the lower size without metadata |
| `test_fresh_device_reads_zeros` | 1 | A zeroed lower device reads as zeros, without CRC errors |
| `test_roundtrip` | 50 | Write and read back, 10 sizes from 1 to 2048 sectors at 5 start positions |
| `test_data_lands_at_the_layout_position` | 1 | Every sector is at its expected place on the lower device |
| `test_metadata_is_written_outside_the_data` | 1 | The chunk's metadata sector changes, the next chunk's does not |
| `test_partial_write_to_an_empty_chunk` | 8 | A one-sector write, for each sector of a chunk; the rest stays zero |
| `test_partial_write_keeps_the_crcs_of_its_neighbours` | 8 | After a one-sector write, each sector still reads on its own |
| `test_write_across_a_chunk_boundary` | 1 | The write lands correctly, the data around it is intact |
| `test_last_sector_of_the_device` | 1 | The last sector can be written and read |
| `test_read_past_the_end_is_short` | 1 | A read over the end is short, a read beyond it is empty |
| `test_write_past_the_end_fails` | 1 | A write beyond the end gives an error |
| `test_data_survives_recreating_the_device` | 1 | Data and CRCs persist after `dmsetup remove` and `create` |
| `test_random_writes_match_a_reference_copy` | 1 | 1500 random overlapping reads and writes against a copy in memory, fixed seed |

### `test_corruption.py`: damage is detected, and only where it is (28 tests)

Three chunks are written, and the damage is done to the middle one.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_data_corruption_fails_only_that_sector` | 8 | A flipped data bit gives `EIO` for that sector and any read with it; every other sector of the 3 chunks reads correctly |
| `test_any_bit_of_a_sector_is_covered` | 4 | First and last bytes of a sector, lowest and highest bits |
| `test_crc_corruption_fails_only_that_sector` | 8 | A flipped bit in a stored CRC fails only the sector it belongs to |
| `test_zeroed_metadata_is_detected` | 1 | The scenario of the old `tests.py`; the next chunk stays readable |
| `test_unused_metadata_bytes_are_not_checked` | 1 | Damage after the 8 CRCs does not affect reads; documents the format |
| `test_restoring_the_data_clears_the_error` | 1 | No error state is kept in the driver |
| `test_rewriting_a_corrupted_sector_clears_the_error` | 1 | A write of that sector gives it a new, correct CRC |
| `test_write_to_a_neighbour_does_not_hide_corruption` | 1 | A partial write keeps the old CRC of the damaged sector |
| `test_corruption_is_detected_after_recreating_the_device` | 1 | Detection does not depend on driver state |
| `test_zeroed_chunk_is_detected` | 1 | **xfail**: A zeroed chunk passes the check |
| `test_chunk_copied_elsewhere_is_detected` | 1 | **xfail**: The CRC does not depend on the position |

### `test_durability.py`: flushes and FUA writes reach the lower device (7 tests)

Reads the bios queued on `/dev/vdb` from the `block_bio_queue` trace event. A write is durable once it is FUA
or a flush is queued after it, so after an `fsync` no write it caused may be neither.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_the_test_disk_has_a_write_cache` | 1 | Control: `vdb` is `write back`, or the next tests would prove nothing |
| `test_device_reports_a_write_cache_and_fua` | 1 | The device is `write back` with `fua` 1, or the layers above send neither |
| `test_fsync_on_the_lower_device_flushes` | 1 | Control: this way of counting does see flushes |
| `test_fsync_on_the_device_flushes` | 1 | An `fsync` on the device gives a flush on `vdb` after its writes |
| `test_fsync_on_ext4_leaves_nothing_in_the_cache` | 3 | A new file and an `fsync` on ext4 without lazy initialisation: a FUA write is seen (the journal commit) and no write is left unflushed. On the lower device alone it is the control; on the device with 4 KiB blocks the commit block is a whole chunk, with 1 KiB blocks it is part of one, so its metadata is read first |

### `test_crash.py`: the device after a crash (6 tests)

`dm-log-writes` logs every write that reaches the disk below the driver, with its flushes and FUA, in
the order the data reaches the disk itself. `logwrites.py` reads the log and replays a prefix of it to the
zeroed lower device, then the driver is put on it again: that is the device after a crash at that point.
The format is that of `replay-log` from xfstests, which is not needed.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_flushed_writes_survive_a_crash` | 1 | Whole chunks, partial writes and a write across a chunk, each step flushed and marked, then a write left unflushed: at each mark the device holds exactly what was written before it |
| `test_a_write_cut_between_data_and_metadata_reads_old_or_new` | 2 | **xfail**: Data and CRC are not written atomically. A whole chunk and one sector: the replay stops after the first of the two writes of the chunk, and the chunk must read as the old or the new data |
| `test_ext4_survives_a_crash_after_each_fsync` | 2 | `slow`: 8 files on ext4 with 1 KiB and 4 KiB blocks, each with an `fsync` and a mark. At every mark: ext4 mounts, `e2fsck -fn` finds nothing, and each file marked so far is intact |
| `test_ext4_survives_a_crash_at_any_flush` | 1 | `slow`, **xfail**: Data and CRC are not written atomically. The same at every flush and FUA write after `mkfs`. It fails at once: ext4 writes its superblock, part of a chunk, with FUA, and its data reaches the disk before the metadata write is sent |

### `test_lower_errors.py`: the lower device fails (10 tests)

`dm-dust` with 512-byte blocks fails reads of chosen sectors of the lower device, and writes to them a
chosen number of times; a write to such a sector clears it. One test loads `dm-flakey` in its place.
Three chunks are written first, and the middle one gets the failures.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_failed_data_sector_fails_only_its_reads` | 2 | First and last data sector: read one at a time, only that sector fails; a read over all three chunks fails; the first chunk reads correctly |
| `test_failed_metadata_sector_fails_only_its_chunk` | 1 | Every sector of the chunk fails, the other two chunks read |
| `test_device_works_again_once_the_sector_reads` | 1 | A failed data and metadata sector, then cleared: everything reads back, no error state stays in the driver |
| `test_whole_chunk_write_over_a_failed_metadata_sector_needs_no_read` | 1 | The chunk does not read, then a write of it succeeds, as it does not read the old metadata, and the chunk reads back |
| `test_partial_write_fails_when_the_old_metadata_does_not_read` | 1 | The write or its flush fails with `EIO`; the other chunks read. What the chunk holds after it is open |
| `test_failed_write_is_reported` | 3 | The data or the metadata of a whole chunk, the data of one sector fails to write once: the write or its flush fails with `EIO`, the next one succeeds, the other chunks read |
| `test_writes_fail_while_reads_go_on` | 1 | `dm-flakey` with `error_writes`: whole, partial and crossing writes fail, the data from before reads back, and once `dm-linear` is back the device takes writes again |

### `test_lifecycle.py`: the device and the module come and go (4 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_suspend_and_resume_under_load` | 1 | `slow`: `dmsetup suspend` and `resume` over and over while fio writes and verifies 4 areas with 1 MiB requests, enough that parts wait in `dm_map` for a place, which is checked |
| `test_table_reload_under_load` | 1 | `slow`: the same with `dmsetup reload` and `resume`, which builds a new target and destroys the old one |
| `test_module_unloads_only_without_devices` | 1 | `rmmod` fails while a device exists, succeeds without one; loaded again, the device works |
| `test_nothing_leaks` | 1 | `slow`: a device that did I/O, then removed: its lock table in `/proc/vmallocinfo` and the rescuer thread of its workqueue are gone (and were there while it existed), and `kmemleak` reports nothing allocated by the driver |

`kmemleak` does not catch everything here. A context left behind by `dm_dtr` was not reported in a minute of
scans, and showed up only after more devices had come and gone. The likely reason: per-bio data is not cleared
when a bio is allocated again, so bios in the reserves of the bio pools still hold the old `part->dm_ctx`, and
`kmemleak` takes that for a reference. It also reports a leak only a few scans after it, so a leak from an
earlier test of the same boot may show up in this one. The lock table and the workqueue are checked directly
for that reason.

### `test_target.py`: arguments and table of the target (7 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_bad_arguments_are_rejected` | 3 | No arguments, too many, a missing device |
| `test_device_takes_the_usable_length` | 1 | A table with the correct length gives a device of that size |
| `test_too_long_a_device_is_rejected` | 1 | **xfail**: The table length is ignored |
| `test_table_shows_the_lower_device` | 1 | **xfail**: `dmsetup table` does not show the device |
| `test_target_may_start_after_sector_0` | 1 | With a table that puts the target after sector 0, its first sector lands on sector 0 of the lower device |

### `test_filesystem.py`: files survive on a filesystem (2 tests, `slow`)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_file_survives_a_remount` | 2 | ext4 and xfs: a 128 MiB random file keeps its SHA-256 after dropping caches and after a remount |

### `test_fio.py`: load (29 tests, `slow`)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_single_job` | 7 | fio verify, `bs` from 512 bytes to 1 MiB, `iodepth=16` |
| `test_parallel_jobs_on_separate_areas` | 7 | fio verify, the same sizes, 8 jobs at `iodepth=32`, each in its own area |
| `test_jobs_competing_within_the_worker_limit` | 6 | 20 seconds of `write` and `randwrite` on a shared area, `bs`/`numjobs` of `4k/8`, `16k/8`, `4k/32`; then the whole area must read without a CRC error |
| `test_reads_and_writes_competing` | 3 | The same with `randrw`, `bs` of `512`, `4k`, `32k`, 8 jobs: a read that meets a write in a chunk must not get a CRC error |
| `test_jobs_competing_beyond_the_worker_limit` | 6 | The same as the first with `32k/8`, `16k/32`, `1m/8`: more items than the workqueue runs at a time, which hangs if a worker ever sleeps on a chunk |

### `test_memory.py`: I/O when memory is short (16 tests)

Failures come from the kernel's fault injection (`failslab`, `fail_page_alloc`), limited to one thread and to
allocations whose stack passes through given code. How the driver uses memory is in "Memory" in `README.md`.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_io_takes_nothing_from_slab_in_the_driver` | 2 | `read`, `write` of 64 chunks while every slab allocation through the driver fails: no error and correct data |
| `test_failed_page_allocation_does_not_fail_the_io` | 10 | `read`, `write` of 64 chunks with one metadata page failing at a varying place, which must have happened: the reserve takes over, no error and correct data |
| `test_write_goes_on_with_only_the_page_reserve` | 1 | All new metadata pages of the thread fail, and a write of 1 MiB, more pages than the reserve holds, must finish and read back |
| `test_write_goes_on_with_only_the_bio_reserve` | 1 | `slow`: all new bios of the thread fail, and a write of 1 MiB must finish in 15 seconds |
| `test_ordinary_load_does_not_wait` | 1 | `fio` `randrw` with `bs=128k`, `iodepth=16`, at most 512 parts: `dmsetup status` shows no wait for a place among the parts in flight |
| `test_memory_of_requests_in_flight_is_limited` | 1 | `slow`: `fio` with `bs=1m`, 8 jobs, `iodepth=128` takes less than 512 MiB more through the driver than on the lower device, and requests waited for the limit. Measured: 1074 MiB on the lower device, 1052 MiB through the driver, 28833 waits |

## What is not tested yet

Nothing of what stage 1 of `TODO.md` asked for. Suspend and reload under load have no positive control: the
driver has no code for them yet, so no change to it makes them fail but for ones that break everything else
too. They will guard the cache, which has to write back its data on a suspend.

A part lives in the per-bio data of its bio, so `bio_endio` frees it, and it must be the last thing
`complete_work` does. KASAN does not report a read of the part right after `bio_endio`, for a reason not found
yet, so nothing here guards this. `kmemleak` and `/sys/kernel/slab/<cache>/shrink` show that parts are freed.

If the kernel log overruns during a run, the summary reports it as `Kernel log overran N times`; a report in
that window would go unseen.

## Do the tests catch bugs?

Checked by breaking the driver on purpose, in the copy inside the VM, and running the fast tests with
`deploy/vm.sh test --no-sync`, see [deploy/README.md](../../deploy/README.md):

| Change | Failed | Where |
| ------ | ------ | ----- |
| No `check_crc` call in `complete_work` | 24 | `test_corruption.py`, as expected |
| No merging of old CRCs in `update_crc_local` | 10 | Partial writes, boundaries and random writes in `test_data.py` |
| `bio_crc_calc` starts at index 0, not `first_sector` | 50 | `test_data.py` |

The chunk lock is checked the same way, on the slow tests that compete for chunks:

| Change | Result | Where |
| ------ | ------ | ----- |
| Two writers may hold a chunk | Failed, `Input/output error` | `test_jobs_competing_within_the_worker_limit`, first case |
| Readers and writers ignore each other | Failed, `Input/output error` | `test_reads_and_writes_competing`, first case; nothing else in `test_fio.py`, `test_filesystem.py`, `test_durability.py` caught it |
| Releasing the lock does not start the next part | Exit code 3, a hang | `test_jobs_competing_beyond_the_worker_limit` |

DM splitting requests at chunk boundaries:

| Change | Result | Where |
| ------ | ------ | ----- |
| No `dm_set_target_max_io_len` | Failed, a kernel report | `test_data.py`, sixth test |
| Reading the part after `bio_endio` in `complete_work` | **Not caught**, and KASAN reports nothing | `test_single_job[4k]` |

Memory on the I/O path:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver before the page pool and the lock table (`4a73a2f`) | Failed, `Input/output error` | All 13 tests above `test_write_goes_on_with_only_the_bio_reserve` |
| A page reserve of 1 instead of 128 | Passed, as it should: parts go on one at a time | `test_write_goes_on_with_only_the_page_reserve`, `test_failed_page_allocation_does_not_fail_the_io` |

Flushes and FUA, with `test_durability.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| The driver before flushes were enabled (`f130fb4`) | 3 | Every test of the device, the controls passed |
| The metadata write of a whole chunk without FUA | 1 | `test_fsync_on_ext4_leaves_nothing_in_the_cache[device, 4k blocks]` |
| The metadata write of a partial write without FUA | 1 | `test_fsync_on_ext4_leaves_nothing_in_the_cache[device, 1k blocks]` |
| An empty flush completed in `dm_map` without reaching the lower device | 3 | `test_fsync_on_the_device_flushes` and the two ext4 cases of the device |

Crash consistency, with `test_crash.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| An empty flush completed in `dm_map` without reaching the lower device | 2 | `test_flushed_writes_survive_a_crash`, `test_ext4_survives_a_crash_after_each_fsync[1k blocks]` |
| The metadata write of a partial write without FUA | 1 | `test_ext4_survives_a_crash_after_each_fsync[1k blocks]` |
| The metadata write of a whole chunk without FUA | 1 | `test_ext4_survives_a_crash_after_each_fsync[4k blocks]`; the case with 1 KiB blocks does not catch it |

Lower device errors, with `test_lower_errors.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| `complete_work` hands the bio back with `BLK_STS_OK` instead of the status of the part | 10 | All of them |

Lifecycle, with `test_lifecycle.py`:

| Change | Result | Where |
| ------ | ------ | ----- |
| `dm_exit` does not unregister the target | Failed, `insmod` gives an error; the kernel then oopses in `get_target_type`, as the target list points into the unloaded module, and needs `deploy/vm.sh reset` | `test_module_unloads_only_without_devices` |
| `dm_dtr` does not free the lock table | Failed, one vmalloc area more | `test_nothing_leaks` |
| `dm_dtr` does not destroy the workqueue | Failed, one rescuer thread more | `test_nothing_leaks` |
| `dm_dtr` does not free the context | **Not caught**, see above | `test_nothing_leaks` |

Repeat this after large changes to the tests. `deploy/vm.sh sync` restores the copy in the VM.

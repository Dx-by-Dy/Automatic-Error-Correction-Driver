# Driver tests

387 tests in pytest. They run as root in the development VM and refuse to run anywhere else,
as they overwrite `/dev/vdb`. The VM is described in [DEPLOY.md](DEPLOY.md), why the tests work this way in
[D1](DECISIONS.md#d1-tests-run-in-a-vm-crashes-are-replayed-from-a-log).

Keep this file up to date when adding or removing tests.

## Running

```bash
deploy/vm.sh test                                     # all 387 tests
deploy/vm.sh test -m "not slow"                       # the fast ones: 346 tests
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
| 124 | Nothing finished in `CORRDM_TEST_TIMEOUT` (60 minutes; a full run takes over 30), which should not happen |

## How a test runs

**Device.** The `stack` fixture gives each test a new device, `make_stack(lower_mib)` one of a chosen
size. The stack is `dcorr-test` (the driver) on `dcorr-test-lower` (`dm-linear` over the start of
`/dev/vdb`). The lower device is zeroed first, 32 MiB by default, then formatted with `tools/dcorrsetup` with
groups of 16 MiB, the smallest size, so that even a small device has two groups, and the table gets the
capacity `harness.py` computes, which the driver checks against the superblock. Tests that need a device that
holds a given amount use `lower_mib_for_capacity`, as the headers, the metadata and the parity take a quarter of
a group of 16 MiB. Every stack
formats through its top layer, so `test_crash.py` formats through `dm-log-writes` and every replay has the
superblock with its salt. Two files build stacks of their own, with a
third layer between the two: `test_crash.py` puts `dm-log-writes` there (`dcorr-test-log`, its log on
`dcorr-test-logdev` at 256 MiB of `/dev/vdb`), `test_lower_errors.py` puts `dm-dust` or `dm-flakey` there
(`dcorr-test-faulty`), and `test_lost_writes.py` a table of `linear` with `dm-flakey` dropping writes over
chosen sectors, under the same name.

**I/O.** `BlockDevice` in `harness.py` reads and writes whole sectors with `O_DIRECT`. The page cache
would hide reads from the driver, and a buffered write to the lower device writes a whole 4 KiB block
back, damaging its neighbours. Tests damage data through `stack.lower` and use it through `stack.upper`.
A write through the driver is sure to be on the lower device only after `flush()`, so a test that looks at the
lower device, or damages it, flushes first. A failed write may be reported by the write or by the flush.

**Layout.** `harness.py` has its own copy of the on-disk layout, `layout(lower_sectors, group_sectors)`, apart
from `src/dcorr-format.h`, which the driver and `dcorrsetup` share: groups of one size, each a header of 1 MiB
and as many whole regions as fit, the last group possibly short; regions of 1024 slots, each with 128 sectors for
the copy of the metadata of the region before in the group, 128 sectors of its own metadata and 8192 sectors of
slots; the slots of a group in 32 columns, the first 30 of data; an entry of 8 CRCs of 8 bytes per chunk, 8
entries to a metadata sector. The positions depend on the size of the lower device and of a group, so
`physical_sector`, `metadata_sector` and `region_sector`, the logical start of a region, take them, the size of a
group 16 MiB unless given. A change of layout has to be made there as well.
`test_layout_of_the_chunks_at_the_borders` spells the positions out apart from both, and
`test_dcorrsetup_gives_the_layout_of_the_tests` compares `dcorrsetup dump` with `harness.py`. `crc64_be` there is
the CRC of the kernel, so that the tests can build a superblock and a block of the bitmap by hand, and `data_crc`
the CRC of a data sector, over the salt, the logical sector and the data, which
`test_the_crcs_on_the_device_are_those_of_the_model` compares with what the driver writes.

**Metadata in RAM.** The driver keeps the metadata of the regions it used in RAM until a suspend, so a test that
changes metadata on the lower device calls `drop_metadata()` from `conftest.py` afterwards, which suspends and
resumes the device. udev reads the start and the end of a device when it is created and after each resume,
which reads the metadata of the first and the last region again, and of the one before it when the end of the
device is near the start of the last region; the tests that count reads of metadata, or need it out of RAM, use
region 1, or a larger device. A chunk never written reads as zeros without its metadata, so they write the
chunks they read first.

**Bitmap.** A chunk never written since the format reads as zeros, whatever the lower device holds, and its
bit reaches the lower device only with a flush. `test_bitmap.py` fills its lower devices with random data
before formatting them, as a device that is only formatted would be, and builds blocks of the bitmap with
`BitmapBlock` of `harness.py`.

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
A `-m` given to pytest replaces the default one, so `-m known_hang` runs those.

**Known bugs.** A test for a known bug is a strict `xfail`, with the title of its `TODO.md` item as the
reason: when the bug is fixed the test fails until the mark is removed. A bug that hangs the guest
cannot be `xfail`, as it would end the run, so it gets `known_hang`. Eleven cases of eight tests are strict `xfail`,
added on 2026-11-17 with their items; none is `known_hang`.

## What is tested

### `test_data.py`: data reads back unchanged and lands where the layout says (80 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_capacity_excludes_metadata_and_parity` | 1 | The device size on 32 MiB: two groups of 3 regions, each region adding 30/32 of its chunks |
| `test_layout_of_the_chunks_at_the_borders` | 1 | Positions written out by hand: the superblocks at 0 and 32768; the first chunks of regions 0 and 1, the last chunk of data of group 0 in region 2 and the first of group 1 in region 3 at their places, 256 sectors into their regions; the first slot of parity zero; the entry of each in its leading metadata sector, the rest of the sector zero, and the trailing copy equal to it at the start of the next region of the group, region 0 for region 2; the trailing area of region 5, at the start of region 3, zero |
| `test_fresh_device_reads_zeros` | 1 | A formatted device reads as zeros, without CRC errors |
| `test_roundtrip` | 50 | Write and read back, 10 sizes from 1 to 2048 sectors at 5 start positions |
| `test_data_lands_at_the_layout_position` | 3 | Every sector of 4 chunks is at its expected place on the lower device, at the start of a region, across the boundary of two and across the boundary of two groups |
| `test_the_last_chunk_of_the_device` | 1 | The last chunk of the device, before the parity of the last group, lands where it should and reads back |
| `test_metadata_is_written_outside_the_data` | 1 | Only the entry of the chunk changes in its metadata sector, in both copies; the next metadata sector does not |
| `test_partial_write_to_an_empty_chunk` | 8 | A one-sector write, for each sector of a chunk; the rest stays zero |
| `test_partial_write_keeps_the_crcs_of_its_neighbours` | 8 | After a one-sector write, each sector still reads on its own |
| `test_write_across_a_chunk_boundary` | 1 | The write lands correctly, the data around it is intact |
| `test_last_sector_of_the_device` | 1 | The last sector can be written and read |
| `test_read_past_the_end_is_short` | 1 | A read over the end is short, a read beyond it is empty |
| `test_write_past_the_end_fails` | 1 | A write beyond the end gives an error |
| `test_data_survives_recreating_the_device` | 1 | Data and CRCs persist after `dmsetup remove` and `create` |
| `test_random_writes_match_a_reference_copy` | 1 | 1500 random overlapping reads and writes against a copy in memory, fixed seed |

### `test_cache.py`: the write back cache (13 tests)

What reaches the lower device and when, and what reads see before it does. The chunk under test is in region 1,
and is written and flushed first where the lower device has to hold it.

The last four tests put `dm-delay` under the driver for some sectors of the lower device: reads of them are
answered a second late, writes at once, and the rest of the lower device is `dm-linear`. `dm-delay` holds a bio
back before it sends it, so a delayed read sees what was written meanwhile. The chunk is written, then the
metadata in RAM dropped. With the data of the chunk delayed, a read of it from the lower device has its CRCs at
once and its data a second later. With its metadata sector delayed, the first write back or read of the region
waits a second for its metadata area. So the races between reads and write backs, and with the read of the
metadata, happen every time.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_a_write_reaches_the_lower_device_on_a_flush` | 1 | A write is not on the lower device and counts as dirty, and is there after a flush |
| `test_dirty_data_is_written_back_by_age` | 1 | Without a flush, the data reaches the lower device within 10 seconds |
| `test_a_dsync_write_reaches_the_lower_device` | 1 | A write with `RWF_DSYNC` is on the lower device when it returns, and nothing is dirty. On a block device `RWF_DSYNC` gives a FUA write and then an fsync, so this cannot tell whether the FUA write itself waited; `test_fsync_on_ext4_leaves_nothing_in_the_cache` does |
| `test_a_suspend_writes_back` | 1 | `dmsetup suspend` writes back what is dirty; after `resume` it reads back |
| `test_a_partial_chunk_writes_only_its_sectors` | 1 | Sectors 1 and 5 of a chunk written: the lower device changes only there, and each sector reads with its CRC |
| `test_a_read_of_a_partly_dirty_chunk` | 1 | One dirty sector comes from the cache, the other seven from the lower device |
| `test_a_dirty_sector_reads_while_a_clean_one_is_damaged` | 1 | A damaged clean sector fails, the dirty one and the sectors before it read |
| `test_writes_larger_than_the_cache_go_through` | 1 | `slow`: 96 MiB through a cache of 64 MiB, without a flush in between, all read back. Whether writes wait for free entries depends on the speed of the lower device here |
| `test_writes_larger_than_the_cache_wait_for_free_entries` | 1 | `slow`: the same over `dm-delay` holding every lower write back 5 ms: no write has waited a quarter of the cache in, writes have waited for free entries at the end, and all reads back |
| `test_a_write_back_waits_for_a_read_in_flight` | 1 | Data delayed: a read of the chunk waits for its data while the chunk is written and flushed: the read gets the old data without an error, then the new data reads |
| `test_the_write_backs_of_a_chunk_wait_for_its_metadata` | 1 | Metadata delayed: sectors 1 and 5 written back by two lower writes, which wait for the metadata area: after the flush the whole chunk reads |
| `test_the_write_backs_of_chunks_sharing_a_metadata_sector_wait_for_its_metadata` | 1 | Metadata delayed: a sector of the chunk and the whole next chunk, whose entries share the sector: after the flush both read |
| `test_a_read_of_a_clean_sector_waits_for_the_write_back` | 1 | Metadata delayed: a read of sector 5 while sector 1 is written back waits for it, counted in `read_waits`, and reads the old data |

### `test_corruption.py`: damage is detected, and only where it is (48 tests)

Three chunks are written, whose entries share one metadata sector, and the damage is done to the middle one.
A read accepts a CRC from either copy of the metadata, so damage to metadata is done to both, but where a test
says one copy.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_data_corruption_fails_only_that_sector` | 8 | A flipped data bit gives `EIO` for that sector and any read with it; every other sector of the 3 chunks reads correctly |
| `test_any_bit_of_a_sector_is_covered` | 4 | First and last bytes of a sector, lowest and highest bits |
| `test_crc_corruption_fails_only_that_sector` | 8 | A flipped bit in a stored CRC fails only the sector it belongs to |
| `test_crc_corruption_in_one_copy_is_covered_by_the_other` | 4 | A flipped bit in the CRC of the first or the last sector, in the leading or the trailing copy: all three chunks read |
| `test_zeroed_metadata_is_detected` | 1 | The scenario of the old `tests.py`, with the entry of the chunk zeroed; the next chunk stays readable |
| `test_a_zeroed_metadata_sector_fails_every_chunk_it_covers` | 1 | The whole sector zeroed: all three chunks fail |
| `test_a_zeroed_metadata_sector_in_one_copy_fails_nothing` | 2 | The whole sector zeroed in the leading or the trailing copy: all three chunks read |
| `test_the_entry_of_a_neighbour_does_not_cover_this_chunk` | 1 | A flipped bit in the entry of the next chunk fails that chunk only |
| `test_a_sector_whose_copies_differ_is_read_before_it_is_written` | 2 | The CRC of a sector damaged in the leading or the trailing copy, as a crash between the copies leaves them: the chunk is settled once with no mismatch, before the write of that sector, or with the trailing copy damaged already when udev reads it after the resume, and after the flush both copies are equal and the sector reads |
| `test_only_the_sectors_written_are_read_first` | 1 | Copies that differ in another sector: a write of one sector reads nothing first, and the other sector still reads after the metadata is read again, so its trailing copy was not overwritten |
| `test_a_sector_matching_neither_copy_is_counted_before_it_is_written` | 1 | Copies that differ and damaged data: the read before the write counts a mismatch, and the write goes on |
| `test_restoring_the_data_clears_the_error` | 1 | No error state is kept in the driver |
| `test_rewriting_a_corrupted_sector_clears_the_error` | 1 | A write of that sector gives it a new, correct CRC |
| `test_write_to_a_neighbour_does_not_hide_corruption` | 1 | A partial write keeps the old CRC of the damaged sector |
| `test_corruption_is_detected_after_recreating_the_device` | 1 | Detection does not depend on driver state |
| `test_the_crcs_on_the_device_are_those_of_the_model` | 1 | Both copies of the entries of the three chunks hold `data_crc` of `harness.py`: over the salt from the superblock, the logical sector as `le64`, the data |
| `test_zeroed_chunk_is_detected` | 1 | The chunk and its entry zeroed in both copies, its bit set: a read error, not zeros |
| `test_chunk_copied_elsewhere_is_detected` | 1 | The chunk with its entry copied over the next chunk: the copy fails there |
| `test_sectors_swapped_inside_a_chunk_with_their_crcs_are_detected` | 1 | Sectors 0 and 1 swapped with their CRCs in both copies: both fail, sector 2 reads |
| `test_a_zeroed_region_with_its_chunks_written_is_detected` | 1 | Region 1 zeroed whole, its leading copy with it, its trailing copy in region 2 left: its three written chunks fail |
| `test_a_region_shifted_whole_with_its_metadata_is_detected` | 1 | Region 0 copied whole over region 1, where the same chunk was written with other data, as a table off by a region: the chunk fails |
| `test_a_chunk_from_another_device_is_detected` | 1 | The same data written in the same place on the device formatted again, then the metadata sectors of the old format put back: the chunk fails. Before that, the new device reads, as a control |
| `test_every_damaged_sector_of_a_read_is_counted_and_logged` | 1 | Three sectors of the chunk damaged, the chunk read whole: `crc_mismatches` grows by 3, and the log names the device as `dmsetup` does, the logical sector of the read and of its first damaged sector |
| `test_a_flood_of_mismatches_is_counted_whole_and_logged_rate_limited` | 1 | 80 chunks with a damaged sector each, read one after another: `crc_mismatches` grows by 80, the log has at most 20 lines of them |
| `test_a_flood_on_one_device_does_not_hide_the_errors_of_another` | 2 | Two devices: a mismatch on the second is logged with its name; after a flood of mismatches on the first in the same 5 s it is not, a strict `xfail` |

All but the model test passed before the seed: zeros with zero metadata and a CRC that does not depend on the
place or the device. Each of the 7 failed on the driver of step 2, on its check of detection.

### `test_durability.py`: flushes and FUA writes reach the lower device (7 tests)

Reads the bios queued on `/dev/vdb` from the `block_bio_queue` trace event. A write is durable once it is FUA
or a flush is queued after it, so after an `fsync` no write it caused may be neither.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_the_test_disk_has_a_write_cache` | 1 | Control: `vdb` is `write back`, or the next tests would prove nothing |
| `test_device_reports_a_write_cache_and_fua` | 1 | The device is `write back` with `fua` 1, or the layers above send neither |
| `test_fsync_on_the_lower_device_flushes` | 1 | Control: this way of counting does see flushes |
| `test_fsync_on_the_device_flushes` | 1 | An `fsync` on the device gives a flush on `vdb` after its writes |
| `test_fsync_on_ext4_leaves_nothing_in_the_cache` | 3 | A new file and an `fsync` on ext4 without lazy initialisation: the journal commit is seen, as a FUA write on the lower device alone and as a flush through the driver, whose cache turns FUA into a write back and a flush; and no write is left unflushed. On the lower device alone it is the control; on the device with 4 KiB blocks the commit block is a whole chunk, with 1 KiB blocks it is part of one, so its metadata is read first |

### `test_crash.py`: the device after a crash (16 tests)

`dm-log-writes` logs every write that reaches the disk below the driver, with its flushes and FUA, in
the order the data reaches the disk itself. `logwrites.py` reads the log and replays a prefix of it to the
zeroed lower device, or one filled with the same random data, then the driver is put on it again: that is the device after a crash at that point.
The format is that of `replay-log` from xfstests, which is not needed. The log is in the order writes
complete, so a disk that persists two writes in another order between flushes cannot be replayed: the order of
the driver's own writes is checked in the log itself. A second crash is replayed on top of the first: the log
is started again from the state of a replay, and the entries of both run in a row.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_flushed_writes_survive_a_crash` | 1 | Whole chunks, partial writes and a write across a chunk, each step flushed and marked, then a write left unflushed: at each mark the device holds exactly what was written before it |
| `test_the_leading_copy_is_durable_before_the_data` | 2 | A whole chunk and one sector: between two flushes, the leading metadata sector of the chunk is a FUA write and comes before its data in the log |
| `test_a_write_cut_between_data_and_metadata_reads_old_or_new` | 2 | A whole chunk and one sector: a crash at every entry between the two flushes leaves the chunk with its old or its new data |
| `test_chunks_of_a_region_cut_between_flushes_read_old_or_new_each` | 1 | Three chunks of region 0, two of them in one metadata sector, one written anew in one sector only: a crash at every entry between the two flushes leaves each sector old or new, some points leave one chunk new and another old, and after the last flush both copies of the metadata are equal |
| `test_a_chunk_written_back_twice_between_flushes_reads_one_of_its_versions` | 1 | A chunk written back by age twice without a flush from above: one barrier, and a crash at every entry leaves one of its three versions |
| `test_a_second_crash_after_one_between_the_copies` | 3 | A crash after the leading copy (old data left) or after the data (new data left), then a write of the chunk, logged anew from the state the first crash and its read left: one settle with no mismatch, by the write back, or by the read after the crash when the new data matches only the leading copy; with that chunk in region 1 and no read, by the write back again; a second crash at every entry leaves what the first crash left or the newest data |
| `test_ext4_survives_a_crash_after_each_fsync` | 2 | `slow`: 8 files on ext4 with 1 KiB and 4 KiB blocks, each with an `fsync` and a mark. At every mark: ext4 mounts, `e2fsck -fn` finds nothing, and each file marked so far is intact |
| `test_first_writes_cut_anywhere_read_zeros_or_new` | 1 | On a lower device of random data, a whole chunk and one sector of another written for the first time and flushed: a crash at every entry leaves each of them zeros or the new data with zeros around it, never an error, and both states are seen |
| `test_a_discard_cut_anywhere_reads_old_or_zeros` | 1 | Four chunks written and flushed, the two in the middle discarded and flushed: a crash at every entry leaves each of those old or zeros, both seen, zeros after the flush, the neighbours unchanged |
| `test_a_write_after_a_discard_cut_anywhere_reads_zeros_or_new` | 1 | The trap of a discard: a first crash after the data leaves copies of the metadata that differ, checked on the lower device, as a read would settle them, for a chunk in region 1, which udev does not read; then the chunk is discarded and one sector written back by age: one barrier, no read to settle, and a second crash at every entry leaves what the first left, zeros, or the sector with zeros around it. Without the sync before that write back, the first entry already leaves a chunk that does not read |
| `test_ext4_survives_a_crash_at_any_flush` | 1 | `slow`: the same at every flush after `mkfs`, and at every fourth FUA write: each write back writes its leading metadata sector with FUA, about 270 points besides 60 flushes, too many to check all in 10 minutes. Before the cache it failed at once, as ext4 writes its superblock, part of a chunk, with FUA |

### `test_bitmap.py`: the bitmap of written chunks (30 tests)

Groups of 16 MiB, one block of the bitmap each, on 48 MiB of random data, three groups.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_a_device_of_random_data_reads_zeros_once_formatted` | 1 | The whole device reads as zeros, with no metadata area read and every chunk counted in `unwritten_reads`; before the bitmap it failed its CRC |
| `test_a_first_write_reads_back_with_zeros_around_it` | 1 | One sector, a whole chunk, a run across chunks, the ends of groups 0 and 1, written for the first time: each chunk reads the data with zeros around it, before and after the target is created again, and nothing was read to settle its copies |
| `test_a_bit_reaches_the_device_only_with_a_flush` | 1 | Written back by age, both copies of the block keep generation 1 and the bit clear; after a flush both are valid, of generation 2, with their group, index and role, and only that bit; a flush with no new bit writes nothing |
| `test_a_reload_keeps_the_bits_the_old_table_sets` | 2 | A chunk written, still in the cache or written back by age, then `dmsetup reload` and `resume`: the chunk reads under the new table, and a sector written there keeps the rest of the chunk after the target is created again. It failed with the bitmap read in the constructor |
| `test_one_damaged_copy_is_covered_and_repaired` | 4 | The leading or the trailing copy damaged: the chunk reads, `single_blocks` 1 and a warning; a flush rewrites the copy with the generation and the bits of the other; with a read only table it stays damaged |
| `test_the_copy_with_the_larger_generation_is_taken` | 2 | One copy put back to an older valid version: the chunk of the newer reads |
| `test_an_older_copy_is_rewritten_before_the_newer_is_lost` | 4 | One copy put back to an older valid version, then a flush, then the newer copy damaged: after a first write to another chunk of the block the chunk of the newer reads, and so it does after a flush alone, as the creation marked the block to be written in both copies |
| `test_a_block_of_another_place_or_device_is_not_taken` | 5 | The leading copy with another group, index or role, or a CRC from another salt, all with generation 100 and no bits: not taken, the chunk reads from the trailing copy. The same copy with nothing wrong is taken, and the chunk then reads as zeros: the positive control |
| `test_a_block_invalid_in_both_copies_makes_its_range_read_only` | 1 | Both copies damaged: a warning, `read_only_blocks` 1; a written chunk reads, one never written fails its CRC, a write there fails and is counted; group 1 is written and read; the damaged copies are never written |
| `test_a_zeroed_chunk_in_a_read_only_block_never_reads_its_old_data` | 2 | Strict `xfail`: a chunk discarded, or zeroed by write zeroes, and flushed reads zeros; with its block then invalid in both copies it reads its old data, where an error or zeros would be right |
| `test_a_discard_touching_a_read_only_block_fails_whole` | 1 | A discard across the end of group 0, whose block is invalid in both copies, into group 1: it fails, is counted in `refused_writes`, and the chunks of group 1 keep their data |
| `test_the_superblock_of_every_other_group_is_checked` | 4 | The superblock of group 2 zeroed, of another device or of another generation: the device is created, `bad_superblocks` 1 and the reason in the log; unchanged, 0 |
| `test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write` | 1 | Over `dm-dust` failing one write of the leading copy: the flush fails, the error is counted, no copy has the bit; the next flush writes both, and the chunk reads after the target is created again |
| `test_a_second_copy_that_fails_to_write_is_counted` | 1 | Over `dm-dust` failing one write of the trailing copy: the flush succeeds, the error is counted, the leading copy has the bit, the chunk reads after the target is created again |

### `test_discard.py`: discard and write zeroes through the bitmap (17 tests)

Five chunks written and flushed; the discards start in the chunk before the middle one, or at it, and the
write zeroes go from sector 3 of the chunk before it to sector 5 of the chunk after it.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_the_device_offers_discard_in_chunks_and_write_zeroes` | 1 | In sysfs: `discard_granularity` 4096, `discard_max_bytes` and `write_zeroes_max_bytes` at least 1 GiB, as the lower device has write zeroes |
| `test_a_discard_reads_zeros_in_whole_chunks_and_keeps_the_ends` | 1 | From sector 3 of one chunk to sector 5 of the third after it: the two whole chunks read as zeros, without a lower read, the ends keep their data, `discarded_chunks` 2. The block layer sends the unaligned head as a discard of its own |
| `test_a_discard_inside_one_chunk_changes_nothing` | 1 | Sectors 1 to 6 of a chunk: counted, no chunk discarded, the data unchanged |
| `test_a_discard_writes_no_data_below` | 1 | No write reaches the lower device at the discard; after a flush its slot still holds the old data, and the chunk reads zeros |
| `test_data_in_the_cache_is_dropped_by_a_discard` | 1 | A chunk still dirty in the cache is dropped: no dirty entry left, zeros, and after a flush its slot below is still zeros |
| `test_a_discard_survives_recreating_the_device` | 2 | After a flush, or only the sync of the suspend, the target created again reads the chunk as zeros and the next one as written |
| `test_a_write_after_a_discard_is_written_whole_after_a_barrier` | 1 | One sector written after a discard: one barrier, no read to settle, and after the target is created again the sector with zeros around it |
| `test_a_second_write_after_a_flushed_discard_needs_no_barrier` | 1 | Once a flush has put the cleared bit on the device, a write back of the chunk takes no barrier |
| `test_blkdiscard_of_the_whole_device_is_one_discard` | 1 | `blkdiscard` of the device: one discard reaches the target, every chunk is discarded, the chunks read as zeros |
| `test_fstrim_on_ext4_keeps_the_files` | 1 | `mkfs.ext4` discards the device; two files of 4 MiB, one deleted, `fstrim` discards at least its chunks, `e2fsck -fn` is clean and the other file intact after a remount |
| `test_write_zeroes_reads_zeros_and_keeps_the_neighbours` | 1 | `BLKZEROOUT`: the range reads as zeros, the rest as written; the two whole chunks without a lower read; the counters of discards unchanged |
| `test_write_zeroes_survives_recreating_the_device` | 2 | After a flush, or only the sync of the suspend, the target created again reads the same |
| `test_write_zeroes_over_data_in_the_cache` | 1 | Five dirty chunks: the whole chunks drop their data, the ends are zeroed in the cache; the same after a flush and the target created again |
| `test_blkdiscard_z_zeroes_through_write_zeroes` | 1 | `blkdiscard -z` of the range: zeros, and the whole chunks read without a lower read, which ordinary writes of zeros would not give |
| `test_write_zeroes_inside_one_chunk_zeroes_only_its_sectors` | 1 | Sectors 2 to 4 of a chunk: only they read as zeros, before and after the target is created again |

### `test_lost_writes.py`: writes acknowledged and lost (9 tests)

Three chunks written and flushed. The faulty layer is loaded after a write from above and before its write
back by age, dropping writes to the data slot of the chunk, a copy of its metadata sector or a copy of the
block of the bitmap, then `linear` again; each test checks on the lower device that the write was dropped.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_lost_data_of_a_rewrite_reads_old_until_the_flush_then_fails` | 2 | A whole chunk and one sector: before the flush the old data reads without an error; after it `EIO`, also after the target is created again; the other sectors still read |
| `test_lost_data_of_a_first_write_fails_at_once` | 1 | A chunk never written: `EIO` before the flush, and after it and a recreation |
| `test_a_lost_leading_copy_is_covered_by_the_trailing_one` | 1 | The leading metadata sector dropped: the new data reads before and after the flush and a recreation, the copies differ on the device; the next write back reads the chunk to settle it, with no mismatch, and the copies are equal again |
| `test_data_lost_with_both_copies_of_its_metadata_passes_as_old` | 1 | The blind spot, pinned: the data and both metadata sectors dropped through the flush: the old data reads without an error. Its control is the rewrite test, which differs only in the trailing copy |
| `test_a_lost_copy_of_a_block_of_the_bitmap_is_covered_by_the_other` | 2 | A first write whose leading or trailing copy of the block is dropped: that copy keeps its old generation, and the chunk reads after the target is created again |
| `test_old_data_put_back_fails_once_the_new_was_read` | 2 | A rewrite flushed, the target created again, the new data read and flushed, then the old data put back in its slot: it fails with both copies written, and with the trailing copy lost, as the read settled the chunk |

### `test_lower_errors.py`: the lower device fails (28 tests)

`dm-dust` with 512-byte blocks fails reads of chosen sectors of the lower device, and writes to them a
chosen number of times; a write to such a sector clears it. One test loads `dm-flakey` in its place.
16 chunks are written first, whose entries fill two metadata sectors, and the second chunk gets the failures.
The tests of the counters look at how much a counter grows, as earlier I/O of the test may count too.
The device has two groups of three regions, so that the trailing copy of region 0 is in region 1: `dm-dust` takes an empty
flush, whose sector is 0, for a write to block 0. A failed metadata sector is failed in both copies, but where
a test says one copy; a write is followed by two flushes, so that the trailing copy is written before the test
goes on.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_failed_data_sector_fails_only_its_reads` | 2 | First and last data sector: read one at a time, only that sector fails; a read over all the chunks fails; the first chunk reads correctly |
| `test_failed_metadata_sector_fails_only_the_chunks_it_covers` | 1 | Metadata dropped from RAM first: every sector of the 8 chunks of that metadata sector fails, the other 8 chunks read, as the failed read of the area is retried one sector at a time |
| `test_metadata_sector_failed_in_one_copy_fails_nothing_and_warns` | 2 | Metadata dropped from RAM first. The leading or the trailing sector fails: everything reads, with a warning that the chunk is read with one copy; a write of the chunk warns too and rewrites both copies, equal on the lower device, and after the metadata is read again no warning is left |
| `test_a_failed_leading_sector_is_rebuilt_from_the_trailing_copy` | 1 | On 34 regions, so that the area of region 0 is read into one that held another region: the leading sector fails, a write of one chunk there makes it equal to the trailing one, and every chunk reads back |
| `test_a_sector_rebuilt_from_one_copy_keeps_its_neighbours_readable` | 3 | A chunk rewritten, then the copy that holds the CRC of its data fails to read, a neighbour is written and the sector healed: with the copies equal the chunk reads; with them left as a crash after the data or before it leaves them, it fails for good, a strict `xfail` |
| `test_failed_trailing_write_is_counted_and_warned` | 1 | The trailing sector fails to write once: the write and its flush succeed, `trail_errors` is 1, a read warns about one copy; the next write of the chunk restores the copy |
| `test_device_works_again_once_the_sector_reads` | 1 | Metadata dropped from RAM first. A failed data and metadata sector, then cleared: everything reads back, no error state stays in the driver, an area that failed to read is not kept |
| `test_write_fails_when_its_metadata_sector_does_not_read` | 3 | Metadata dropped from RAM first. A whole chunk, one sector, and a whole neighbouring chunk with its entry in the same sector: the write or its flush fails with `EIO`, as the sector holds the entries it has to keep; the other chunks read. What the chunk holds after it is open |
| `test_failed_write_is_reported` | 4 | The data or the metadata sector of a whole chunk or of one sector fails to write once: the write or its flush fails with `EIO` and `write_errors` grows, the next one succeeds, the other chunks read. The metadata is in RAM, so the write back does not read the sector, which `dm-dust` would fail too |
| `test_writes_fail_while_reads_go_on` | 1 | `dm-flakey` with `error_writes`: whole, partial and crossing writes fail on their flush and stay in the cache, so they read back, and every flush fails; once `dm-linear` is back a flush writes them back and the device takes writes again |
| `test_a_cache_full_of_failed_chunks_refuses_writes` | 1 | `dm-flakey` with `error_writes` under a device larger than the cache: writes of 1 MiB are taken in until every entry has failed, at most 64 MiB, then refused with `EIO`; what was taken in reads back, and reaches the lower device once `dm-linear` is back |
| `test_a_failed_read_is_counted_and_logged_with_the_device` | 1 | A failed data sector read alone: `read_errors` grows by 1, and the log names the device as `dmsetup` does and the logical sector |
| `test_a_failed_metadata_read_is_counted_in_sectors` | 1 | Three sectors of the leading copy fail, metadata dropped from RAM: everything reads, and `metadata_read_errors` grows by a multiple of 3, as each read of the area counts each sector; udev reads it a number of times not known |
| `test_a_failed_flush_is_counted` | 1 | `dm-flakey` with `error_writes` and nothing to write back: the flush from above fails, `flush_errors` grows by 1 and `write_errors` not; with `dm-linear` back the flush succeeds |
| `test_a_chunk_written_back_again_after_a_failed_flush_takes_a_barrier` | 2 | A chunk written back by age twice: one barrier with no flush between, and one with a failed flush between, as it made nothing durable |
| `test_a_chunk_whose_barrier_fails_is_not_written_back` | 1 | `dm-flakey` with `error_writes` before the second write back: its barrier fails, so the entry fails with no write back sent, `write_errors` unchanged; with `dm-linear` back a flush writes it, and it reads back |
| `test_the_first_error_raises_one_device_mapper_event` | 1 | A failed read: `dmsetup wait` sees one event; three more failed reads raise none |
| `test_write_zeroes_is_not_offered_over_a_lower_device_without_it` | 1 | `dm-dust` has no write zeroes, nor then has the driver; `BLKZEROOUT` zeroes with ordinary writes, so after a flush the chunks read from the lower device |

### `test_metadata.py`: metadata in RAM (8 tests)

What keeping the metadata of a region in RAM saves on the lower device, counted in `/sys/block/<lower>/stat`,
and when the driver reads it again, counted in `metadata_loads` of `dmsetup status`. 32 areas are kept, each
with both copies; and when the trailing copy is written.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_a_write_back_reads_nothing_when_the_metadata_is_in_ram` | 1 | After a first write of the region, a one-sector write and a write of the neighbouring chunk, with their flushes, read nothing from the lower device; every sector reads with its CRC |
| `test_a_read_takes_one_lower_read_when_the_metadata_is_in_ram` | 1 | A read of a chunk written before reads the lower device once, for its data |
| `test_a_region_is_read_once` | 1 | Reads of 11 chunks of a region, written before, read its metadata once, a read in the next region once more |
| `test_a_suspend_drops_the_metadata` | 1 | A second read of a region reads no metadata, a read after a suspend and resume does |
| `test_the_least_recently_used_region_is_dropped` | 1 | 32 regions fill the areas, the first is used again, then a new region takes the place of the second, not the first |
| `test_data_is_right_after_its_region_was_dropped` | 1 | A chunk and then one sector of it written in each of 34 regions, so areas are dropped and read again in between: after the metadata is dropped, every sector reads with its CRC |
| `test_the_trailing_copy_is_written_after_a_flush` | 1 | A chunk written back by age has its leading copy on the lower device and not yet the trailing one; after a flush the two are equal, and the driver flushed nothing by itself |
| `test_the_driver_flushes_by_itself_when_half_the_areas_are_pinned` | 1 | Chunks written back by age in 13 regions leave the trailing copies unwritten; in 36 regions, more than there are areas, the driver flushes and writes them by itself (`crowded_flushes`) instead of waiting for an area for ever; every chunk reads back after the metadata is read again |

The fio tests, on more than 500 MiB, drop and read areas again all the time.

### `test_lifecycle.py`: the device and the module come and go (4 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_suspend_and_resume_under_load` | 1 | `slow`: `dmsetup suspend` and `resume` over and over while fio writes and verifies 4 areas with 1 MiB requests, far more than the cache holds. Whether writes wait in `dcorr_map` for a free entry depends on the speed of the write back and is checked in `test_cache.py` instead |
| `test_table_reload_under_load` | 1 | `slow`: the same with `dmsetup reload` and `resume`, which builds a new target and destroys the old one |
| `test_module_unloads_only_without_devices` | 1 | `rmmod` fails while a device exists, succeeds without one; loaded again, the device works |
| `test_nothing_leaks` | 1 | `slow`: a device that did I/O, then removed: the rescuer threads of its three workqueues are gone (and were there while it existed), and `kmemleak` reports nothing allocated by the driver |

`kmemleak` does not catch everything here. A context left behind by `dcorr_dtr` was not reported in a minute of
scans, and showed up only after more devices had come and gone. The likely reason: per-bio data is not cleared
when a bio is allocated again, so bios in the reserves of the bio pools still hold the old `part->dc`, and
`kmemleak` takes that for a reference. It also reports a leak only a few scans after it, so a leak from an
earlier test of the same boot may show up in this one. The workqueues are checked directly for that reason.
The pages of the cache and of the metadata in RAM come from `alloc_page`, which `kmemleak` does not track, and
are not checked. The
tables of the device are small enough for `kmalloc`, so `/proc/vmallocinfo` does not show them; it showed the
lock table, which is gone.

### `test_target.py`: arguments, table and limits of the target (12 tests)

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_bad_arguments_are_rejected` | 3 | No arguments, too many, a missing device |
| `test_device_takes_the_usable_length` | 1 | A table with the correct length gives a device of that size |
| `test_a_length_other_than_the_capacity_is_rejected` | 2 | A chunk longer or shorter than the capacity in the superblock is refused |
| `test_table_shows_the_lower_device` | 1 | `dmsetup table` gives the lower device as major:minor, as every target. It was a strict `xfail` until stage 5 |
| `test_the_table_loads_again_as_dmsetup_gives_it` | 1 | The line of `dmsetup table`, saved, creates the device again on the same data |
| `test_target_may_start_after_sector_0` | 1 | With a table that puts the target after sector 0, its first sector lands on sector 0 of the lower device |
| `test_a_second_device_on_the_same_lower_device_is_refused_or_agrees` | 1 | Strict `xfail`: a second device over the same lower device is taken, and reads zeros where the first wrote and flushed |
| `test_the_limits_are_those_of_a_chunk_over_the_lower_device` | 1 | In sysfs: logical block 512, physical block and minimal I/O 4096, no optimal I/O, `max_hw_sectors_kb` of the lower device, no polling, no stable pages |
| `test_a_lower_device_with_4k_logical_blocks_is_refused` | 1 | An image formatted and loaded over a loop device with sectors of 512 bytes, as a control, is refused over one with sectors of 4096, and the log says why |

### `test_superblock.py`: the superblock and `dcorrsetup` (79 tests)

The superblock is also built by hand, with the layout and `crc64_be` of `harness.py`, so that the driver is
seen to take one made apart from `dcorrsetup` and to refuse each field that is wrong. The reasons are read from
the kernel log. The device is two groups of 16 MiB unless said otherwise.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_the_superblock_built_by_the_tests_is_taken` | 1 | The control of the tests below: `crc64_be` of the tests gives the check value of CRC-64/ECMA-182 and the CRC `dcorrsetup` wrote, and superblocks rewritten with it are taken |
| `test_a_device_without_a_superblock_is_refused` | 1 | A zeroed device: no magic in group 0, no copy of group 1 for any size |
| `test_a_wrong_field_in_both_copies_is_refused` | 15 | Version, flags, the size of a chunk, of a region and of a block of the bitmap, the columns, the parity columns, the header, a size of a group not in the list, the size of the device, the capacity, the groups, the regions of a group and of the last one, the blocks of the bitmap: each with its reason for group 0 |
| `test_a_wrong_field_in_group_1_is_seen` | 17 | The same fields, the number of another group, and a size of a group other than that of its place, in group 1 only: the device comes up from group 0 and names the reason for group 1 |
| `test_a_group_size_with_too_few_groups_is_refused` | 1 | Group 0 says 32 MiB on a device of 32 MiB, one group |
| `test_copies_with_the_numbers_swapped_are_refused` | 1 | Groups 0 and 1 with each other's number, as after misdirected writes |
| `test_a_damaged_crc_is_refused` | 1 | A bit flipped in the reserved bytes of both, which only the CRC covers |
| `test_one_damaged_copy_is_covered_by_the_other` | 2 | Group 0 or group 1 zeroed: the device comes up from the other with a warning, and the data written before in both groups reads |
| `test_group_1_is_found_for_each_size_when_group_0_is_damaged` | 4 | Groups of 16, 32, 64 MiB and 1 GiB, group 0 zeroed: the probe finds group 1 at its size, past the smaller sizes inside group 0, and the data reads |
| `test_a_format_with_larger_groups_wipes_group_1_of_the_smaller_sizes` | 1 | Formatted with 16 MiB, then with 32 MiB: the old copy of group 1 is zeroed and the probe finds the new one; the positive control: with the old copy put back, the probe takes it |
| `test_a_superblock_stored_as_data_does_not_win_the_probe` | 1 | Strict `xfail`: groups of 32 MiB, the image of a superblock of group 1 for groups of 16 MiB written through the driver at its place, group 0 damaged: the probe takes the image and the device is refused |
| `test_both_damaged_copies_are_refused` | 1 | Both copies zeroed |
| `test_the_copy_with_the_larger_generation_is_taken` | 2 | Generation 2 in group 0 or in group 1 |
| `test_copies_that_differ_in_the_same_generation_warn` | 2 | Another salt or UUID in group 1: a warning, group 0 taken |
| `test_copies_that_agree_do_not_warn` | 1 | The control of the test above |
| `test_a_device_of_another_size_is_refused` | 1 | The device below grown by 1 MiB |
| `test_the_smallest_device` | 2 | A group and a short one of two regions is taken by both; a chunk less, `dcorrsetup` refuses it as too small and the driver finds no superblock |
| `test_dcorrsetup_gives_the_layout_of_the_tests` | 7 | `dump` and `table` against `harness.py` on the smallest device, 32 MiB, 32 MiB and 300 sectors, 42 MiB with a short group and 100 MiB with groups of 16 MiB, 100 MiB with 32 MiB and 2 GiB with 1 GiB, and the driver takes the device |
| `test_the_header_of_every_group_holds_its_superblock_and_bitmaps` | 2 | With groups of 16 MiB and 1 GiB: in every header a superblock with its number and the layout, the leading bitmap of the group and the trailing one of the group before with their group, index and role, empty, with a CRC that starts from the salt, and the dirty stripes zero |
| `test_dcorrsetup_refuses_a_size_of_a_group_not_in_the_list` | 7 | `3M`, `8M`, `24M`, `8G`, `0M`, `16`, `16K` |
| `test_dcorrsetup_formats_with_groups_of_1_gib_by_default` | 1 | 2 GiB without `--group-size`: two groups of 248 regions |
| `test_every_region_lies_where_the_layout_says` | 1 | On three groups, the last short, the first and the last chunk of data of every region land where `harness.py` puts them |
| `test_data_never_lands_in_the_parity_columns_nor_outside_the_regions` | 1 | The whole device written: every slot of the parity columns and the unused end of every group stay zero, and every header keeps its superblock |
| `test_a_large_device` | 2 | A sparse file of 40 GiB on a loop device, groups of 1 and 4 GiB: `dump` agrees with `harness.py`, and the first and the last chunk of groups 0, 1 and the last land where it says |
| `test_format_keeps_a_valid_superblock_without_force` | 1 | `format` again fails and keeps the UUID; with `--force` the UUID changes |
| `test_format_keeps_a_superblock_found_only_in_group_1` | 1 | With group 0 zeroed, `format` without `--force` still finds group 1 and refuses |
| `test_format_refuses_a_device_in_use` | 1 | With the driver on top, `format --force` fails: the device is opened with `O_EXCL` |
| `test_dump_of_a_device_without_a_superblock_fails` | 1 | `dump` of a zeroed device fails and names both reasons |

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
| `test_reads_and_writes_competing` | 3 | The same with `randrw`, `bs` of `512`, `4k`, `32k`, 8 jobs: no read gets a CRC error. With the cache a read rarely meets the write back of its chunk here, see `test_cache.py` |
| `test_jobs_competing_beyond_the_worker_limit` | 6 | The same as the first with `32k/8`, `16k/32`, `1m/8`: more items than the workqueue runs at a time, which hangs if a worker ever sleeps on a chunk |

### `test_memory.py`: I/O when memory is short (5 tests)

Failures come from the kernel's fault injection (`failslab`), limited to one thread and to allocations whose
stack passes through given code. How the driver uses memory is in [Memory](ARCHITECTURE.md#memory). The two tests of the
pool of metadata pages were removed with the pool: the I/O path takes no page any more.

| Test | Cases | Checks |
| ---- | ----- | ------ |
| `test_io_takes_nothing_from_slab_in_the_driver` | 2 | `read`, `write` and flush of 64 chunks while every slab allocation through the driver fails, for a write in any task, as the write back runs in the worker of the cache: no error and correct data |
| `test_write_goes_on_with_only_the_bio_reserve` | 1 | `slow`: all new bios of the thread fail, and a write of 1 MiB must finish in 15 seconds |
| `test_ordinary_load_does_not_wait` | 1 | `fio` `randrw` with `bs=128k`, `iodepth=16`, at most 512 parts: `dmsetup status` shows no wait for a place among the parts in flight |
| `test_parts_in_flight_stay_under_the_limit` | 1 | `slow`: over `dm-delay` holding every lower read back 100 ms, with the chunks written and the metadata of the regions read first, `fio` asks for 32 reads of 1 MiB at a time, 8192 parts: the parts in flight, by `/sys/block/<device>/inflight` of the driver, come above half the limit of 4096 and not above it (with 64 for parts completing), and reads waited in `dcorr_map`. 4096 at most in a run. The statistics of `dm-delay` count a bio only once it is sent on after the delay, so they cannot be used |

The memory a load takes through the driver against the lower device was measured here until 2026-11-14, and
dropped: on the debug kernel the difference, 100 to 535 MiB, is freed DM clones, one per 4 KiB, that KASAN and
kmemleak hold back, not memory of the driver. It is left to the baseline, on a kernel without them.

## What is not tested yet

Nothing of what stage 1 of `TODO.md` asked for. That a write to an entry under write back waits is not tested
on its own: the fio tests that compete for chunks go through it, but nothing checks the counter.

A part lives in the per-bio data of its bio, so `bio_endio` frees it, and it must be the last thing
`complete_work` does. KASAN does not report a read of the part right after `bio_endio`, for a reason not found
yet, so nothing here guards this. `kmemleak` and `/sys/kernel/slab/<cache>/shrink` show that parts are freed.

Three things of the bitmap are not tested: the flush between the first copies of its blocks and the second
ones, the order of the bitmap write after the flush of the data, and which copy `trail_first` writes first. A
crash test would need a cut between two writes that the log replays in the order they completed, and dm-log-writes
logs nothing of a write until it completes, so a reorder inside one flush never shows in a replay.

One thing of discard is not tested. The cache rounds the start of a discard up to a chunk, but
`__blkdev_issue_discard` always ends the first bio of a range at the boundary of the granularity, so an unaligned
head reaches the target as a bio with no whole chunk, completed in `dcorr_map`, and the rounding is never needed
from userspace: discarding the head chunk too passed every test.

Two things of write zeroes are not tested. A FUA write zeroes, as nothing in userspace sends one: `BLKZEROOUT`
has no FUA; it goes the way of a FUA write, through the flushes of the worker. And a crash in the middle of one,
as `dm-log-writes` has no write zeroes, so a write zeroes over it comes as ordinary writes; its whole chunks go
the way of a discard and its ends the way of a write, both cut by the crash tests.

The worker takes the lock of the cache once after it waits for no job or no write back in flight, so that a
sync never writes a block of the bitmap while the completion of the last job is still setting a bit in it. This
is fixed by reading and is not tested: the window is a few instructions in one hold of the lock, and no run
reaches it on purpose.

If the kernel log overruns during a run, the summary reports it as `Kernel log overran N times`; a report in
that window would go unseen.

## Do the tests catch bugs?

Checked by breaking the driver on purpose, in the copy inside the VM, and running the fast tests with
`deploy/vm.sh test --no-sync`, see [DEPLOY.md](DEPLOY.md). The tables are a record of runs at their time: a test
named in italics has been removed or replaced since.

| Change | Failed | Where |
| ------ | ------ | ----- |
| No `check_crc` call in `complete_work` | 24 | `test_corruption.py`, as expected |
| No merging of old CRCs in `update_crc_local` | 10 | Partial writes, boundaries and random writes in `test_data.py` |
| `bio_crc_calc` starts at index 0, not `first_sector` | 50 | `test_data.py` |

Before the cache, the chunk lock was checked the same way on the slow tests of `test_fio.py` that compete for
chunks: readers and writers that ignore each other failed `test_reads_and_writes_competing`, two writers in
one chunk failed `test_jobs_competing_within_the_worker_limit`, and a released lock that did not start the next
part hung `test_jobs_competing_beyond_the_worker_limit`. The lock is gone; what replaced it, the tree of reads
in flight in the cache, is checked on the tests of `test_cache.py` on `dm-delay`:

| Change | Result | Where |
| ------ | ------ | ----- |
| The write back does not wait for the reads in flight on its chunk | Failed, `Input/output error` | `test_a_write_back_waits_for_a_read_in_flight`. `test_reads_and_writes_competing` passed, all 3 cases: with the cache a read rarely meets a write back there |
| The lower writes of one entry go at once | Failed, `Input/output error`, 2 | *test_the_write_backs_of_a_chunk_go_one_at_a_time*, since replaced by `test_the_write_backs_of_a_chunk_wait_for_its_metadata`, and `test_a_partial_chunk_writes_only_its_sectors` without any delay |
| A read of a clean sector does not wait for the write back of its chunk | Failed | `test_a_read_of_a_clean_sector_waits_for_the_write_back` |
| The end of a read does not wake the worker | Exit code 3, a hang | `test_a_write_back_waits_for_a_read_in_flight` |
| The end of a lower write of an entry does not start the next one | Exit code 3, a hang | *test_the_write_backs_of_a_chunk_go_one_at_a_time*, since replaced by `test_the_write_backs_of_a_chunk_wait_for_its_metadata` |

DM splitting requests at chunk boundaries:

| Change | Result | Where |
| ------ | ------ | ----- |
| No `dm_set_target_max_io_len` | Failed, a kernel report | `test_data.py`, sixth test |
| Reading the part after `bio_endio` in `complete_work` | **Not caught**, and KASAN reports nothing | `test_single_job[4k]` |

Memory on the I/O path, checked when the metadata pages came from a pool; the tests of the pool are gone with
it:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver before the page pool and the lock table (`4a73a2f`) | Failed, `Input/output error` | All 13 tests above `test_write_goes_on_with_only_the_bio_reserve` |
| A page reserve of 1 instead of 128 | Passed, as it should: parts go on one at a time | *test_write_goes_on_with_only_the_page_reserve*, *test_failed_page_allocation_does_not_fail_the_io*, removed with the pool |

Flushes and FUA, with `test_durability.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| The driver before flushes were enabled (`f130fb4`) | 3 | Every test of the device, the controls passed |
| Before the cache: the metadata write of a whole chunk without FUA | 1 | `test_fsync_on_ext4_leaves_nothing_in_the_cache[device, 4k blocks]` |
| Before the cache: the metadata write of a partial write without FUA | 1 | `test_fsync_on_ext4_leaves_nothing_in_the_cache[device, 1k blocks]` |
| An empty flush completed in `dcorr_map` without reaching the lower device | 3 | `test_fsync_on_the_device_flushes` and the two ext4 cases of the device |

Crash consistency, with `test_crash.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| An empty flush completed in `dcorr_map` without reaching the lower device | 2 | `test_flushed_writes_survive_a_crash`, `test_ext4_survives_a_crash_after_each_fsync[1k blocks]` |
| Before the cache: the metadata write of a partial write without FUA | 1 | `test_ext4_survives_a_crash_after_each_fsync[1k blocks]` |
| Before the cache: the metadata write of a whole chunk without FUA | 1 | `test_ext4_survives_a_crash_after_each_fsync[4k blocks]`; the case with 1 KiB blocks does not catch it |

Lower device errors, with `test_lower_errors.py`:

| Change | Failed | Where |
| ------ | ------ | ----- |
| `complete_work` hands the bio back with `BLK_STS_OK` instead of the status of the part | 10 | All of them |

Lifecycle, with `test_lifecycle.py`:

| Change | Result | Where |
| ------ | ------ | ----- |
| `dcorr_exit` does not unregister the target | Failed, `insmod` gives an error; the kernel then oopses in `get_target_type`, as the target list points into the unloaded module, and needs `deploy/vm.sh reset` | `test_module_unloads_only_without_devices` |
| `dcorr_dtr` does not free the lock table, before it was removed | Failed, one vmalloc area more | `test_nothing_leaks` |
| `cache_free` does not destroy the workqueue of the write back | Failed, one rescuer thread more | `test_nothing_leaks` |
| `dcorr_dtr` does not destroy the workqueue | Failed, one rescuer thread more | `test_nothing_leaks` |
| `dcorr_dtr` does not free the context | **Not caught**, see above | `test_nothing_leaks` |

Metadata in RAM:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver before it (`1c44ae2`), with `test_metadata.py` | Failed, 6 | The two tests that count lower reads: 2 more for the two write backs, 2 lower reads for a read instead of 1; the other 4 for want of the counter |
| An area let go goes to the head of the LRU, not the tail | Failed | `test_the_least_recently_used_region_is_dropped` |
| No drop on suspend | Failed, 18 | `test_a_suspend_drops_the_metadata`, every test of damaged metadata in `test_corruption.py` (one of them an `XPASS(strict)`) and every test of a failed metadata read in `test_lower_errors.py` |
| An area with failed sectors is kept | Failed, 4 | `test_device_works_again_once_the_sector_reads`, the 3 cases of `test_write_fails_when_its_metadata_sector_does_not_read` |
| A failed read of an area marks all its sectors failed, without reading them one at a time | Failed | `test_failed_metadata_sector_fails_only_the_chunks_it_covers` |
| Whoever starts the read of an area does not wait for it | Failed, 3 | The 3 tests of `test_cache.py` with the metadata delayed |

Both copies of the metadata, the trailing one written after a flush:

| Change | Result | Where |
| ------ | ------ | ----- |
| A read checks the leading entry twice, ignoring the trailing one | Failed, 3 | The leading cases of `test_crc_corruption_in_one_copy_is_covered_by_the_other` and `test_a_zeroed_metadata_sector_in_one_copy_fails_nothing` |
| A leading sector that failed to read is not filled from the trailing copy | Failed | `test_a_failed_leading_sector_is_rebuilt_from_the_trailing_copy`; `test_metadata_sector_failed_in_one_copy_fails_nothing_and_warns` passed, as the area came back into pages that held the same region |
| The trailing copy is never written | Failed, 6 | *test_layout_of_the_first_chunks_of_two_regions*, since replaced by `test_layout_of_the_chunks_at_the_borders`, `test_metadata_is_written_outside_the_data`, `test_the_trailing_copy_is_written_after_a_flush`, `test_the_driver_flushes_by_itself_when_half_the_areas_are_pinned`; in a run of its own, both cases of `test_a_write_cut_between_data_and_metadata_reads_old_or_new` |
| A failed trailing write counts as written | Failed | `test_failed_trailing_write_is_counted_and_warned` |
| The worker never flushes by itself when the areas are busy | Hang, exit code 3 | `test_the_driver_flushes_by_itself_when_half_the_areas_are_pinned`: the write back waits for an area for ever |

The two copies as the two CRCs:

| Change | Result | Where |
| ------ | ------ | ----- |
| The leading copy without FUA | Failed, 2 | Both cases of `test_the_leading_copy_is_durable_before_the_data`; the replays pass, as the log is in the order of completion |
| No barrier, with the check of the counter taken out of the test | Failed | `test_a_chunk_written_back_twice_between_flushes_reads_one_of_its_versions`: the chunk does not read after a crash at entry 7 |
| No read before a write back, with the check of the counters taken out of the crash test | Failed, 4 | `test_a_second_crash_after_one_between_the_copies[data]`, the 3 tests of a read before a write in `test_corruption.py`; the `[leading copy]` case passes, as it should: the trailing copy matches there. Before the settle after a read; since, the `[data, not read]` case has the place of `[data]` |
| No read before a write back, since the settle after a read (2026-11-21) | Failed, 2, on the counter | `test_a_second_crash_after_one_between_the_copies[leading copy]` and `[data, not read]`; `[data]` passes, as the read after the crash settles it |
| The trailing copy written by the settle without FUA | Failed | `test_a_second_crash_after_one_between_the_copies[data, not read]`, the chunk fails after a crash at entry 1; `[data]` passes, as its settle runs on a replay outside the log and is flushed when the replay is removed |
| No settle after a read that matched only the leading copy (the code before 2026-11-21, `df18907`) | Failed: the old data put back passes, strict `xfail` in every run before | `test_old_data_put_back_fails_once_the_new_was_read` |
| The trailing copy takes the whole entry of a chunk, not only the sectors written | Failed | `test_only_the_sectors_written_are_read_first` |
| A trailing sector takes the CRCs of only the first chunk written back in it | Failed | `test_chunks_of_a_region_cut_between_flushes_read_old_or_new_each`; the tests of one chunk pass |

Waits, with the two tests that replaced the unstable test of memory:

| Change | Result | Where |
| ------ | ------ | ----- |
| The limit on parts in flight is 16384 instead of 4096 | Failed | `test_parts_in_flight_stay_under_the_limit` |
| A wait for a free entry is not counted | Failed | `test_writes_larger_than_the_cache_wait_for_free_entries` |
| No write back under pressure, only by age and for a flush | Passed, as it should | `test_writes_larger_than_the_cache_wait_for_free_entries`: writes still wait and all arrive; the test checks the waits, not why the cache drains |

The superblock, with `test_superblock.py` and `test_data.py`:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver does not check the CRC of the header | Failed | `test_a_damaged_crc_is_refused` |
| The copy with the smaller generation is taken | Failed, 2 | Both cases of `test_the_copy_with_the_larger_generation_is_taken` |
| The driver does not check the number of the group | Failed, 2 | `test_a_wrong_field_in_group_1_is_seen[group]`, `test_copies_with_the_numbers_swapped_are_refused` |
| The probe of group 1 starts at 1 GiB instead of 16 MiB | Failed, 5 | `test_group_1_is_found_for_each_size_when_group_0_is_damaged` for 16, 32 and 64 MiB, `test_one_damaged_copy_is_covered_by_the_other[0]`, `test_a_format_with_larger_groups_wipes_group_1_of_the_smaller_sizes` |
| The slot of a chunk ignores the groups, `sector / 8`, so data runs into the parity columns | Failed, 7 | `test_layout_of_the_chunks_at_the_borders`, `test_data_lands_at_the_layout_position[across groups]`, `test_the_last_chunk_of_the_device`, `test_every_region_lies_where_the_layout_says`, `test_data_never_lands_in_the_parity_columns_nor_outside_the_regions`, both cases of `test_a_large_device` |
| The trailing copy of the last region of a group goes into the next group | Failed | `test_layout_of_the_chunks_at_the_borders` only; the other tests see both copies equal wherever they are |
| One region less per group, for the driver and `dcorrsetup` both | Failed, 129 | Nearly every test of `test_superblock.py`, `test_data.py`, `test_target.py`: `harness.py` gives another capacity |
| No short last group, for both | Failed, 8 | The smallest device, the layouts on 25.25 and 42 MiB, the probe on 2.5 groups, the headers on 42 MiB, the regions, the parity columns |
| `dcorrsetup` leaves the salt out of the CRC of a block of the bitmap | Failed, 2 | Both cases of `test_the_header_of_every_group_holds_its_superblock_and_bitmaps` |
| `dcorrsetup` does not wipe the starts of group 1 of smaller sizes | Failed | `test_a_format_with_larger_groups_wipes_group_1_of_the_smaller_sizes` |

The groups, on 1b, ran with `test_superblock.py`, `test_data.py` and `test_target.py` only. The mutations of
step 1 about copy 1 in the middle no longer apply, as there is no middle copy.

The bitmap of written chunks, with `test_bitmap.py` and
`test_crash.py::test_first_writes_cut_anywhere_read_zeros_or_new`; all 19 caught:

| Change | Result | Where |
| ------ | ------ | ----- |
| A chunk never written is read from the lower device | Failed, 3 | `test_a_device_of_random_data_reads_zeros_once_formatted`, `test_a_block_of_another_place_or_device_is_not_taken[nothing]`, the crash test |
| A first write is not filled with zeros around it | Failed, 2 | `test_a_first_write_reads_back_with_zeros_around_it`, the crash test |
| A chunk never written is settled before its write back | Failed | `test_a_first_write_reads_back_with_zeros_around_it`: the settle reads the random data and counts mismatches |
| The bit is never set | Failed, 16 | Every test that writes, the crash test among them |
| The generation of the copies is ignored, the leading taken | Failed | `test_the_copy_with_the_larger_generation_is_taken[leading]`; the trailing case passes, as the leading copy is the newer there |
| The CRC of a block is not checked | Failed, 6 | The four cases of `test_one_damaged_copy_is_covered_and_repaired`, `[salt]` of `test_a_block_of_another_place_or_device_is_not_taken`, `test_a_block_invalid_in_both_copies_makes_its_range_read_only` |
| The group of a block is not checked | Failed | `test_a_block_of_another_place_or_device_is_not_taken[group]` |
| The index of a block is not checked | Failed | `test_a_block_of_another_place_or_device_is_not_taken[index]` |
| The role of a block is not checked | Failed | `test_a_block_of_another_place_or_device_is_not_taken[role]` |
| A block with one valid copy is not repaired | Failed, 2 | The writable cases of `test_one_damaged_copy_is_covered_and_repaired` |
| A block with one valid copy is repaired with a read only table too | Failed, 2 | The read only cases of `test_one_damaged_copy_is_covered_and_repaired` |
| Writes to the range of a block invalid in both copies are not refused | Failed | `test_a_block_invalid_in_both_copies_makes_its_range_read_only` |
| That range reads as zeros, not from the lower device | Failed | `test_a_block_invalid_in_both_copies_makes_its_range_read_only` |
| A failed write of the first copy does not fail the flush | Failed | `test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write` |
| The second copy is never written | Failed, 11 | The tests that look at both copies on the lower device |
| The superblocks of groups 2 and on are not checked | Failed, 3 | `test_the_superblock_of_every_other_group_is_checked`, all but `[nothing]` |
| A superblock of another device is taken | Failed | `test_the_superblock_of_every_other_group_is_checked[another device]` |
| The generation of those superblocks is not compared | Failed | `test_the_superblock_of_every_other_group_is_checked[another generation]` |
| The bitmap read in the constructor, not on the first resume | Failed, 3 | Both cases of `test_a_reload_keeps_the_bits_the_old_table_sets`, `test_table_reload_under_load`; the first full run found it there |

Repeat this after large changes to the tests. `deploy/vm.sh sync` restores the copy in the VM.

Discard, with the tests whose names hold `discard`; the 14 failed on the driver of step 3, as it refused
discards. 4 of 5 caught:

| Change | Result | Where |
| ------ | ------ | ----- |
| No sync before the first write back of a chunk with its bit clear while a clear is not durable | Failed, 2 | `test_a_write_after_a_discard_is_written_whole_after_a_barrier` and the crash test, on the counters: the chunk is settled instead, which is the fallback and safe. With that settle taken out too and the check of the counters dropped, the crash test fails on the read: the chunk gives `EIO` after a crash at the first entry |
| The entries of the range are not dropped | Failed | `test_data_in_the_cache_is_dropped_by_a_discard` |
| The sync never records the clears it made durable | Failed, 2 | `test_a_second_write_after_a_flushed_discard_needs_no_barrier`, the crash test |
| A discard into a read only range is not refused | Failed | `test_a_discard_touching_a_read_only_block_fails_whole` |
| The partial chunk at the head of a discard is discarded too | Passed | Not reachable from userspace, see "What is not tested yet" |

Lost writes, with `test_lost_writes.py`; all 3 caught:

| Change | Result | Where |
| ------ | ------ | ----- |
| The trailing copy of the metadata is never written | Failed, 3 | Both cases of the rewrite, which then reads old after the flush too, and the lost leading copy |
| The seed is zero | Failed | `test_lost_data_of_a_first_write_fails_at_once`: zeros below with zero metadata pass |
| The second copy of a block of the bitmap is never written | Failed | `[leading]` of the bitmap test: the bit is lost; `[trailing]` passes, as the trailing copy is the second one |

The seed of the CRC of data, with `test_corruption.py`; all 3 caught:

| Change | Result | Where |
| ------ | ------ | ----- |
| The seed is the CRC of the salt only, without the logical sector | Failed, 4 | The model test, `test_chunk_copied_elsewhere_is_detected`, the sectors swapped, the region shifted |
| The seed is the logical sector only, without the salt | Failed, 2 | The model test, `test_a_chunk_from_another_device_is_detected` |
| The settle before a write back computes the CRC with a zero seed | Failed, 2 | Both cases of `test_a_sector_whose_copies_differ_is_read_before_it_is_written`: the settle counts mismatches |

The cache, with `test_cache.py` and the tests changed for it:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver before the cache (`b07497f`), with these tests | Failed, 3 | `test_a_write_reaches_the_lower_device_on_a_flush`, `test_writes_fail_while_reads_go_on`, `test_a_cache_full_of_failed_chunks_refuses_writes`; the others of `test_cache.py` pass on a driver that writes through |
| `BlockDevice.flush` does nothing | Failed, 38 | The tests that look at or damage the lower device after a write, in `test_data.py`, `test_corruption.py`, `test_lower_errors.py`, `test_target.py` |
| No write back by age (100 s instead of 1 s) | Failed | `test_dirty_data_is_written_back_by_age` |
| A FUA write completes at once, as a plain write | Failed, 2 | The two device cases of `test_fsync_on_ext4_leaves_nothing_in_the_cache`; `test_a_dsync_write_reaches_the_lower_device` cannot tell, as `RWF_DSYNC` on a block device also does an fsync |
| No write back on suspend | Failed, 2 | `test_a_suspend_writes_back`, `test_data_survives_recreating_the_device` |
| The whole chunk counts as dirty | Failed, 2 | `test_a_partial_chunk_writes_only_its_sectors`, `test_a_read_of_a_partly_dirty_chunk`; only since the fixture writes another chunk after the original, as a freed entry comes back with its page unchanged |
| A read copies the whole bio from the cache | Failed, 2 | `test_a_read_of_a_partly_dirty_chunk`, `test_a_dirty_sector_reads_while_a_clean_one_is_damaged` |
| A flush does not try failed chunks again | Failed, 2 | `test_writes_fail_while_reads_go_on`, `test_a_cache_full_of_failed_chunks_refuses_writes` |

Metadata in an area per region, with the tests changed for it:

| Change | Result | Where |
| ------ | ------ | ----- |
| The write backs go one at a time per chunk, not per metadata sector | Failed, `Input/output error` | *test_the_write_backs_of_chunks_sharing_a_metadata_sector_go_one_at_a_time*; *test_the_write_backs_of_a_chunk_go_one_at_a_time* passed, as it should. Both since replaced by the tests over `dm-delay` that `wait_for_its_metadata` |
| `update_crc_local` keeps only the entry of its own chunk, the neighbours lose theirs | Failed, 39 | `test_corruption.py`, `test_cache.py`, `test_lower_errors.py` |
| The data ignores the regions, at `256 + s`, the metadata does not | Failed, 3 | *test_layout_of_the_first_chunks_of_two_regions*, `test_data_lands_at_the_layout_position[across regions]`, *test_the_last_chunk_of_a_short_region*, both since replaced with the groups |
| The write back does not wait for the reads in flight on its chunk, with the data delayed now | Failed, `Input/output error` | `test_a_write_back_waits_for_a_read_in_flight` |

Errors as a signal, stage 5, with the tests of the counters, the event and the log:

| Change | Result | Where |
| ------ | ------ | ----- |
| A read with damaged sectors counts one mismatch, not one per sector | Failed | `test_every_damaged_sector_of_a_read_is_counted_and_logged`; the flood test passes, one damaged sector a read |
| The mismatch is logged without a rate limit | Failed | `test_a_flood_of_mismatches_is_counted_whole_and_logged_rate_limited` |
| No event is raised | Failed | `test_the_first_error_raises_one_device_mapper_event` |
| An event at every error | Failed | `test_the_first_error_raises_one_device_mapper_event` |
| The log names the device by major:minor | Failed, 2 | `test_a_failed_read_is_counted_and_logged_with_the_device`, `test_every_damaged_sector_of_a_read_is_counted_and_logged` |
| A failed flush is not counted | Failed | `test_a_failed_flush_is_counted` |
| An older valid copy of a block of the bitmap is not marked to be written (the code before 2026-11-21, `3a08f98`) | Failed: the chunk of the newer reads as zeros, strict `xfail` in every run before | `test_an_older_copy_is_rewritten_before_the_newer_is_lost` |
| A failed flush unpins the areas and forgets their chunks, and a failed barrier still writes back (the code before 2026-11-21, `007c904`) | Failed: no barrier after the failed flush, and the write back sent, `write_errors` 1 | `test_a_chunk_written_back_again_after_a_failed_flush_takes_a_barrier`, `test_a_chunk_whose_barrier_fails_is_not_written_back` |
| A failed read of a copy of an area counts 1, not its sectors | Failed | `test_a_failed_metadata_read_is_counted_in_sectors` |
| A failed write back is not counted | Failed, 4 | `test_failed_write_is_reported` |
| A failed read is not counted | Failed | `test_a_failed_read_is_counted_and_logged_with_the_device` |

Limits and write zeroes, stage 5:

| Change | Result | Where |
| ------ | ------ | ----- |
| The driver before them (`e932f3c`), with these tests | Failed, 4 | `test_the_device_offers_discard_in_chunks_and_write_zeroes`, `test_write_zeroes_reads_zeros_and_keeps_the_neighbours`, `test_the_limits_are_those_of_a_chunk_over_the_lower_device`, `test_a_lower_device_with_4k_logical_blocks_is_refused`; the rest pass on ordinary writes of zeros, as they should |
| The partial chunk at the start is not zeroed | Failed, 6 | Every test of write zeroes over written data |
| The partial chunk at the end is not zeroed | Failed, 5 | The same but the one inside one chunk, which has no end of its own |
| The whole chunks are not cleared | Failed, 5 | The same |
| A partial chunk zeroes its whole entry | Failed | `test_write_zeroes_over_data_in_the_cache`: elsewhere the other sectors of the entry are not in its mask |

A read cut to 0 sectors by `dm_accept_partial_bio` makes device mapper send it again and again, until the
write back by age frees the entry and the read goes to the lower device, with the right data. The read tests
check that the chunk is still dirty after the read, so such a bug fails them.

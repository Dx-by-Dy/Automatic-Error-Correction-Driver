# TODO

How the driver works is in [README.md](README.md) and `docs/`; how to build and
run it is in [CLAUDE.md](CLAUDE.md). This file holds only what is not done yet.
The order of work is in [Stages](#stages), at the end.

Problems below were found at commit `086ef3c`, on Fedora 45 with kernel
`7.2.15+debug`, a virtio disk as `/dev/vdb`. **Confirmed** means it was observed
in a run, **From reading** means it was only found in the code.

## Memory and locking

- **Use-after-free in `trn_rq_submit`.** Confirmed: KASAN reports a
  `slab-use-after-free` read there, 10 times over a short fio run at sizes from 4k to 1m.
  After the last `queue_work`, `list_for_each_entry_safe` reads `req->parts.next`,
  but all parts may already have completed and freed `req`. Fix: move the parts to a local
  list before queueing, or keep a reference on `req` until the loop ends.
- **The chunk lock is released by another task.** Confirmed: the `rw_semaphore` is taken in
  `submit_work` and released in `complete_work`. The kernel reports `workqueue leaked
  atomic, lock or RCU` and a `DEBUG_RWSEMS_WARN_ON` in `__up_write`, then lockdep reports a
  possible circular dependency between `&lock->sem` and `transformation_wq` and turns itself
  off (`debug_locks: 0`). **Until this is fixed, lockdep checks nothing else in the system.**
  An `rw_semaphore` is not meant for this; the kernel has no non-owner `up_write`. Fix: a chunk
  lock of our own (state and a list of waiting parts under a spinlock), where the part that
  releases the lock queues the next one.
- **Workers can block the work that would release them.** From reading: `submit_work` sleeps
  on the chunk lock in the same workqueue that runs `complete_work`, which releases it. If
  all active workers wait on a lock whose owner's `complete_work` is still queued, I/O stops
  for good. Many requests to one chunk should be enough. Not reproduced yet; the lock
  above would fix this too. Worth a test first: a concurrent fio run on one chunk, more
  in flight than `max_active`.
- **Several bios from one bioset in one context.** From reading: `trn_rq_init` allocates 2-3
  bios per chunk from `transform_bs` (128 reserved) in `dm_map`, before submitting any.
  A 1 MiB request needs over 500. Under memory pressure this can wait for bios that are
  never freed, because they are not submitted yet. Fix: allocate in the worker, or
  one bioset per kind of bio.
- **`dm_map` reads `bio` after it may have completed.** From reading: when `trn_rq_init` returns
  NULL, the bio may already have been ended, and `DM_ERR` then reads its fields.
- **`check_crc` reads `md` after `kunmap_local`.** From reading: the `DM_ERR` on a mismatch
  uses `md` after it was unmapped. Harmless on x86_64 without highmem, still wrong.

## Integrity and durability

- **`fsync` does not reach the lower device.** Confirmed: `vdb` is `write back`, the dm device is
  `write through`. An `fsync` on the dm device gives 0 flush bios on `vdb`, the same `fsync` on
  `vdb` itself gives 1. A filesystem believes its data is durable while it is in the lower
  device's cache. `num_flush_bios` is not set, and the `REQ_OP_FLUSH` branch in `dm_map` is
  dead code, since a flush arrives as an empty `REQ_OP_WRITE` with `REQ_PREFLUSH`. Fix: enable
  flushes, handle the empty bio, carry FUA over to both the data and the metadata.
- **A zeroed chunk passes the check.** Confirmed: with a chunk and its metadata sector zeroed
  on the lower device, the read succeeds and returns zeros. CRC64 of zeros with a zero seed is
  0, the same as empty metadata. A lost or trimmed region is never noticed. Fix: a non-zero
  seed, plus a way to tell unwritten chunks from written ones (see the next item).
- **A fresh device has to be zeroed by hand.** From reading: there is no superblock, format
  version or "never written" state. On a device with old contents every read fails, and
  `corrdm_reinit.sh` zeroes only the first 1 GiB.
- **The CRC does not depend on the position.** From reading: the sector number is not part of
  the CRC, so a misdirected write, or a chunk with its metadata copied elsewhere, passes the
  check. Fix: mix the sector number into the seed.
- **Data and CRC are not written atomically.** From reading: they are two independent bios, so
  after a power loss a chunk may have new data and an old CRC, and reads fail on data that
  is fine. It is the same when the metadata bio of a partial write fails after its data bio
  succeeded. Needs a decision (journal, or tolerate and resolve through ECC) and a crash test
  with `dm-log-writes`.
- **Pages can change after their CRC is computed.** From reading, with `stable_writes=0`
  confirmed: the CRC is computed in `dm_map` and the pages are submitted later, without a copy.
  A page changed in between (`mmap`, a buffer in use during O_DIRECT) gives a CRC that does not
  match the data, then a false mismatch on read. Fix: request stable writes in `io_hints` and
  check it is enough, or write from a copy.
- **The metadata sector has an uninitialized tail.** From reading: `alloc_page` is not zeroed, and
  only 64 of the 512 bytes are filled before the sector goes to disk. The run showed zeros, but
  `init_on_alloc` is on here and hides it. Without it, kernel memory reaches the disk.
  Fix: `__GFP_ZERO`.
- **Other request types bypass the CRC.** From reading: the `REQ_OP_DISCARD` and `default`
  branches in `dm_map` only remap the start sector, so a range would also cover metadata sectors.
  They do not run today (`discard_max_bytes=0` confirmed). Either remove them, or implement
  discard along with the "never written" state.

## Device Mapper integration

- **`dmsetup table` does not show the device.** Confirmed: it prints `0 14913080 corrdm` with no
  arguments, as there is no `.status`, so the table cannot be saved and reloaded. `.status` is
  also the natural place for counters such as CRC mismatches, which do not exist today.
- **The table length is ignored.** Confirmed: `dm_ctr` overwrites `ti->len` (16777216 requested,
  14913080 used). Fix: require a correct length, return an error otherwise, and print the
  right value with a helper command.
- **Queue limits are not inherited.** From reading: there is no `.iterate_devices` or `.io_hints`.
  A lower device with 4K logical blocks is not rejected, although metadata is written
  as single 512-byte sectors.
- **Mismatch logging has no rate limit.** From reading: each failed read prints a line with
  `pr_err`, so a reader in a loop can flood the log. The line also gives the physical sector,
  and nothing identifies the device.

## Correction

The goal of the project; only detection exists today.

- **No design yet:** which code, what it corrects (bits, a sector, a whole chunk), where the
  redundancy lives and how much space it takes, and how it combines with the CRC.
- **Recovery path:** the entry point is marked in `check_crc`. It needs a retry of the read,
  rewriting the fixed data, and counters. This depends on copying `orig_bio` so a whole request
  can be retried.

## Optimization and cleanup

Carried over from the previous list.

- **Large blocks break invariants (`bs >= 32k`).** Not reproduced: fio verify with `randwrite`,
  `iodepth=16`, `numjobs=1` and 128 MiB passes from 4k to 1m with no CRC mismatch. Which invariant
  broke and under what load is not recorded; next, try `numjobs=8` and a filesystem.
- **Benchmarks are not formalized.** `benchmarks.py` has hardcoded devices, test sets commented
  in and out by hand, and needs `pandas` and `matplotlib`. Numbers need a non-debug kernel.
- **Move `first_sector` and `nr_sectors` into `struct trn_p_rq`.**
- **Use preallocation where possible.**
- **Use the Crypto API to speed up CRC64.**
- **Cache hot metadata blocks** (a lock on the cache and a state machine).

## Tests and tooling

- **`tests.py` cannot fail on undetected corruption.** From reading: when the read succeeds it
  prints `ERROR: corruption not detected` and still exits 0. The output of fio is dropped as well.
- **`tests.py` itself damages neighbouring sectors.** Confirmed: `corrupt_sector` uses a buffered
  `dd` on `/dev/vdb`, while `clear_disk` has left zeros in the page cache. Zeroing sector 8 writes
  the whole 4 KiB block back, wiping sectors 9-15, and untouched chunk 1 then fails to read.
  Corruption must use `oflag=direct`.
- **Tests that do not exist yet** (pytest, in the VM, one fixture per device):
  - data: comparison with a reference copy, unaligned requests, chunk boundaries, end of the
    device, sizes from 512 bytes to 1 MiB;
  - corruption: every data and metadata sector, neighbouring chunks stay readable, a partial
    write keeps the CRCs of its neighbours;
  - lower device errors, through `dm-flakey` and `dm-dust`;
  - load: fio verify, and concurrent writes to one chunk;
  - lifecycle: bad arguments, removal under load, unloading the module, leaks through kmemleak;
  - filesystems: ext4 and xfs;
  - crash consistency: `dm-log-writes`.
- **No static checks.** A `make check` with `W=1`, `sparse` and `checkpatch`.
- **`deploy/vm.sh test` fails today**, because of the kernel reports above. That is correct, and it
  will not pass before the first items of [Memory and locking](#memory-and-locking) are fixed.

## Documentation

- **The README uses the wrong target name.** Confirmed: it says `correction_driver`, the target is
  `corrdm`, so its `dmsetup create` command fails. It also passes a length that is not used.
- **The README claims functional testing is done**, and does not mention the VM.
- **`MODULE_DESCRIPTION` says "Linux Kernel 6.16"**, while the driver builds on 7.1 and 7.2.

## Open questions

- Should a CRC cover a 512-byte sector or the whole 4 KiB chunk? Per sector takes 64 bytes per chunk
  and can tell which sector is bad, which matters for correction.
- Should metadata stay next to the data? It makes a metadata write a seek and splits
  sequential I/O; a separate area would change the on-disk format, so decide before ECC.

## Stages

1. **Trustworthy tests.** Replace `tests.py` with the pytest suite, starting with data and corruption,
   and add `make check`. Failures already known go in as `xfail` with a link to the item here.
2. **Memory and locking.** Fix the use-after-free, replace the chunk lock so lockdep stays on, then
   clean up the rest of [Memory and locking](#memory-and-locking). Done when `deploy/vm.sh test` is
   clean under load, and the `bs >= 32k` question is answered.
3. **Integrity and durability.** Flushes first, as they lose data today; then stable pages, seed and
   position in the CRC, the on-disk format, crash tests.
4. **Device Mapper integration and docs.** `.status` with counters, table length, queue limits,
   the README.
5. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, to compare the
   later stages against.
6. **Correction.** Settle the open questions, design the code and the format, implement recovery.
7. **Optimization.** Metadata cache, preallocation, Crypto API, guided by the baseline.

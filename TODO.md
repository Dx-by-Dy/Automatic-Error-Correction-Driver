# TODO

How the driver works is in [README.md](README.md) and `docs/`; how to build and
run it is in [CLAUDE.md](CLAUDE.md); the tests are described in
[correction-driver/tests/README.md](correction-driver/tests/README.md). This file holds only what is
not done yet.
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
- **Workers block the work that would release them.** Confirmed: this is the hang under load.
  `submit_work` sleeps on the chunk lock in the same workqueue that runs `complete_work`, which
  releases it. When all 1024 active workers (`WQ_DFL_ACTIVE`) wait on locks, the `complete_work`
  items stay queued behind them and I/O stops for good, with nothing in flight on the lower
  device. A request takes one item per 4 KiB chunk, so it takes more items than workers once
  `numjobs * iodepth * chunks per request > 1024` on a shared area. With `numjobs=8` and
  `iodepth=32`, `bs=16k` is exactly 1024 and passes, while `bs=32k` is 2048 and hangs. That is
  why it appeared as `bs >= 32k`; `bs=16k` with `numjobs=32` hangs as well. Reproduce with
  `deploy/vm.sh test -m known_hang -k "32k and write"`. Replacing the chunk lock as described
  above fixes this too, as a worker then never sleeps on a chunk.
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
- **The CRC does not depend on the position.** Confirmed: a chunk copied with its metadata over
  another chunk reads back without an error, as the sector number is not part of the CRC. A
  misdirected write would pass the same way. Fix: mix the sector number into the seed.
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

- **Benchmarks are not formalized.** `benchmarks.py` has hardcoded devices, test sets commented
  in and out by hand, and needs `pandas` and `matplotlib`. Numbers need a non-debug kernel.
- **Move `first_sector` and `nr_sectors` into `struct trn_p_rq`.**
- **Use preallocation where possible.**
- **Use the Crypto API to speed up CRC64.**
- **Cache hot metadata blocks** (a lock on the cache and a state machine).

## Tests and tooling

- **Tests that do not exist yet:**
  - lower device errors, through `dm-flakey` and `dm-dust`;
  - lifecycle: removal under load, unloading the module, leaks through kmemleak;
  - crash consistency: `dm-log-writes`.
- **`sparse` does not run.** The kernel requires `__typeof_unqual__`, which sparse 0.6.4 from
  Fedora does not support, so `make check` prints a warning and skips it. It takes a build from
  upstream sources.

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

1. **Trustworthy tests.** Data, corruption, filesystem, fio and target tests are in place, known bugs
   are strict `xfail` or `known_hang`, `make check` is clean. What is left: lower device errors,
   lifecycle, `sparse`.
2. **Memory and locking.** Fix the use-after-free, replace the chunk lock so lockdep stays on and the
   hang is gone, then clean up the rest of [Memory and locking](#memory-and-locking). Done when
   `KNOWN_KERNEL_REPORTS` in `tests/conftest.py` is empty and the `known_hang` tests pass as normal
   tests.
3. **Integrity and durability.** Flushes first, as they lose data today; then stable pages, seed and
   position in the CRC, the on-disk format, crash tests.
4. **Device Mapper integration and docs.** `.status` with counters, table length, queue limits,
   the README.
5. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, to compare the
   later stages against.
6. **Correction.** Settle the open questions, design the code and the format, implement recovery.
7. **Optimization.** Metadata cache, preallocation, Crypto API, guided by the baseline.

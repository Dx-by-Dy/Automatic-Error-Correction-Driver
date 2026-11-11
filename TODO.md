# TODO

How the driver works is in [README.md](README.md) and `docs/`; the global decisions (threat model,
contract, format, cache) are in [ARCHITECTURE.md](ARCHITECTURE.md); how to build and
run it is in [deploy/README.md](deploy/README.md); the tests are described in
[correction-driver/tests/README.md](correction-driver/tests/README.md). This file holds only what is
not done yet.
The order of work is in [Stages](#stages), at the end.

How to keep this file:

- Remove an item once it is done; the history is in git. How the driver works belongs in `README.md`
  and `docs/`, not here.
- Group items by topic under `##` headings. Start an item with a short bold statement of the problem,
  then give the cause, the consequence and a way to fix it, if known.
- Say how a problem is known, as below. Do not promote an item to **Confirmed** without a run.
- `## Stages` stays the last section and gives the order of work. Update it when items are added or
  finished.

Problems below were found at commit `086ef3c`, on Fedora 45 with kernel
`7.2.15+debug`, a virtio disk as `/dev/vdb`. **Confirmed** means it was observed
in a run, **From reading** means it was only found in the code.

## Integrity and durability

- **A zeroed chunk passes the check.** Confirmed: with a chunk and its metadata sector zeroed
  on the lower device, the read succeeds and returns zeros. CRC64 of zeros with a zero seed is
  0, the same as empty metadata. A lost or trimmed region is never noticed. Fix: a non-zero
  seed, plus a way to tell unwritten chunks from written ones (see the next item).
- **A fresh device has to be zeroed by hand.** From reading: there is no superblock, format
  version or "never written" state. On a device with old contents every read fails, and
  `deploy/vm.sh reinit` zeroes only the first 1 GiB.
- **The CRC does not depend on the position.** Confirmed: a chunk copied with its metadata over
  another chunk reads back without an error, as the sector number is not part of the CRC. A
  misdirected write would pass the same way. Fix: mix the sector number into the seed.
- **Data and CRC are not written atomically.** From reading: they are two independent bios, so
  after a power loss a chunk may have new data and an old CRC, and reads fail on data that
  is fine. It is the same when the metadata bio of a partial write, its read of the old
  metadata or its write of the new, fails after its data bio succeeded. Confirmed by the crash tests, which are strict `xfail` for it. Two CRCs are to be tried first, see
  "Cache" in `ARCHITECTURE.md`.
- **No discard.** The device does not offer it (`discard_max_bytes=0`), and `dm_map` refuses any
  operation other than read, write and an empty flush. Discard needs the "never written" state,
  so that a discarded chunk does not fail its check.

- **A failed metadata sector fails 8 chunks.** By design of the layout: a metadata sector holds the entries of
  8 chunks, so when it cannot be read, the reads of all of them fail, and so do the write backs, which read it
  first. Fix: the copy of the metadata in the next region, which the layout has room for; reads fall back to it,
  and every change of metadata costs a second write.

## Device Mapper integration

- **`dmsetup table` does not show the device.** Confirmed: it prints `0 14913080 corrdm` with no
  arguments, as `.status` gives nothing for `STATUSTYPE_TABLE`, so the table cannot be saved and
  reloaded. `dmsetup status` has only the counters of waits and of dirty and failed entries of the
  cache; counters such as CRC mismatches do not exist yet.
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
  rewriting the fixed data, and counters. The clone of a chunk is ours until `bio_endio`, with its
  iterator saved in `saved_iter`, so a read can be submitted again from `complete_work`.

## Optimization and cleanup

Carried over from the previous list.

- **Benchmarks are not formalized.** `benchmarks.py` has hardcoded devices, test sets commented
  in and out by hand, and needs `pandas` and `matplotlib`. Numbers need a non-debug kernel.
- **Move `first_sector` and `nr_sectors` into `struct trn_p_rq`.**
- **Use preallocation where possible.**
- **Use the Crypto API to speed up CRC64.**
- **Metadata is not kept in RAM.** From reading: the cache holds only dirty data. A read of sectors not in the
  cache reads the metadata sector of the chunk along with the data, also right after a write back, as a written
  entry is freed at once (`cache_finish_entry`). Every write back reads the metadata sector first, as it holds
  the entries of 8 chunks, so the metadata write waits for a lower read, and the write backs of the chunks of one
  sector go one at a time. Two CRCs need the old CRCs of every chunk written back as well. Fix: keep metadata
  sectors in RAM, clean and dirty, kept in step with write back; the next step of the cache.
- **A write to a chunk under write back waits.** By decision, for simplicity: a hot chunk stalls its writers
  for the length of a lower write. Fix: a second copy of the chunk, as `dm-writecache` does. A cheaper partial
  fix: a mask of the sectors under write back, so that only writes to those sectors wait.
- **A FUA write writes back the whole cache.** By decision, one path of code with the flush. Fix: write back
  only the chunks of the bio, with FUA.
- **One spinlock for the whole cache.** It is held only for a lookup and a copy of at most 4 KiB, but every
  request takes it, and a read from the lower device twice, to register in the tree of reads in flight and
  leave it. Not measured. Fix: locks per part of the tree, as `dm-bufio` hashes its buffers over several trees.
- **A write back waits for reads of its chunk one entry at a time.** By decision, for simplicity: the worker
  waits for the reads in flight on one entry before it sends the next, so a slow read of one chunk delays the
  write back of the others. Fix: mark all the picked entries first and send each once its reads are done.

## Tests

- **`test_memory_of_requests_in_flight_is_limited` is unstable.** Confirmed: it checks that writes waited for
  a free entry of the cache under fio, and none waits when the whole of `test_memory.py` runs (3 runs of 3, also
  on `2b04bad`, before the tree of reads), while alone or after any part of the file tried it gets 900 to 1200
  waits. Something the earlier tests leave lets the write back keep up with fio; not found what. Marked
  `unstable`, so it runs only on request. Fix: find the cause, then check the waits deterministically, with the
  cache over a lower device with slow writes, and keep this test about memory only.
- **Waits for free entries of the cache are not checked.** Confirmed: `test_suspend_and_resume_under_load`
  checked them under fio, and on `90bbfcf`, run alone 5 times, it got no wait twice and 35 and 36 where counted;
  with metadata in areas per region none in three runs, as the write back keeps up with fio. The check was
  removed from it. Fix: with the item above, check the waits on a lower device with slow writes.

## Documentation

- **The README uses the wrong target name.** Confirmed: it says `correction_driver`, the target is
  `corrdm`, so its `dmsetup create` command fails. It also passes a length that is not used.
- **The README claims functional testing is done**, and does not mention the VM.
- **`MODULE_DESCRIPTION` says "Linux Kernel 6.16"**, while the driver builds on 7.1 and 7.2.

## Stages

1. **Test base.** Data, corruption, filesystem, fio, target, durability, crash, lower device error
   and lifecycle tests are in place, known bugs are strict `xfail` or `known_hang`, `make check` is
   clean. What is left: mark the commit before the cache.
2. **Cache.** Designed in `ARCHITECTURE.md`. Written so far: the cache with a write back of one chunk
   at a time, kept apart from reads by the tree of reads in flight instead of chunk locks. Left, in this
   order: metadata in an area per region, metadata in RAM, two CRCs, neighbouring chunks written back as
   one bio, a place to plug in the reserved area, then the cause of the unstable test of memory.
3. **Integrity and format.** Old or new contents after a crash, superblock and version, seed and
   position in the CRC after the threat research, discard, whether to add a reserved area for failed
   write backs.
4. **Device Mapper integration and docs.** `.status` with the table and more counters, table length,
   queue limits, the README.
5. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, for the commit before
   the cache and for the cache.
6. **Correction.** Settle the open questions of `ARCHITECTURE.md`, design the code and the format,
   implement recovery.
7. **Optimization.** Proportions of metadata, preallocation, Crypto API, tuning the limit on parts in
   flight, guided by the baseline.

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
- **A crash together with a lost sector of the other copy fails the chunks that were in flight.** By
  decision: between the write back of a chunk and the flush after it, only the trailing copy has the CRC of the
  old data and only the leading one that of the new. Fix, if the threat model asks for it: a third copy, or ECC.
- **A failed flush of the lower device leaves the trailing copies behind.** From reading: the chunks written
  back before it are forgotten without their trailing copy, so their copies differ, and the read before their
  next write back may see data that is not durable. A device that fails flushes gives no durability anyway.
  Fix, if it matters: keep them pinned and retry, with a way out when the areas run out.
- **No discard.** The device does not offer it (`discard_max_bytes=0`), and `dm_map` refuses any
  operation other than read, write and an empty flush. Discard needs the "never written" state,
  so that a discarded chunk does not fail its check.

- **A metadata sector failed in both copies fails 8 chunks.** By design of the layout: a metadata sector holds
  the entries of 8 chunks, so when neither copy reads, the reads of all of them fail, and so do the write backs,
  which need the other entries. Fix: ECC, or a third copy if the threat model asks for it.
- **A failed copy of a metadata sector is put right only by the next write of that sector.** By decision, for
  simplicity: until a chunk of the sector is written back, it stays with one copy, and a warning is logged at
  every access, rate-limited. A trailing sector that failed to write is counted, not retried. Fix: rewrite the
  failed copy from the other once it is found, in the worker.

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
- **A read of a region whose metadata is not in RAM blocks `dm_map`.** By decision, for simplicity: the read of
  the metadata area is waited for in `dm_map`, so a submitter with many requests in flight stalls for one lower
  read each time a request comes to a new region. Fix: a list of the parts waiting for an area, started by the
  end of its read.
- **A metadata area with a sector failed in both copies is read again by every request that finds it unused.**
  By decision, so that a sector that reads again is seen. On a failing device such a request then costs two
  reads of 64 KiB and one read per sector of the failed copy. Fix, if it matters: read again only the failed
  sectors.
- **Two flushes of the lower device per flush from above.** By decision, for simplicity: the second makes the
  trailing copies durable before a chunk can be written back again. The flush from above completes after the
  first. Fix: leave the trailing copies to the next flush, with a state for chunks whose trailing copy is
  written but not yet durable; and make the moment the trailing copy is written configurable.
- **A write back is two requests in a row.** By decision: the leading metadata sector is a FUA write, and the
  data waits for it, so every chunk costs the latency of two writes and a FUA. Fix: runs, with one FUA write of
  a range of the metadata area before the data of the run; or the leading copies of a batch, then a flush, then
  its data.
- **The read before a write back is synchronous in the worker.** It happens only for chunks whose copies
  differ, after a crash or a failed write back. Fix, if it matters: settle them in the background after
  activation.
- **The trailing copies are written one range at a time, synchronously, in the worker.** Each range of an area
  is a request of its own. Fix: send them all, then wait, as runs will do for the data.
- **When half the metadata areas are busy, the worker flushes by itself.** A write back pins its area until the
  trailing copy is written, so random writes over many regions without flushes from above cost a flush of the
  lower device every 16 regions. Counted in `dmsetup status`. Fix, if it matters: more areas, or a pin that
  does not hold the whole area.
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
   at a time, kept apart from reads by the tree of reads in flight instead of chunk locks, metadata in an
   area per region, metadata in RAM, and both copies of the metadata written, the trailing one after a flush.
   The two copies are the two CRCs: the leading one before the data, a flush before a chunk is written back
   again, and a read of a chunk whose copies differ. Left: the cause of the unstable test of memory.
3. **Integrity and format.** Superblock and version, seed and
   position in the CRC after the threat research, discard, whether to add a reserved area for failed
   write backs, and the place in the cache where it plugs in.
4. **Runs.** Neighbouring chunks written back as one bio, as decided in `ARCHITECTURE.md`. After the format,
   as it may change what a write back writes, and before the baseline, so that the cache is measured with them.
5. **Device Mapper integration and docs.** `.status` with the table and more counters, table length,
   queue limits, the README.
6. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, for the commit before
   the cache and for the cache.
7. **Correction.** Settle the open questions of `ARCHITECTURE.md`, design the code and the format,
   implement recovery.
8. **Optimization.** Proportions of metadata, preallocation, Crypto API, tuning the limit on parts in
   flight, guided by the baseline.

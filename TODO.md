# TODO

How the driver works is in [README.md](README.md) and `docs/`; the global decisions (threat model,
contract, format, cache) are in [ARCHITECTURE.md](docs/en/ARCHITECTURE.md); how to build and
run it is in [deploy/README.md](deploy/README.md); the tests are described in
[tests/README.md](tests/README.md). This file holds only what is
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

- **A damaged copy of the superblock stays damaged.** By decision, for now: the driver never writes a
  superblock; it warns about a copy that is not valid each time the device is created, and counts those of
  groups 2 and on in `dmsetup status`. Fix: write it from another copy, with a command of `dcorrsetup`.
- **A block of the bitmap invalid in both copies makes its range read only.** By decision on 2026-11-15: its
  chunks are read as written, so the CRC decides, and writes there fail, for the life of the device: the driver
  never writes such a block, as it does not know which chunks were written. Counted in `dmsetup status`. Fix:
  rebuild the block from the CRCs of its chunks, with `dcorrsetup` or in the correction stage.
- **A copy of a block of the bitmap that failed to write is put right only with the next change of the block.**
  By decision, as for the trailing metadata: until then the block has one copy, and the next change writes the
  failed copy first. Counted. A block found with one copy when the device is created is repaired by the next
  flush, unless the table is read only.
- **A reload after a failed write of the bitmap loses its new bits.** The new table reads the bitmap on its
  first resume, after the old one has written its bitmap on suspend; when that write fails, the new table reads
  the chunks first written since the last good flush as zeros, though their data is on the device. Fix: hand
  the bitmap in RAM from the old table to the new one, or refuse the resume.
- **A stale copy of group 1 in the data can win the probe.** From reading: with group 0 damaged the driver
  takes the first valid copy of group 1 for any size of a group, from the smallest. `dcorrsetup format` wipes
  the starts of group 1 of the smaller sizes, but data written later that holds the image of such a
  superblock for the same device size, a dump of the lower device stored on it, would be taken as well.
  Fix, if it matters: prefer the copy that agrees with other groups, or ask the user to name the size.
- **The device cannot grow.** By decision on 2026-11-15: the size of the lower device must be the one it was
  formatted for. Fix: a feature of its own, adding groups of the same size, as `xfs_growfs` does, rewriting
  every superblock and one trailing copy of the bitmap.
- **The unused end of every group is lost.** By decision on 2026-11-15: a group holds whole regions only, so
  1 to 3.6 MiB of a group of a size other than 1 GiB is not used, and so is a tail of the device shorter than
  a header and two regions. Fix, if it matters: short regions, in the optimization stage.
- **A parity slot has no CRC defined.** By decision on 2026-11-16: the CRC of a data sector takes its logical
  sector, which a slot of a parity column does not have. Fix: define it in the correction stage, from the
  physical slot or the stripe.
- **A crash together with a lost sector of the other copy fails the chunks that were in flight.** By
  decision: between the write back of a chunk and the flush after it, only the trailing copy has the CRC of the
  old data and only the leading one that of the new. Fix, if the threat model asks for it: a third copy, or ECC.
- **A failed flush of the lower device leaves the trailing copies behind.** From reading: the chunks written
  back before it are forgotten without their trailing copy, so their copies differ, and the read before their
  next write back may see data that is not durable. A device that fails flushes gives no durability anyway.
  Fix, if it matters: keep them pinned and retry, with a way out when the areas run out.
- **A lost write passes as the old contents until the flush after its write back.** By decision of the threat
  model: until then the trailing copy holds the old CRC, and the read accepts it; a write lost together with both
  copies of its metadata passes for ever. Not tested: dropped writes need a test with `dm-flakey` and
  `drop_writes`, detected after that flush and passing before it.
- **No write zeroes.** By decision on 2026-11-16: device mapper offers it only through `iterate_devices` with
  every device below capable, which the target does not have, so `blkdev_issue_zeroout` writes zero pages
  through the cache. Correct, only slower. Fix: with `iterate_devices`, under Device Mapper integration, clear
  the bits of whole chunks as a discard does and write the partial ends as zeros.
- **A discard is not durable until the next flush.** By decision on 2026-11-16, as for writes: the cleared bits
  reach the device with the next sync, so after a crash before it the chunks may hold their old data.

- **A metadata sector failed in both copies fails 8 chunks.** By design of the layout: a metadata sector holds
  the entries of 8 chunks, so when neither copy reads, the reads of all of them fail, and so do the write backs,
  which need the other entries. Fix: ECC, or a third copy if the threat model asks for it.
- **A failed copy of a metadata sector is put right only by the next write of that sector.** By decision, for
  simplicity: until a chunk of the sector is written back, it stays with one copy, and a warning is logged at
  every access, rate-limited. A trailing sector that failed to write is counted, not retried. Fix: rewrite the
  failed copy from the other once it is found, in the worker.

## Device Mapper integration

- **`dmsetup table` does not show the device.** Confirmed: it prints `0 14913080 dcorr` with no
  arguments, as `.status` gives nothing for `STATUSTYPE_TABLE`, so the table cannot be saved and
  reloaded. `dmsetup status` has only the counters of waits and of dirty and failed entries of the
  cache; counters such as CRC mismatches do not exist yet.
- **Queue limits are not inherited.** From reading: there is no `.iterate_devices`; `.io_hints` sets only the
  limits of discard. A lower device with 4K logical blocks is not rejected, although metadata is written
  as single 512-byte sectors. Write zeroes waits for `.iterate_devices` too, see above.
- **Nothing warns the user of a failing drive.** By decision of the threat model: the first error is a strong sign
  that a drive is failing, but today it is only a line in the kernel log. Fix: counters of errors and
  mismatches in `dmsetup status` and a device mapper event at the first one. An idea of the user, to think over:
  a daemon that reads SMART and the counters of the driver and warns.
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
- **The first resume reads the header of every group, one after another.** By decision on 2026-11-15, the simple
  way: a request per group, about 76 KiB for groups of 1 GiB, so a seek per group on an HDD. Measured in the
  VM, on a disk in RAM and a debug kernel: 128 groups in 24 ms, 32 in 6 ms, so about 0.2 ms a group without a
  seek, 0.2 s for a TiB in groups of 1 GiB; on an HDD the seeks add around 10 ms a group, so around 10 s for a
  TiB, not measured. Fix: several reads in flight, or the bitmap of a group read when it is first needed.
- **The whole bitmap of written chunks is in RAM.** By decision: 32 MiB per TiB, allocated in the constructor.
- **A chunk whose bit is not on the device yet still takes a barrier.** By decision on 2026-11-15, for
  simplicity: written back twice before a flush, such a chunk reads as zeros after a crash whatever its slot
  holds, so no barrier is needed. Fix: a second bitmap, of the bits on the device.
- **The metadata area of a region with no bit set is read from the device.** Its entries are never used. Fix:
  fill such an area with zeros without a read.
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
- **A chunk written back again before a flush forces a flush (a barrier).** By decision, see "On-disk format" in
  `ARCHITECTURE.md`: after a write back the drive may hold the old or the new version of each sector until a
  flush, and a second write back would make a third with two slots of metadata. Counted as `barriers`. Options,
  asked about by the user on 2026-11-15:
  - **Keep such a chunk dirty until the next flush instead of forcing one**, the choice of the user: the newer
    data waits in the cache, so the drive never holds more than the old and the new version, and the flush
    that comes anyway (from above, or of the trailing copies) settles it. Under memory pressure the worker may
    still have to flush.
  - Take the barrier only where the sectors of the two write backs overlap; the code takes it for the whole
    chunk. Helps partial writes, not full rewrites of a chunk.
  - FUA data writes, after which the trailing copy can take the new CRC at once: cheap on SSDs with power loss
    protection, slow on HDDs.
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

## Documentation

- **The README claims functional testing is done**, and does not mention the VM.
- **`MODULE_DESCRIPTION` says "Linux Kernel 6.16"**, while the driver builds on 7.1 and 7.2.

## Stages

1. **Test base.** Data, corruption, filesystem, fio, target, durability, crash, lower device error
   and lifecycle tests are in place, known bugs are strict `xfail` or `known_hang`, `make check` is
   clean. What is left: mark the commit before the cache.
2. **Integrity and format.** A test of lost writes. The threat model was settled, the superblock written, the
   device laid out in groups with room for parity and the bitmap of written chunks read and written on
   2026-11-15; no reserved area. The seed of the CRC of data, with the logical sector and the salt, and discard
   through the bitmap on 2026-11-16; write zeroes moved to Device Mapper integration.
3. **Runs.** Neighbouring chunks written back as one bio, as decided in `ARCHITECTURE.md`. After the format,
   as it may change what a write back writes, and before the baseline, so that the cache is measured with them.
4. **Device Mapper integration and docs.** `.status` with the table and more counters, queue limits with `iterate_devices` and write zeroes, the
   README.
5. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, for the commit before
   the cache and for the cache, with the memory a load takes through the driver against the lower device:
   on the debug kernel KASAN and kmemleak hold freed bios back, 100 to 535 MiB under `fio` with 1 MiB
   requests, as device mapper makes a clone per 4 KiB.
6. **Correction.** Settle the open questions of `ARCHITECTURE.md`, design the code and the format,
   implement recovery.
7. **Optimization.** Proportions of metadata, preallocation, Crypto API, tuning the limit on parts in
   flight, guided by the baseline.

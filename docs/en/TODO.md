# TODO

What is not done yet: problems, missing features and the order of work, in [Stages](#stages) at the end. How
the driver works is in [ARCHITECTURE.md](ARCHITECTURE.md), why in [DECISIONS.md](DECISIONS.md); what was left
simple for the optimization stage is in [TODO_OPTIMIZATION.md](TODO_OPTIMIZATION.md); how to build and run it is
in [DEPLOY.md](DEPLOY.md); the tests are described in [TESTS.md](TESTS.md).

How to keep this file:

- Remove an item once it is done; the history is in git. How the driver works belongs in `ARCHITECTURE.md`, not
  here; an item that is only about speed belongs in `TODO_OPTIMIZATION.md`.
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
- **A lost write passes as the old contents until the flush after its write back.** Confirmed by
  `test_lost_writes.py`, by decision of the threat model: until then the trailing copy holds the old CRC, and the
  read accepts it; a write lost together with both copies of its metadata passes for ever, which a test pins.
  Fix, for the correction stage: parity computed from the data in RAM, not from what is read back, would make
  such a stripe disagree, and P+Q can tell which member is wrong, so a scrub could find the chunk and rebuild
  it.
- **No write zeroes over a lower device without it.** By decision (D23): device mapper offers write zeroes only
  where every device below has it, so over such a device `blkdev_issue_zeroout` writes zero pages through the
  cache. Correct, only slower. Fix, if it matters: device mapper has no flag for a target that zeroes by itself.
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

- **Nothing is measured by IMA.** By decision on 2026-11-16: `STATUSTYPE_IMA` gives nothing, so a table of the
  driver is measured without its fields. Fix, if IMA is used: the keys and values of the target, as other
  targets give them.
- **Nothing tells the user in person of a failing drive.** By decision (D22): the driver counts the errors and
  raises a device mapper event at the first one, but something has to wait for it. An idea of the user, to think
  over: a daemon that reads SMART and the counters of the driver and warns.

## Correction

The goal of the project; only detection exists today.

- **No design yet:** which code, what it corrects (bits, a sector, a whole chunk), where the
  redundancy lives and how much space it takes, and how it combines with the CRC.
- **Recovery path:** the entry point is marked in `check_crc`. It needs a retry of the read,
  rewriting the fixed data, and counters. The clone of a chunk is ours until `bio_endio`, with its
  iterator saved in `saved_iter`, so a read can be submitted again from `complete_work`.

## Optimization

Moved to [TODO_OPTIMIZATION.md](TODO_OPTIMIZATION.md).

## Stages

1. **Test base.** Data, corruption, filesystem, fio, target, durability, crash, lower device error
   and lifecycle tests are in place, known bugs are strict `xfail` or `known_hang`, `make check` is
   clean. What is left: mark the commit before the cache.
2. **Runs.** Neighbouring chunks written back as one bio, as decided in D12 of `DECISIONS.md`. After the format,
   as it may change what a write back writes, and before the baseline, so that the cache is measured with them.
3. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, for the commit before
   the cache and for the cache, with the memory a load takes through the driver against the lower device:
   on the debug kernel KASAN and kmemleak hold freed bios back, 100 to 535 MiB under `fio` with 1 MiB
   requests, as device mapper makes a clone per 4 KiB.
4. **Correction.** Settle the open questions of `ARCHITECTURE.md`, design the code and the format,
   implement recovery.
5. **Optimization.** The items of [TODO_OPTIMIZATION.md](TODO_OPTIMIZATION.md), guided by the baseline.

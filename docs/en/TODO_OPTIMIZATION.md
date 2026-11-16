# Optimization

What was left simple on purpose while the driver was built, to be revisited in the optimization stage with the
numbers of the baseline ([TODO.md](TODO.md#stages)). Correctness problems are in [TODO.md](TODO.md); why each
simple form was chosen is in [DECISIONS.md](DECISIONS.md). An item is kept as in `TODO.md`: a short bold
statement, the cause, what it costs, and a way to fix it if known; it is removed once done.

## Measuring

- **Benchmarks are not formalized.** `benchmarks.py` has hardcoded devices, test sets commented in and out by
  hand, and needs `pandas` and `matplotlib`. Numbers need a non-debug kernel. Done in the baseline stage, before
  anything here is changed.
- **Defaults are constants.** 64 MiB of cache per device, write back from 50% used down to 45%, an age of 1 s, 32
  metadata areas (4 MiB), 4096 parts in flight, 256 write back jobs (D7, D11). Fix: tune them on the baseline, and
  make the ones that depend on the device parameters of the table.
- **Proportions of the metadata.** 32 KiB of data per sector of metadata. A larger unit means less overhead and
  fewer metadata requests, but more read amplification for small reads. See the open questions of
  [ARCHITECTURE.md](ARCHITECTURE.md#open-questions).

## Cache

- **A write to a chunk under write back waits.** By decision (D7), for simplicity: a hot chunk stalls its writers
  for the length of a lower write. Fix: a second copy of the chunk, as `dm-writecache` does. A cheaper partial
  fix: a mask of the sectors under write back, so that only writes to those sectors wait.
- **A FUA write writes back the whole cache.** By decision (D7), one path of code with the flush. Fix: write back
  only the chunks of the bio, with FUA.
- **One spinlock for the whole cache.** It is held only for a lookup and a copy of at most 4 KiB, but every
  request takes it, and a read from the lower device twice, to register in the tree of reads in flight and leave
  it. Not measured. Fix: locks per part of the tree, as `dm-bufio` hashes its buffers over several trees.
- **A write back waits for reads of its chunk one entry at a time.** By decision, for simplicity: the worker waits
  for the reads in flight on one entry before it sends the next, so a slow read of one chunk delays the write back
  of the others. Fix: mark all the picked entries first and send each once its reads are done.
- **Move `first_sector` and `nr_sectors` into `struct trn_p_rq`.**
- **Use preallocation where possible.**

## Write back and flushes

- **A write back is two requests in a row.** By decision (D10): the leading metadata sector is a FUA write, and the
  data waits for it, so every chunk costs the latency of two writes and a FUA. Fix: runs (D12), with one FUA write
  of a range of the metadata area before the data of the run; or the leading copies of a batch, then a flush, then
  its data.
- **Runs, once written, are to be tuned**: the longest run, whether neighbours not yet due by age join, and the
  scheme without the queue of runs sharing a metadata sector (D12).
- **Two flushes of the lower device per flush from above.** By decision, for simplicity: the second makes the
  trailing copies durable before a chunk can be written back again. The flush from above completes after the
  first. Fix: leave the trailing copies to the next flush, with a state for chunks whose trailing copy is written
  but not yet durable; and make the moment the trailing copy is written configurable.
- **A chunk written back again before a flush forces a flush (a barrier).** By decision (D10): after a write back
  the drive may hold the old or the new version of each sector until a flush, and a second write back would make
  a third with two slots of metadata. Counted as `barriers`. Options, asked about by the user on 2026-11-15:
  - **Keep such a chunk dirty until the next flush instead of forcing one**, the choice of the user: the newer
    data waits in the cache, so the drive never holds more than the old and the new version, and the flush that
    comes anyway (from above, or of the trailing copies) settles it. Under memory pressure the worker may still
    have to flush.
  - Take the barrier only where the sectors of the two write backs overlap; the code takes it for the whole
    chunk. Helps partial writes, not full rewrites of a chunk.
  - FUA data writes, after which the trailing copy can take the new CRC at once: cheap on SSDs with power loss
    protection, slow on HDDs.
- **The read before a write back is synchronous in the worker.** It happens only for chunks whose copies differ,
  after a crash or a failed write back. Fix, if it matters: settle them in the background after activation.
- **The trailing copies are written one range at a time, synchronously, in the worker.** Each range of an area is
  a request of its own. Fix: send them all, then wait, as runs will do for the data.

## Metadata in RAM

- **A read of a region whose metadata is not in RAM blocks `dm_map`.** By decision, for simplicity: the read of
  the metadata area is waited for in `dm_map`, so a submitter with many requests in flight stalls for one lower
  read each time a request comes to a new region. Fix: a list of the parts waiting for an area, started by the
  end of its read.
- **When half the metadata areas are busy, the worker flushes by itself.** A write back pins its area until the
  trailing copy is written, so random writes over many regions without flushes from above cost a flush of the
  lower device every 16 regions. Counted in `dmsetup status`. Fix, if it matters: more areas, or a pin that does
  not hold the whole area.
- **A metadata area with a sector failed in both copies is read again by every request that finds it unused.** By
  decision, so that a sector that reads again is seen. On a failing device such a request then costs two reads of
  64 KiB and one read per sector of the failed copy. Fix, if it matters: read again only the failed sectors.
- **The metadata area of a region with no bit set is read from the device.** Its entries are never used. Fix:
  fill such an area with zeros without a read.

## Bitmap and format

- **The first resume reads the header of every group, one after another.** By decision (D18), the simple way: a
  request per group, about 76 KiB for groups of 1 GiB, so a seek per group on an HDD. Measured in the VM, on a
  disk in RAM and a debug kernel: 128 groups in 24 ms, 32 in 6 ms, so about 0.2 ms a group without a seek, 0.2 s
  for a TiB in groups of 1 GiB; on an HDD the seeks add around 10 ms a group, so around 10 s for a TiB, not
  measured. Fix: several reads in flight, or the bitmap of a group read when it is first needed.
- **The whole bitmap of written chunks is in RAM.** By decision (D18): 32 MiB per TiB, allocated in the
  constructor.
- **A chunk whose bit is not on the device yet still takes a barrier.** By decision on 2026-11-15, for simplicity:
  written back twice before a flush, such a chunk reads as zeros after a crash whatever its slot holds, so no
  barrier is needed. Fix: a second bitmap, of the bits on the device.
- **One discard makes every first write back sync until the next flush.** By decision (D20): the generation of
  clears is one counter for the device, so a first write back of any chunk with its bit clear, not only of a
  discarded one, syncs while a clear is not durable. Fix: the second bitmap of the item above, which tells the
  chunks whose bit is set on the device.
- **A discard waits for every write back in flight, and clears its bits one at a time.** By decision (D20), for
  simplicity. Fix: wait only for the entries of its range; clear whole words of the bitmap.
- **The unused end of every group is lost.** By decision (D17): a group holds whole regions only, so 1 to 3.6 MiB
  of a group of a size other than 1 GiB is not used, and so is a tail of the device shorter than a header and two
  regions. Fix, if it matters: short regions.
- **The regions are aligned to 128 KiB only.** The header is 1 MiB and a region 4.125 MiB, so a filesystem block of
  4 KiB stays aligned but larger units of an SSD may not. Fix, if measured to matter: pad the regions.

## CRC

- **Use the Crypto API to speed up CRC64.**
- **The seed adds a CRC over 8 bytes per sector** (D19); to be measured in the baseline stage.

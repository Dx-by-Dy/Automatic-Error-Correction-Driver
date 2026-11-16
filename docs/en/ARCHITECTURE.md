# Architecture

Draft. This file holds the global decisions: what the driver protects against, what it promises to the layer
above, the on-disk format and the shape of the I/O path. How the driver works today is in [README.md](../../README.md),
what is not done yet is in [TODO.md](../../TODO.md), the reasons behind the decisions are in [RESEARCH.md](RESEARCH.md).

Each point is marked:

- **Decided**: agreed, change it only with a new entry in the [decision log](#decision-log);
- **Proposed**: suggested but not discussed yet, so not binding;
- **Current**: what the code does today, which may change;
- **Open**: not decided yet, with the options known so far.

## Purpose

**Decided.** The driver keeps the data of a degrading drive readable long enough to recover it and move it
elsewhere. At the first failures of the drive it must tell which data is damaged, and later repair it from
redundancy of its own. Today it only detects damage, with a CRC; correction with an error correcting code (ECC)
comes later.

**Decided.** Performance is a main criterion, on a par with integrity. A design that is correct but makes large
sequential I/O much slower than the lower device is not acceptable.

## Threat model

**Decided** on 2026-11-15, after the [reading on drive failures](RESEARCH.md#drive-failures), unless marked
otherwise. The frequencies are from the field studies quoted there; "Now" is what the code does, "Stage" is
where the rest is done.

| Threat | How common | Detected by | Handled by | Now | Stage |
| --- | --- | --- | --- | --- | --- |
| **A sector fails to read**: a latent sector error, an uncorrectable read | Common: 20 to 63% of SSDs within 4 years; about 19% of nearline HDDs within 2 | An error of the lower device | Only the bio over it fails; later rebuilt by ECC between chunks and written in place | Detected | Correction |
| **Data damaged silently**: decay, firmware, transfer, bits flipped by a power fault | 0.86% of nearline and 0.065% of enterprise HDDs in 41 months, often in consecutive blocks | CRC per 512-byte sector | As above | Detected | Correction |
| **A write cut short by a crash**, torn at 512 bytes on some SSDs | 3 of 15 SSDs under power faults | Two copies of the metadata, the leading one durable before the data | Each sector reads its old or its new data | Done, except a crash together with a lost sector of the other copy | |
| **A range reads back as zeros**: discarded by mistake, the mapping of an FTL lost, never written | No field data, only the mechanisms | A nonzero seed; the bitmap of written chunks says the chunk holds data | A read error for a chunk that was written; zeros, without a read, for one that was not | Done | |
| **A lost write**: acknowledged, even flushed, but not on the medium | 0.04% of nearline and 0.007% of enterprise HDDs in 17 months; 8 of 15 SSDs and 1 of 2 HDDs lost or reordered completed writes at a power fault | Data and metadata are separate writes: once the flush after a write back has passed, both copies hold the new CRC | A read error | Detected after that flush, at once for a first write. Not detected before it, nor when both copies of the metadata are lost with the data | Correction: a scrub against the parity may find the rest |
| **A misdirected write**: the data lands on another sector | Counted with lost writes; not seen under power faults | The CRC of the sector hit; its own place as a lost write; the logical sector and a salt per device in the seed | A read error | Detected unless the data equals that of the sector hit | |
| **A write fails** | Rare: the drive remaps a bad place first, so an error that reaches the host means its spare is gone or the region is in a bad way | An error of the lower device | The chunk stays in RAM and is retried, every flush fails meanwhile, new writes are refused when such chunks fill the cache, reads go on. No reserved area | Done | |
| **The drive is near its end** | After the first error 14 to 39 times more likely to fail within 60 days; but over half of failed HDDs gave no warning | Every error and mismatch | Counters in `dmsetup status` and a device mapper event, so that the user moves the data off; **Proposed** | Only a line in the kernel log | Device Mapper integration |

The "never written" state comes from a bitmap of written chunks, kept in the superblock and in RAM, apart from the
data it describes; a discard clears its bits. A chunk whose bit is clear reads as zeros without a read of the lower
device, as a discarded range of the lower device need not read back as zeros.

**A crash or a power loss** is not a threat to the data by itself, but a requirement, **Proposed**: which writes
survive is the business of the filesystem journal, which relies on flushes and FUA. The driver must not turn a
write cut short by the crash into a read error, see the contract.

Out of scope, **Proposed**:

- **Deliberate modification.** CRC64 is not a cryptographic hash. That is the task of `dm-verity` or of
  `dm-integrity` with an HMAC.
- **Loss of the whole device.** That takes redundancy across devices, as in RAID.
- **Memory errors** in the host.
- **A drive that ignores flushes.** No layer above it can make data durable. The driver detects what it can as
  lost writes.
- **A drive that hangs** on access to a range, as one SSD did after power faults. Timeouts are the business of the
  block layer.
- **A drive that deduplicates** could keep the two equal copies of the metadata once. Rare today; mixing the
  number of the copy into its contents would answer it.

## Contract with the layer above

**Decided** for 1 and 2, **Proposed** for the rest. The driver gives the guarantees of an ordinary block
device:

1. A write that completed before a `REQ_PREFLUSH` is durable once the flush completes.
2. A write with `REQ_FUA` is durable once it completes.
3. After a crash, each sector reads back either its old or its new contents, never an error made by the driver.
4. A failed read of the lower device or a CRC mismatch fails only the bio that covers the damaged data, with
   `BLK_STS_IOERR`. The device stays usable.
5. A failed write reaches the layer above. Without a cache it fails the bio itself. With a write-back cache
   the bio has already completed, so the error fails the next flush (and a later FUA write), as the page cache
   does for files.

The filesystem journal relies on 1 and 2 for the order of its writes, and on 3 when it replays: `jbd2` reads
past the last commit to find the end of the journal, and a read error there stops the mount.

**Current.** Points 1 and 2 hold: an empty flush and a FUA write wait until the cache has written back
everything dirty and the lower device has flushed. Point 3 holds through the two copies of the metadata, see
[On-disk format](#on-disk-format), except after a crash together with a lost sector of the other copy, or
when the lower device fails to flush. Point 5 holds as written: a failed write back fails every flush until
the chunk is written.

## On-disk format

**Current.** Version 1, not final: nothing has been released, so a change of format needs no migration yet.

- The lower device is a sequence of **groups** of one size, a power of two from 16 MiB to 4 GiB, 1 GiB by
  default (`dcorrsetup format --group-size`), as `src/dcorr-format.h` computes it for the driver and
  `dcorrsetup` both. A group is `[header of 1 MiB | as many whole regions as fit | unused]`: 248 regions at
  1 GiB and nothing unused, 1 to 3.6 MiB unused at the other sizes. The last group may be short, with the same
  header and at least 2 regions; a smaller tail of the device is not used. At least 2 groups.
- The header of group `g` holds a full copy of the superblock with the number of the group, the leading copy
  of the bitmap of written chunks of `g`, the trailing copy of the one of `g - 1` (of the last group for group
  0), and two blocks for the dirty stripes of the parity, zeroed until the correction stage defines them; the
  rest is reserved. The superblock is 4 KiB: magic, version, the number of the group, a generation, flags, a
  UUID, a salt, the size of the lower device, the capacity, all parameters of the layout and a CRC64 over it.
  A block of a bitmap is 4 KiB with a header of 32 bytes (CRC, generation, group, index, role) for 32512
  slots; its CRC starts from the salt, so a block of another device does not pass.
- **Parity columns.** The slots of a group, numbered across its regions, are cut into 32 columns of equal
  length, 32 slots per region of the group. The first 30 hold the data, in order; the last 2 are kept for P+Q
  parity, a stripe being the same offset in every column, and are not part of the capacity. A parity slot is an
  ordinary slot with its own metadata. The capacity is 7680 sectors per region; 930 MiB per group of 1 GiB.
- `dcorrsetup format` writes the header of every group, with empty bitmaps of generation 1, and wipes the
  starts of group 1 of the smaller sizes, where an old format would have left a copy; nothing else. The driver
  reads the superblocks of groups 0 and 1 in the constructor, never writes them, takes the valid one with the
  larger generation, warns about a copy that is not valid, and refuses the device when neither is, when its
  size is not the one formatted for, or when the length of the table is not the capacity. With group 0 not
  valid, the start of group 1 is probed for each size of a group. On the first resume the header of every group is read, one
  request each: the superblocks of groups 2 and on are checked against the one taken, and a copy that is not
  valid or differs is counted and named in the log, not refused; the bitmap is taken from them, see below.
- A chunk is 8 data sectors, 4 KiB. Its metadata is an entry of 64 bytes: 8 `__le64` values, one per data
  sector, in order, each `crc64_be` over the salt, the logical sector as `le64` and the 512 bytes of the sector.
  A metadata sector holds the entries of 8 neighbouring chunks. A parity slot has no logical sector; its CRC is
  for the correction stage.
- The slots of a group are a sequence of regions, as in `dm-integrity`. A region holds 1024 slots of a chunk,
  4 MiB, and is laid out as `[trailing copy of the metadata of the region before | leading copy of this region |
  slots]`: 128 sectors, 128 sectors, 8192 sectors, 8448 in all. The trailing copy of the last region of a group
  goes into the first region of the same group. The leading copy and the slots of a region are one contiguous
  range, and the data stays aligned to 128 KiB on the device; the header and the groups are aligned to 1 MiB.
- The leading copy is written with each write back of a chunk, with FUA, and the data only once it
  completes; the trailing one after the lower device has flushed that write back, and the device is flushed
  again. Once everything is flushed both copies are equal. A read accepts a sector that matches either, so
  after a crash at any point each sector reads its old or its new data.
- A chunk written back since the last flush is not written back again before another flush, counted as a
  barrier. A chunk whose copies differ in the sectors to be written, after a crash or a failed write back, is
  read first: a sector that matches the leading copy has that CRC written into the trailing one with FUA; one
  that matches neither is counted and left, so the damage stays visible.
- A metadata sector that failed to read in one copy is taken from the other; a rate-limited warning names
  every chunk read or written with one copy. A sector failed in both copies fails the reads of its 8 chunks,
  and the writes to them, as a write needs the other entries of the sector. A trailing sector that fails to
  write is counted in `dmsetup status`; it does not fail a flush, as the data and the leading copy are there.
- **The bitmap of written chunks** is in RAM whole, a page per block, 32 MiB per TiB. Each block is taken from
  its valid copy with the larger generation; a copy is valid with its CRC, its group, its index and its role.
  A block valid in one copy is written by the next flush, the invalid copy first, unless the table is read
  only; a block invalid in both makes its range read only: its chunks are read as written, so the CRC decides,
  and writes there fail in `dm_map`. A chunk whose bit is clear reads as zeros without a read of the lower
  device or its metadata, so a device is only formatted, never zeroed.
- The first write back of a chunk, with its bit clear, writes the whole chunk, the sectors not written from
  above as zeros, without reading it to settle its copies, which hold whatever was there; its bit is set in RAM
  once it succeeds. A flush of the cache then goes: flush the lower device, write the first copy of each block
  with new bits, with the next generation, flush, complete the flushes from above, write the trailing metadata
  and the other copies of the blocks, flush. A bit on the device thus means the data is durable, and a crash
  before it leaves the chunk zeros. A first copy that fails to write fails the flush from above and stays
  dirty; a second one is counted, and is written first with the next change of its block.
- A discard clears the bits of its whole chunks, dropping their data from the cache, and is never passed down;
  the partial chunks at its ends are left. The worker of the cache does it, after the write backs in flight,
  so that no bit changes while a sync writes a block. The bits reach the device with the next sync, so after a
  crash before it the chunks may hold their old data. A first write back of a chunk with its bit clear while
  a clear is not yet on the device syncs first, counted as a barrier: its bit is still set there, and the
  write back does not settle its metadata. If that sync fails, the chunk is settled as one written before. A
  discard touching a read only range fails. Write zeroes is not offered, see the decisions below.
- Only a lower device with 512-byte logical blocks works, as metadata is written as one 512-byte sector.
- The tests have their own copy of the layout in `tests/harness.py`.

**Decided** on 2026-11-11, replacing metadata next to each chunk. The driver is for SSDs and HDDs both, so the
metadata lives in areas of its own, one per region, as in `dm-integrity`:

- **Two CRCs** make the metadata durable before the data. With metadata after every chunk a run became a row of
  scattered metadata writes and then the data; with an area per region it is two sequential requests.
- **Alignment.** Chunks at `9k` were not aligned to 4 KiB, so a drive with 4 KiB physical sectors did a
  read-modify-write in firmware for every chunk, and a lower device with 4 KiB logical blocks could not work at all.
- **Density.** A metadata sector per chunk used 64 of its 512 bytes, 12.5% of the device. Packed, the metadata is
  1.6%, 3.1% with its copy, and small enough to keep its hot part in RAM.
- **Locality.** A region of 4 MiB keeps the metadata near its data on an HDD; one area for the whole device
  would put a seek between them.
- **The copy** in the next region guards against a failed metadata sector, which now covers 8 chunks. Writing it
  costs a second request for every change of metadata; settled on 2026-11-14, see below.

**Decided** on 2026-11-14, an idea of the user, replacing two CRCs in one entry: **the two copies are the two
slots.** The entry stays 64 bytes and the layout does not change. The leading copy gets the new CRC and the
trailing copy keeps the CRC of the data that is durable, until a flush makes the new data durable; then the
trailing copy is written too. So the copy guards against a lost metadata sector in the steady state, and the
two slots cover a write cut short by a crash in between. What is lost is the case of a crash in that window
together with a lost sector of the other copy, two faults at once. A completed write is not durable, so a
chunk written back again before a flush needs a flush first: its data may be any of three versions, and there
are two slots. A chunk whose copies differ after a crash is read before it is written back again, as
writing its leading copy over a trailing one that does not match the data would leave neither matching.
- **The cost:** a write of the metadata of one chunk needs the other entries of its sector. They come from the
  metadata area of the region in RAM, read whole the first time the region is used, see [Cache](#cache); the
  writes of the chunks of one sector go one at a time.

**Open:**

- **Proportions.** How much data one metadata block covers: 32 KiB per sector of metadata today. A larger unit
  means less overhead and fewer metadata requests, but more read amplification for small reads, and it sets
  the unit of the cache and of ECC. To be measured after the cache, against the baseline. It also has to fit a
  lower device with 4 KiB logical blocks: then the metadata is written in blocks of 4 KiB, 64 chunks to a
  block.
- **ECC.** The code, how much space it takes, where the redundancy lives, and how it combines with the CRC. What
  the reading on drive failures settled: it corrects erasures between chunks, as a drive returns an error and not
  damaged bits; a stripe is not made of neighbours, as damage comes in consecutive blocks; on an HDD its
  redundancy lies far from the data; parity is updated only from data that passed its CRC, or one error spreads
  over the stripe.
- **Superblock and version**: laid out and checked, see Current above. Still open: when the driver writes the
  header and raises its generation, putting a damaged copy right, and growing a device, which is a feature of
  its own, decided on 2026-11-15.

**Decided** on 2026-11-15, after the [reading on drive failures](RESEARCH.md#drive-failures):

- **The CRC stays per 512-byte sector.** SSDs were seen to tear a 4 KiB write at a power fault in units of 512
  bytes, so a CRC over 4 KiB would turn a crash into a read error. Per 4 KiB only for a drive known to write it
  atomically.
- **The seed is nonzero and holds the logical sector of the data sector and a random salt per device**, kept in
  the superblock, as `dm-integrity` does. A zero chunk with zero metadata no longer passes, nor a chunk in the
  wrong place, nor data from another device. Settled on 2026-11-16: as in `dm-integrity`, the CRC runs over
  the salt, the logical sector as `le64`, then the data; the CRC of the salt is computed once per table. The
  logical sector of each sector, not of its chunk, so that sectors swapped inside a chunk with their CRCs fail
  too: a sector has no header for its place, as a block of the bitmap has. As a CRC is linear, equal data in two
  places of one device gives different CRCs for certain, not by chance. The version of the format stays 1, as
  no device is in use; the cost, a CRC over 8 bytes more per sector, is measured in the baseline stage.
- **A bitmap of written chunks, one bit per chunk, in the superblock and in RAM**, decided by the user: apart from
  the data it describes, so that a range lost together with its metadata is still known to have held data. It
  gives the "never written" state and discard. It takes 32 MiB per TiB of data, on the device and in RAM. It is
  part of the area of the superblock and is kept in both its copies; when a bit reaches the device against the
  flushes is settled in the plan of the stage.
- **The superblock in two copies**, an idea of the user: at the start of the lower device and at a region
  boundary in its middle, so that a lost range rarely takes both. Each copy names itself: magic, version, number
  of the copy, generation, CRC. Replaced later on 2026-11-15 by a copy in every group, see below.
- **All layout parameters live in the superblock**: the chunk, the region, the places of the copies, the size of
  the bitmap. Version 1 accepts only the current values, so the I/O path keeps its constants for now.
- **A device is formatted by a utility in userspace, in C**, which writes the superblock to the lower device, as
  `integritysetup format` does; the constructor refuses a device without a valid one. At run time the utility
  talks to the driver through the channels of device mapper (`dmsetup message`, `status`, events): targets have
  no sysfs of their own.
- **No reserved area** for failed write backs: by the time a write error reaches the host the spare of the drive
  is gone, and on an SSD an LBA says nothing about the place on flash. Data rebuilt by ECC is written in place.

## I/O path

**Decided**, the rules from stage 2 that any new design keeps:

- Nothing on the I/O path allocates in a way that can fail: per-bio data, embedded structures, mempools.
- All waiting happens in `dm_map`, which slows down the submitter as a full disk queue would, or in the worker
  of the cache, which runs on a workqueue of its own. The workers of `transform_wq` never wait for memory, a
  limit or a lock, as they run the completions that give those back.
- `dm_map` never waits for a lower bio of its own: it stays on `current->bio_list` until `map` returns.
- A part never holds one element of a pool while waiting for another from the same pool.
- The number of requests in flight is bounded.

**Current.** Device mapper splits each bio at chunk boundaries (`max_io_len` of 8 sectors). A write is copied
into the cache and completes. The worker writes an entry back as one part per run of its dirty sectors, once no read
of the chunk is in flight and the metadata of the chunk is ready (a barrier or a settling read, see
[On-disk format](#on-disk-format)): the part writes the leading metadata sector from the area in RAM with the
new CRCs merged in, with FUA, and the data bio once it completes. The parts of the chunks of one metadata
sector go one at a time. A read takes the sectors the cache holds from it; the
rest is a part in the per-bio data of its bio, registered in the tree of reads of the cache while in flight,
which reads from the lower device and checks the CRC in a worker. Details are in
[README.md](../../README.md).

**Decided**, why this has to change: upper bios are tied to lower bios one chunk at a time. A large request
becomes many 4 KiB pieces, each with its own metadata request, and a read takes two lower requests per chunk.
This is expected to cost much of the throughput at large volumes. Splitting at chunk boundaries is an interim
step, taken because synchronizing overlapping upper bios with lower bios in flight was the main source of
complexity and bugs.

## Cache

Written in the cache stage, closed on 2026-11-14; runs have a stage of their own after the format. How other targets do this, and what it costs, is in
[RESEARCH.md](RESEARCH.md#caches-and-integrity-in-device-mapper).

**Decided:**

- **Purpose: aggregation.** The cache separates the work with bios from above from the work with bios below.
  The data of an upper bio is copied into pages of the driver in RAM. The driver builds its own lower bios over
  runs of chunks, computes the CRC (and later ECC) only when it writes to the lower device, and checks it only
  when it reads from it.
- **Pages are copied**, so a page changed by the layer above after it was submitted no longer matters. This
  closes "Pages can change after their CRC is computed" in `TODO.md`.

**Decided** for now, on 2026-11-11, and may be revised once it is built:

- **A structure of our own**, in the shape of the pmem mode of `dm-writecache`: a pool allocated up front, a tree
  by position, an LRU, two watermarks and an age for write back, neighbours written as one bio.
- **No `dm-bufio` for data**, so that write back stays under the control of the driver.
- **The unit is a chunk.**
- **Reads:** only dirty data is served from the cache, clean data is not kept.
- **A write cut short by a crash: two CRCs are tried first**, so the cache has no journal of its own. The
  filesystem journal decides which writes survive; point 3 of the contract stays with the driver. What this
  requires is in [RESEARCH.md](RESEARCH.md#a-write-cut-short-by-a-crash-two-crcs). Since 2026-11-14 the two
  CRCs are the two copies of the metadata, see [On-disk format](#on-disk-format).
- **The layout:** metadata in an area per region, see [On-disk format](#on-disk-format), decided on 2026-11-11.
  Its proportions are revisited only after measuring the cache and two CRCs on it.
- **A failed write back:** the error is per chunk, not for the device. The data stays in RAM; there is no reserved area,
  rejected on 2026-11-15. When such chunks fill the cache, new writes are refused.
  Every flush fails while such chunks remain, as a flush that succeeds promises the data is on the device.
- **A partial chunk** keeps a mask of its dirty sectors. Write back writes only those and reads the old metadata;
  the rest of the chunk is not read.
- **A write to a chunk under write back waits in `dm_map`** for now, and the waits are counted. A second copy of
  the chunk, as in `dm-writecache`, is the likely final answer and is left for the optimization stage.
- **FUA goes the way of a flush** for now: the data is copied into the cache, then everything dirty is written
  back and the lower device flushed before the bio completes. A write back of that chunk alone with FUA is left
  for the optimization stage.
- **A failed chunk is retried** only on a flush, on a suspend, or when it is written again; there is no timer of
  its own.
- **A suspend cannot fail**, so a chunk that still fails to write when the device is suspended for a removal or
  a reload is lost, with its number in the kernel log.
- **Runs**, decided on 2026-11-14 and left until after the format: a run is a contiguous range of dirty
  sectors inside one region, written as one FUA write of its range of leading metadata sectors, then one data
  bio. A clean hole in a chunk breaks the run, with no read to fill it; dirty neighbours join it before they
  are due by age; the longest run comes from `max_sectors` of the lower device; runs that share a metadata sector
  at their ends go one after another. A failed run fails all its chunks. The limits, the age of neighbours and a
  scheme without the queue (the leading copies of a batch, then all its data) are tuned in the optimization
  stage.
- **The lock of a chunk moved into the cache**, after the first version of the cache and before runs: a read of
  the lower device registers its range in the tree of the cache while in flight, and a write back waits for the
  reads in flight on its chunks, while new reads of their clean sectors wait for it. A run spans many chunks, and
  a part may not hold many chunk locks. The lower writes of the chunks of one metadata sector go one at a time,
  as each merges its CRCs into that sector.
- **Metadata in RAM**, decided on 2026-11-14: the metadata area of a region, 64 KiB, is the unit, read whole
  the first time a chunk of the region needs it, as the next request is likely near. A structure of our own, in a
  pool of its own apart from the data, so that a write back never waits for its own metadata to find room among
  dirty data. Clean areas are dropped by LRU and on a suspend; a write back holds its area and changes the entry
  in place just before it writes the sector, so an area never holds what the lower device does not. Dropping
  dirty metadata comes with metadata writes deferred and batched, at or after runs, as it has to keep in step
  with the data cache. What to do when a metadata write fails is left to the copy of the metadata and two CRCs.
- **Both copies in RAM**, decided on 2026-11-14: an area holds the leading and the trailing copy, 4 MiB still,
  so 32 areas. An area with chunks written back since the last flush is pinned until their trailing copy is
  written. A flush from above completes after the first flush of the lower device, as its data is durable then;
  the trailing copies and the second flush follow. When half the areas are held or pinned, the worker flushes
  and writes the trailing copies by itself, or it could wait for an area for ever. A deferred second flush and
  when to write the trailing copy are left for the optimization stage, configurable.
- **Defaults are constants for now:** 64 MiB of cache per device, write back from 50% used down to 45%, an age of
  1 s, 4 MiB of metadata in RAM. They are to be tuned later.


**Proposed**, requirements:

1. The device always reports a volatile write cache, even over a write-through lower device, as RAM is
   volatile.
2. `REQ_PREFLUSH`: write back every dirty page whose upper write completed before the flush, flush the lower
   device, then complete the flush.
3. `REQ_FUA`: the data of the bio and its metadata are durable before the bio completes, through FUA writes or
   a write back followed by a flush.
4. A failed write back is remembered and fails the next flush.
5. Suspending the device writes back all dirty data, so a table reload or a removal loses nothing.
6. The cache has a bounded size, and the rules of the [I/O path](#io-path) hold for it.

**Open:**

- **A write cut short by a crash** (point 3 of the contract). The cache does not remove the problem: data and
  metadata are still separate writes, and a drive is atomic only per sector. Two CRCs go first; the other
  options stay in case they do not work out:

  | Option | How | Cost |
  | --- | --- | --- |
  | Bitmap, as in `dm-integrity` | Mark the regions of a write back dirty, flush, write data and metadata. After a crash, recompute the CRC of the dirty regions | No detection in the regions dirty at the crash |
  | Two CRCs | Write metadata with both the old and the new CRC, flush, write the data. A read takes either | Keeps detection; ECC would need both the old and the new redundancy |
  | Journal | Every write goes to a journal first, then to its place | Every write twice |

  ECC may still change the choice. The write back of the cache has to leave room for a step before and after
  writing a batch.
- **A reserved area for failed write backs** was rejected on 2026-11-15, see [On-disk format](#on-disk-format);
  the reasoning is kept in [RESEARCH.md](RESEARCH.md#a-failed-write-back-a-reserved-area).

## Errors

**Current.** A failed lower bio or a CRC mismatch fails the part with `BLK_STS_IOERR`, and a mismatch prints a
line with `pr_err`, with no rate limit and without the name of the device.

**Proposed**, as the goal is to move data off a failing drive: an error must not make healthy data unreadable,
and errors must be visible to the user as counters in `dmsetup status`, with a device mapper event at the first
one: it is a strong sign that the drive is failing, see the [threat model](#threat-model).

**Open.** What correction does once ECC exists: rebuild the data, write it back in place or elsewhere, and what
it counts.

## Testing

**Decided:**

- Everything runs in the development VM with a debug kernel, never on the host: [deploy/README.md](../../deploy/README.md).
- Crash consistency is tested with `dm-log-writes` below the driver, and a replay of its log in the tests
  (the format of `replay-log` from xfstests): the log holds every lower request with its flushes and FUA, and
  replaying a prefix of it to a clean device gives the state after a crash at that point. A crash right after
  an `fsync` must keep everything the filesystem made durable, and so must a crash at any flush or FUA write
  while other writes of the filesystem are in flight, and a crash at any entry between two flushes. As
  `dm-log-writes` logs in the order of completion, it cannot show a disk that persists the data before the
  leading copy; that order is checked in the log itself: the leading write is FUA and comes first. A second
  crash is replayed on top of the state of the first, with a log started from it.
- Failures of the lower device are tested with `dm-dust` (reads of chosen sectors fail, and writes to them a
  chosen number of times) and `dm-flakey` (every write fails, reads go through). Writes dropped silently are
  tested with `dm-flakey` and `drop_writes` over chosen sectors, `linear` elsewhere: a lost write is detected
  once the flush after its write back has passed, and passes as the old contents before it; a lost copy of the
  metadata or of a block of the bitmap is covered by the other.

**Decided** on 2026-11-15, an idea of the user, replacing the copy of the superblock in the middle: **groups.**

- **The device is a sequence of groups of one size**, each with a header and whole regions, the trailing copies
  of the metadata cycling inside the group. Growing adds groups of the same size, so recovery of the
  superblock probes the start of group 1 for each size of the list. A header of a fixed 1 MiB, chosen by the
  user: the groups stay aligned to 1 MiB, and the header keeps room for later versions. Whole regions only, the
  rest of a group unused, also the choice of the user, to be looked at in the optimization stage.
- **A full copy of the superblock in every group**, with the number of the group, so that a header in the wrong
  place is seen. The constructor takes the superblock from groups 0 and 1, and checks the others when the
  bitmap reads every header.
- **The bitmap of written chunks of a group** leads in its header and trails in the header of the next group,
  as the metadata of the regions does.
- **Parity in fixed columns at the end of each group, P+Q over 30 + 2**, RAID 4 inside a group without
  rotation, chosen by both: a damaged range shorter than a column takes at most one member of a stripe, two
  across a column boundary, which two parity members cover. Data stays contiguous in the first 30/32 of a
  group, so runs and the mapping stay simple. How and when parity is updated is for the correction stage; the
  space is reserved now, so that the layout does not change when ECC comes.

**Decided** on 2026-11-15 with the user, **the bitmap of written chunks**, step 2 of the format stage:

- The header of every group is read on the first resume of the table, the simple way; lazy loading or reads in
  flight are for the optimization stage. Not in the constructor: on `dmsetup reload` the constructor of the new
  table runs while the old one still writes, so the bits it sets after that would be missed; by the first
  resume the old table is suspended and has written its bitmap. Found by `test_table_reload_under_load`. A
  superblock of group 2 and on that is wrong is counted and named, not refused.
- The CRC of a block does not take its place: the group, the index and the role in the block, under a CRC that
  starts from the salt, are enough.
- The first copies of the changed blocks are written without FUA and then flushed once: libata turns FUA off by
  default, and an emulated FUA costs a flush per block.
- A block found with one valid copy is repaired by the next flush.
- A chunk whose bit is not on the device yet keeps its barrier, and the metadata of a region with no bit set is
  read: both for the optimization stage.

**Decided** on 2026-11-16, discard, step 4 of the format stage:

- **Discard in whole chunks through the bitmap**, not passed down, with no limit of our own on its length.
  Checked in the source of 7.2.15: device mapper does not split a discard at `max_io_len`, only
  `bio_split_to_limits` and `__blkdev_issue_discard` split it, by the limits of the queue; the head of a range
  not aligned to a chunk comes as a bio of its own.
- **A generation of clears**, chosen by the user over a sync per discard and over a second bitmap of the bits on
  the device: the first write back of a chunk skips the settle only while its bit is clear on the device too;
  after a discard that holds only after the next sync, so such a write back syncs first. No memory; the cost
  only on first writes between a discard and the next flush.
- **The worker clears the bits**, not `dm_map`: a sync writes a block of the bitmap from its page in RAM after
  computing its CRC, and a bit changed meanwhile would leave a copy whose CRC does not match on the device.
- **No write zeroes for now**: device mapper offers it only with `iterate_devices` and every device below
  capable; there is no flag for a target that emulates it. It comes with `iterate_devices` in the stage of
  device mapper integration. Until then `blkdev_issue_zeroout` writes zero pages, which is correct, only slower.
- A discard and a write racing on one chunk may land in either order: concurrent I/O, the business of the layer
  above.

## Decision log

| Date | Decision | Why |
| --- | --- | --- |
| 2026-11-09 | Device mapper splits requests at chunk boundaries, the part lives in per-bio data | Removes the bugs of pairing upper and lower bios by hand; an interim step, the cache replaces it |
| 2026-11-09 | Nothing on the I/O path can fail to allocate; waits only in `dm_map`; at most 4096 parts in flight | Workers that wait hang the device; a bio-based device has no queue to bound the load |
| 2026-11-10 | The cache comes right after the test base, before the format and the rest of integrity | It changes the I/O path, the unit of the format and how flushes work, so later work would be redone |
| 2026-11-10 | The cache copies data and aggregates writes; CRC and ECC are computed only towards the lower device | Performance at large volumes, and the stable page problem goes away |
| 2026-11-10 | Metadata stays next to the data; the proportions are measured later | One request for data and metadata; the right proportion needs the cache and the baseline |
| 2026-11-10 | Seed, position in the CRC and the "never written" state wait for research on drive failures | Not clear how real the threat of zeroed regions is for a degrading drive |
| 2026-11-11 | The cache is a structure of our own in the shape of `dm-writecache` pmem, without `dm-bufio`, a chunk as its unit, keeping only dirty data for now | Write back stays under our control; [comparison](RESEARCH.md#caches-and-integrity-in-device-mapper) |
| 2026-11-11 | Two CRCs are tried first for a write cut short by a crash, no journal | No blind spot, no double write, fits the format; [what it requires](RESEARCH.md#a-write-cut-short-by-a-crash-two-crcs) |
| 2026-11-11 | The layout stays 8+1 until measured; a failed write back stays in RAM, with a place to plug in a reserved area later | Numbers first; the area needs a superblock, so it waits for the format |
| 2026-11-11 | FUA goes the way of a flush; a failed chunk is retried on a flush, a suspend or a new write; a chunk that fails on a suspend is lost with a log line | One path of code first; a suspend cannot fail, and the reserved area is not there yet |
| 2026-11-11 | The lock of a chunk is replaced by ranges in flight in the tree of the cache, before runs | A run spans many chunks; one state machine in the driver instead of two |
| 2026-11-11 | Metadata moves into an area per region of 4 MiB, packed 8 chunks to a sector, with room for a copy in the next region; it replaces metadata next to each chunk | SSDs and HDDs both; two CRCs keep a run two sequential requests; data aligned to 4 KiB; 1.6% instead of 12.5% |
| 2026-11-14 | Metadata in RAM: the area of a region as the unit, a pool of its own, clean areas dropped by LRU and on a suspend, entries changed in place by the write back | No read before a metadata write, one lower read per chunk read; two pools, as one shared with data brings deadlocks and policies whose gain is not measured |
| 2026-11-14 | The two copies of the metadata are the two CRC slots: the leading copy is written with the write back, the trailing one after the flush that makes the data durable; both in RAM; a failed trailing write is counted and warned about, not failed | No change of format, the copy guards a lost sector in the steady state; only a crash together with a lost sector of the other copy is not covered |
| 2026-11-14 | The leading copy is a FUA write before the data; a chunk written back since the last flush waits for a flush (a barrier); a chunk whose copies differ is read before its write back, and the matching CRC goes into the trailing copy with FUA | A completed write is not durable, so two write backs between flushes leave three versions for two slots; the read settles a crash left over without a superblock or an epoch |
| 2026-11-14 | Runs move after the format stage, before the baseline; their shape is decided now. The place to plug in the reserved area moves into the format stage | Runs change no logic or guarantee, and the format may change what a write back writes; the baseline should measure the cache with them. The reserved area needs a superblock, and whether to have it is decided there |
| 2026-11-11 | Every flush fails while unwritten chunks remain; partial chunks keep a dirty mask; a write to a chunk under write back waits, a second copy is left for optimization | A flush must not promise what is not on the device; a bad neighbouring sector must not stop a write; simplest first |
| 2026-11-15 | The threat model is settled: zeroed ranges and misdirected writes in scope, lost writes in scope where the layout detects them; the CRC stays per 512-byte sector; the seed is nonzero, with the logical sector and a salt per device; a bitmap of written chunks in the superblock and in RAM; no reserved area | [Drive failures](RESEARCH.md#drive-failures): a write error reaching the host means the spare of the drive is gone; shorn writes come in units of 512 bytes; the seed costs nothing; the bitmap lies apart from the data it describes, an idea of the user |
| 2026-11-15 | The superblock in two copies, at the start and in the middle; all layout parameters in it, version 1 accepting only the current values; the bitmap part of it; formatting by a utility in C, control through `dmsetup message` | Two places far apart on an HDD; a format open to change without variables on the I/O path; formatting in userspace, as in `dm-integrity`, keeps the constructor simple |
| 2026-11-15 | Groups of 16 MiB to 4 GiB, 1 GiB by default, each a header of 1 MiB with a full superblock and the bitmaps, and whole regions; parity reserved in 2 of 32 columns at the end of each group; the constructor reads groups 0 and 1 and probes group 1 for every size | A superblock in every group survives a lost range and allows growing; parity far from its data within a group, room for ECC now so the layout does not change; the user chose the fixed header and whole regions |
| 2026-11-15 | The bitmap of written chunks read from every header on the first resume of the table, written by the flush sequence: the first copy of the changed blocks after the flush that made their data durable, then a flush, the other copy with the trailing metadata; a first write back of a chunk writes it whole with zeros; a block invalid in both copies makes its range read only | A bit on the device means durable data, so a fresh device needs no zeroing and a crash leaves a first write zeros or new; a range whose bits are lost is still checked by its CRC, never read as zeros |
| 2026-11-16 | The CRC of a data sector runs over the salt, its logical sector as `le64` and its data; the format stays version 1 | The place of each sector and the device in the CRC, as in `dm-integrity`; no device is in use yet |
| 2026-11-16 | Discard in whole chunks through the bitmap, by the worker of the cache, not passed down; a first write back after a discard not yet synced syncs first; no write zeroes until `iterate_devices` | A cleared bit is not on the device until a sync, and a sync writes the bitmap from RAM; device mapper offers write zeroes only through the devices below |
| 2026-11-16 | Device mapper integration and the documentation come before runs, which stay before the baseline | The choice of the user: the interface and the docs of the driver as it is now, after the format stage closed |

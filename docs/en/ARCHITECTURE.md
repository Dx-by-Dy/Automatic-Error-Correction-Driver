# Architecture

How dm-dcorr works today: what it protects against, what it promises to the layer above, the on-disk format and
the I/O path; [DIAGRAMS.md](DIAGRAMS.md) shows its situations as pictures, with the tests that cover them. Why it
is built this way is in [DECISIONS.md](DECISIONS.md), with the reading behind it in
[RESEARCH.md](RESEARCH.md). What is not done yet is in [TODO.md](TODO.md), what was left for the optimization
stage in [TODO_OPTIMIZATION.md](TODO_OPTIMIZATION.md), how it is tested in [TESTS.md](TESTS.md), and how to
build and run it in [DEPLOY.md](DEPLOY.md).

## Purpose

The driver keeps the data of a degrading drive readable long enough to recover it and move it elsewhere. At the
first failures of the drive it must tell which data is damaged, and later repair it from redundancy of its own.
Today it detects damage, with a CRC per sector; correction with an error correcting code (ECC) comes later, and
the room for its parity is already in the format.

Performance is a main criterion, on a par with integrity: a design that is correct but makes large sequential
I/O much slower than the lower device is not acceptable.

## Glossary

The terms of the project, in the order they build on each other. The source files are in `src/`.

**Layout**

| Term | What it is | What it is for |
| --- | --- | --- |
| Lower device | The block device under the driver, formatted by `dcorrsetup` | Holds the data, its metadata and the headers |
| Logical sector | A sector of 512 bytes of the device on top, as the layer above sees it | Addresses the data; part of the seed of its CRC |
| Chunk | 8 logical sectors, 4 KiB | The unit of the cache, of the metadata and of the bitmap |
| Slot | The place of one chunk on the lower device | A chunk of data or of parity lives in a slot |
| Region | 1024 slots with two copies of metadata in front of them, 4.125 MiB on the lower device | Keeps the metadata near its data; the unit of the metadata in RAM |
| Group | A header of 1 MiB and as many whole regions as fit, 1 GiB by default | A superblock in every group survives a lost range; the unit of the bitmap and of parity |
| Header | The first 1 MiB of a group | Holds the superblock, the bitmaps and the blocks of dirty stripes |
| Superblock | 4 KiB at the start of every header: the version, the layout, a UUID, the salt, a generation, a CRC | Lets the driver find and check the format |
| Column, parity column, stripe | The slots of a group cut into 32 columns; the last 2 are kept for parity; a stripe is the same offset in every column | Room for P+Q parity, far from its data, so that a damaged range takes at most one or two members of a stripe |

**Metadata**

| Term | What it is | What it is for |
| --- | --- | --- |
| CRC | `crc64_be` of a data sector, 8 bytes | Detects damage of the sector |
| Salt | 16 random bytes in the superblock | Makes the CRCs of one device differ from those of another |
| Seed | Where the CRC of a sector starts: the CRC of the salt and of the logical sector | Data in the wrong place, from another device, or zeros with zeroed metadata fail their CRC |
| Entry | The 8 CRCs of a chunk, 64 bytes | The metadata of one chunk |
| Metadata sector | 512 bytes holding the entries of 8 neighbouring chunks | The unit in which metadata is written |
| Metadata area | The 128 metadata sectors of one region, in one copy | Read whole into RAM the first time the region is used |
| Leading copy | The copy of the metadata of a region right before its slots | Gets the CRC of new data before the data is written |
| Trailing copy | The copy of the metadata of a region in the next region of the group | Keeps the CRC of the durable data until a flush makes the new data durable |
| Bitmap of written chunks | One bit per slot, set once the chunk is written back and durable | Tells a chunk never written, read as zeros, from one that holds data |
| Block of the bitmap | 4 KiB: a header of 32 bytes (CRC, generation, group, index, role) and 32512 bits | The unit in which the bitmap is written, in a leading and a trailing copy |
| Generation | A counter in a superblock and in a block of the bitmap | Of two valid copies, the newer is taken |
| Read only range | The chunks of a block of the bitmap invalid in both copies | Never read as zeros: their CRC decides, and writes there fail |

**Mechanisms**

| Term | What it is | What it is for |
| --- | --- | --- |
| Cache | 64 MiB of RAM per device, an entry per chunk, a tree by chunk and a list by age | Every write is copied there and completes at once; aggregation, and pages that cannot change under their CRC |
| Entry of the cache | A chunk in the cache: a page, a mask of the sectors written, a state (dirty, writing, failed) | Holds the data until it is written back |
| Worker | The work item of the cache, on an ordered workqueue of its own | Writes back, carries out flushes and discards; the only place besides `dcorr_map` that waits |
| Write back | Writing an entry to the lower device: the leading metadata sector with FUA, then the data | Moves data from RAM to the device so that a crash leaves each sector old or new |
| Job | One lower write of a write back, a run of dirty sectors of one entry | The unit the worker sends; the jobs of one metadata sector go one at a time |
| Part | `struct trn_p_rq`: a read of the lower device, or the lower write of a job, with its CRC work | Lives in per-bio data or in a job, so nothing on the I/O path allocates |
| Parts in flight | At most 4096 parts per device | Bounds the load, as a bio-based device has no request queue |
| First write back | The write back of a chunk whose bit is clear | Writes the whole chunk, zeros around what was written, and does not settle |
| Settle | A read of a chunk before its write back when its two copies differ in the sectors to be written | Puts the CRC that matches the data into the trailing copy, so that a second crash leaves a readable chunk |
| Barrier | A sync before the write back of a chunk written back since the last flush, or of a chunk whose bit is clear while a clear of a discard is not yet synced | A completed write is not durable: two write backs between flushes would leave three versions for two copies |
| Sync | `cache_sync`: flush, the first copy of the changed blocks of the bitmap, flush, the flushes from above completed, the trailing metadata and the other copy of the blocks, flush | Makes data durable, then its bits, then its trailing copy |
| Generation of clears | A counter of the discards that cleared a bit, and the value the last sync made durable | A first write back after a discard not yet synced syncs first |
| Metadata cache | 32 metadata areas in RAM, both copies each, kept by LRU | One lower read per region instead of one per chunk; no read before a metadata write |
| Pin | An area with chunks written back since the last flush stays in RAM | Its trailing copy is written after the flush |
| Crowded flush | A sync the worker makes by itself when half the areas are held or pinned | Lets pinned areas go, so that a write back never waits for ever |
| Tree of reads | The reads of the lower device in flight, by chunk | A write back waits for the reads of its chunk, so a read never sees data and CRC of two versions |
| Unwritten read | A read of a chunk whose bit is clear | Zeros without a read of the lower device |
| Event of the first error | A device mapper event raised once per table, at the first error counted | Wakes `dmsetup wait` or `dmeventd`, so that the user moves the data off a failing drive |

## Threat model

The frequencies are from the field studies quoted in [RESEARCH.md](RESEARCH.md#drive-failures); "Now" is what the
code does, "Stage" is where the rest is done.

| Threat | How common | Detected by | Handled by | Now | Stage |
| --- | --- | --- | --- | --- | --- |
| **A sector fails to read**: a latent sector error, an uncorrectable read | Common: 20 to 63% of SSDs within 4 years; about 19% of nearline HDDs within 2 | An error of the lower device | Only the bio over it fails; later rebuilt by ECC between chunks and written in place | Detected | Correction |
| **Data damaged silently**: decay, firmware, transfer, bits flipped by a power fault | 0.86% of nearline and 0.065% of enterprise HDDs in 41 months, often in consecutive blocks | CRC per 512-byte sector | As above | Detected | Correction |
| **A write cut short by a crash**, torn at 512 bytes on some SSDs | 3 of 15 SSDs under power faults | Two copies of the metadata, the leading one durable before the data | Each sector reads its old or its new data | Done, except a crash together with a lost sector of the other copy | |
| **A range reads back as zeros**: discarded by mistake, the mapping of an FTL lost, never written | No field data, only the mechanisms | A nonzero seed; the bitmap of written chunks says the chunk holds data | A read error for a chunk that was written; zeros, without a read, for one that was not | Done | |
| **A lost write**: acknowledged, even flushed, but not on the medium | 0.04% of nearline and 0.007% of enterprise HDDs in 17 months; 8 of 15 SSDs and 1 of 2 HDDs lost or reordered completed writes at a power fault | Data and metadata are separate writes: once the flush after a write back has passed, both copies hold the new CRC | A read error | Detected after that flush, at once for a first write. Not detected before it, nor when both copies of the metadata are lost with the data | Correction: a scrub against the parity may find the rest |
| **A misdirected write**: the data lands on another sector | Counted with lost writes; not seen under power faults | The CRC of the sector hit; its own place as a lost write; the logical sector and a salt per device in the seed | A read error | Detected unless the data equals that of the sector hit | |
| **A write fails** | Rare: the drive remaps a bad place first, so an error that reaches the host means its spare is gone or the region is in a bad way | An error of the lower device | The chunk stays in RAM and is retried, every flush fails meanwhile, new writes are refused when such chunks fill the cache, reads go on. No reserved area | Done | |
| **The drive is near its end** | After the first error 14 to 39 times more likely to fail within 60 days; but over half of failed HDDs gave no warning | Every error and mismatch | Counters in `dmsetup status` and a device mapper event, so that the user moves the data off | Done | |

The "never written" state comes from the bitmap of written chunks, apart from the data it describes; a discard
clears its bits. A chunk whose bit is clear reads as zeros without a read of the lower device, as a discarded
range of the lower device need not read back as zeros.

A crash or a power loss is not a threat to the data by itself, but a requirement: which writes survive is the
business of the filesystem journal, which relies on flushes and FUA. The driver must not turn a write cut short
by the crash into a read error, see the contract.

Out of scope:

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

The driver gives the guarantees of an ordinary block device:

1. A write that completed before a `REQ_PREFLUSH` is durable once the flush completes.
2. A write with `REQ_FUA` is durable once it completes.
3. After a crash, each sector reads back either its old or its new contents, never an error made by the driver.
4. A failed read of the lower device or a CRC mismatch fails only the bio that covers the damaged data, with
   `BLK_STS_IOERR`. The device stays usable.
5. A failed write reaches the layer above. The bio has already completed in the cache, so the error fails the
   next flush (and a later FUA write), as the page cache does for files.

The filesystem journal relies on 1 and 2 for the order of its writes, and on 3 when it replays: `jbd2` reads past
the last commit to find the end of the journal, and a read error there stops the mount.

All five hold today. Point 3 holds through the two copies of the metadata, except after a crash together with a
lost sector of the other copy, or when the lower device fails to flush. A discard, like a write, is durable once
a flush after it completes.

## On-disk format

Version 1, not final: nothing has been released, so a change of format needs no migration yet. The layout is
computed by `src/dcorr-format.h`, which the driver and `dcorrsetup` share; the tests keep a copy of their own in
`tests/harness.py`.

```text
lower device
+---------+---------+-----+-------------+
| group 0 | group 1 | ... | group G - 1 |    the last group may be short
+---------+---------+-----+-------------+

group of 1 GiB
+--------+-----------+-----------+-----+-------------+
| header | region 0  | region 1  | ... | region 247  |    other sizes leave the end of the group unused
| 1 MiB  | 4.125 MiB | 4.125 MiB |     | 4.125 MiB   |
+--------+-----------+-----------+-----+-------------+
 slots of the group in 32 columns: 30 of data, in order, then 2 kept for parity

region i of a group
+------------+------------+-------------+
| trailing   | leading    | slots       |
| region i-1 | region i   | 1024 chunks |    region 0 holds the trailing copy of the last region of the group
| 128 sect.  | 128 sect.  | 8192 sect.  |
+------------+------------+-------------+
```

### Groups

The lower device is a sequence of groups of one size, a power of two from 16 MiB to 4 GiB, 1 GiB by default
(`dcorrsetup format --group-size`). A group is `[header of 1 MiB | as many whole regions as fit | unused]`: 248
regions at 1 GiB and nothing unused, 1 to 3.6 MiB unused at the other sizes. The last group may be short, with the
same header and at least 2 regions; a smaller tail of the device is not used. At least 2 groups.

The header of group `g` holds a full copy of the superblock with the number of the group, the leading copy of the
bitmap of written chunks of `g`, the trailing copy of the one of `g - 1` (of the last group for group 0), and two
blocks for the dirty stripes of the parity, zeroed until the correction stage defines them; the rest is reserved.
The header and the groups are aligned to 1 MiB.

### Superblock

4 KiB: magic, version, the number of the group, a generation, flags, a UUID, a salt, the size of the lower device,
the capacity, all parameters of the layout and a CRC64 over it. Version 1 accepts only the values of
`dcorr-format.h`; they are all in the superblock, so that a later version can change them. The driver never
writes a superblock.

### Regions and metadata

The slots of a group are a sequence of regions, as in `dm-integrity`. A region holds 1024 slots of a chunk, 4 MiB,
and is laid out as `[trailing copy of the metadata of the region before | leading copy of this region | slots]`:
128, 128 and 8192 sectors, 8448 in all. The trailing copy of the last region of a group goes into the first region
of the same group. The leading copy and the slots of a region are one contiguous range, and the data stays aligned
to 128 KiB on the device.

The metadata of a chunk is an entry of 64 bytes: 8 `__le64` values, one per data sector, in order, each
`crc64_be` over the salt, the logical sector as `le64` and the 512 bytes of the sector (`src/data_crc.h`). A
metadata sector holds the entries of 8 neighbouring chunks. Only a lower device with 512-byte logical blocks works,
as metadata is written as one 512-byte sector.

### Parity columns

The slots of a group, numbered across its regions, are cut into 32 columns of equal length, 32 slots per region of
the group. The first 30 hold the data, in order; the last 2 are kept for P+Q parity, a stripe being the same
offset in every column, and are not part of the capacity. A parity slot is an ordinary slot with its own metadata;
it has no logical sector, so its CRC is defined in the correction stage. The capacity is 7680 sectors per region,
930 MiB per group of 1 GiB: the header takes 0.1%, the metadata 3%, the parity 6.25%.

### Bitmap of written chunks

One bit per slot of a group, in blocks of 4 KiB with a header of 32 bytes (CRC, generation, group, index, role) and
32512 bits. The bitmap of group `g` leads in the header of `g` and trails in the header of `g + 1`. The CRC of a
block starts from the salt, so a block of another device does not pass; its group, index and role are checked
too. A bit on the device means the data of its chunk is durable, so a device is only formatted, never zeroed.

### Formatting and loading

`dcorrsetup format` writes the header of every group, with empty bitmaps of generation 1, and wipes the starts of
group 1 of the smaller sizes, where an older format would have left a copy; nothing else.

The constructor reads the superblocks of groups 0 and 1, takes the valid one with the larger generation, warns
about a copy that is not valid, and refuses the device when neither is, when its size is not the one formatted
for, or when the length of the table is not the capacity. With group 0 not valid, the start of group 1 is probed
for each size of a group.

On the first resume of the table the header of every group is read, one request each: the superblocks of groups 2
and on are checked against the one taken, and a copy that is not valid or differs is counted and named in the log,
not refused. Each block of the bitmap is taken from its valid copy with the larger generation. A block valid in one
copy is repaired by the next flush, unless the table is read only; a block invalid in both makes its range read
only. The bitmap is read on the first resume, not in the constructor: on a reload the old table has written its
bitmap by then.

## I/O path

### Rules

- Nothing on the I/O path allocates in a way that can fail: per-bio data, embedded structures, pools allocated
  when the target is created.
- All waiting happens in `dcorr_map`, which slows down the submitter as a full disk queue would, or in the worker of
  the cache, which runs on a workqueue of its own. The workers of `transform_wq` never wait for memory, a limit or
  a lock, as they run the completions that give those back.
- `dcorr_map` never waits for a lower bio of its own: it stays on `current->bio_list` until `map` returns.
- A part never holds one element of a pool while waiting for another from the same pool.
- The number of requests in flight is bounded.

Device mapper splits each read and write at chunk boundaries (`max_io_len` of 8 sectors), so each piece is within
one chunk. A discard is not split at chunks, only by the limits of the queue.

### Write path

1. A write is copied into the entry of its chunk in the cache and completes at once. It waits in `dcorr_map` while
   the entry is under write back, or while no entry is free. A write to a read only range fails.
2. The worker writes the entry back later: by age, under pressure, or for a flush, a FUA write or a suspend. It
   waits first until no read of the chunk is in flight.
3. If the chunk was written back since the last flush, or its bit is clear while a clear of a discard is not yet
   synced, the worker syncs first: a barrier. If the two copies of its metadata differ in the sectors to be written, after a
   crash or a failed write back, the chunk is read and settled. A chunk whose bit is clear is not read: it is
   written whole, zeros around what was written from above.
4. One job per run of dirty sectors: it computes the CRCs, puts them into the leading copy of the metadata area in
   RAM, writes the leading metadata sector from there with FUA, and only then the data.
5. Once a job succeeds, the bit of a first write back is set in RAM. After the next flush of the lower device the
   bit and the trailing copy follow, see [Flushes](#flushes). Until then the trailing copy has the CRC of the old
   data and the leading one that of the new, so after a crash each sector reads its old or its new data.

### Read path

1. The sectors held in the cache are copied from it.
2. A chunk whose bit is clear completes with zeros, without a read of the lower device or its metadata.
3. For the others: the read is registered in the tree of reads of the cache, both entries of the chunk are copied
   from the metadata area of its region in RAM, the data is read, and in a worker each sector is checked: it
   passes if it matches either copy. A mismatch fails the bio with `BLK_STS_IOERR`.

### Cache

Every write goes through a write back cache of 64 MiB per device, allocated when the target is created: one entry
per chunk, with a page, a mask of the sectors written into it, a place in a tree ordered by chunk and a place in a
list ordered by age (`src/cache.c`). Only dirty data is kept; clean data is not cached.

The worker writes back the entries older than 1 second, as many as keep at least 55% of the entries free once more
than half are in use, and all of them for a flush, a FUA write or a suspend. An entry whose write back failed keeps
its data, every flush fails while it is there, and it is tried again on the next flush, suspend or write to it. If
every entry has failed, new writes fail. A suspend writes back everything, so a table reload or a removal loses
nothing, except chunks that still fail to write: they are named in the kernel log.

### Metadata in RAM

The driver keeps the metadata of the regions it used in RAM: 32 areas, each with both copies of 64 KiB, 4 MiB per
device, covering 128 MiB of data (`src/metadata.c`). The first read or write back that needs a region reads both
copies, one request each, on a workqueue of its own; whoever needs it meanwhile waits, `dcorr_map` included. Then
reads and write backs of the region take the CRCs from RAM, and a write back changes the leading copy there in
place before it writes the sector. The trailing copy in RAM changes only when it is written.

An area with chunks written back since the last flush is pinned until their trailing copy is written. When
another region needs a place, the area used longest ago that nobody holds is dropped. When half the areas are held
or pinned, the worker syncs by itself before the next write back: a crowded flush. A suspend writes the trailing
copies and then drops every area, as the lower device may change before the device is resumed.

If the read of a copy fails, its sectors are read one at a time. A sector that failed in one copy is taken from the
other, and a rate-limited warning names each chunk read or written with one copy; the next write of that sector
puts it right. Only the chunks whose entries are in a sector failed in both copies fail, and an area with such
sectors is read again by the next request that finds it unused. A trailing sector that fails to write is counted,
and its chunks go on with the leading copy.

### Flushes

The device reports a write cache with FUA. An empty flush and a FUA write go to the worker, which writes back
everything dirty, waits for it, and syncs:

1. flush the lower device: the data written back is durable;
2. write the first copy of each block of the bitmap with new or cleared bits, with the next generation, and flush:
   a bit on the device means durable data;
3. complete the flushes from above: with an error if any entry has failed to write back, or a block of the bitmap
   failed to write, as a flush promises that nothing is left only in RAM;
4. write the trailing copies of the metadata of the chunks written back, and the other copy of the blocks of the
   bitmap, and flush, so that both copies are durable before the chunks are written back again.

If the first flush fails, no trailing copy is written, as the data may not be on the device: the areas stay pinned
and their chunks count as written since the last flush, so none of them is written back before a sync succeeds,
and that sync writes their trailing copies. When the sync of a barrier or of crowded areas fails, the worker
stops: the entries it has not written back yet fail without I/O and keep their data, and a later pass or a flush
tries the lower device again. A suspend whose sync fails unpins the areas anyway, as it drops the metadata in RAM.

### Discard

The device offers discard in whole chunks (`discard_granularity` 4 KiB, no limit of its own on the length) and
never passes it down. A discard of no whole chunk completes at once; one that touches a read only range fails. The
rest goes to the worker, which waits for the write backs in flight, drops the entries of the whole chunks of the
range with their data, clears their bits and completes the bio; the partial chunks at the ends are left as they
are. The worker does it, not `dcorr_map`, as a sync writes the blocks of the bitmap from RAM and no bit may change
under it.

The cleared bits reach the device with the next sync, so after a crash before it the chunks may hold their old
data. Until then the bit of such a chunk is still set on the device, so its first write back, which does not
settle, syncs first, counted as a barrier; if that sync fails, the write back is given up, as for any barrier.

Write zeroes is offered where the device below has it, as device mapper offers it only then (D23), and is never
passed down either. Device mapper does not split it at chunks. Its partial chunks are written as zeros through the
cache, as a write would be; its whole chunks go to the worker as a discard and read as zeros once their bits are
cleared, without counting as a discard. `REQ_NOUNMAP` changes nothing. Like a write it is durable after the next
flush, and with FUA it completes after the worker has flushed. One that touches a read only range fails. Where
the device below has no write zeroes, the kernel zeroes with ordinary writes.

### Synchronization

Only reads from the lower device and write backs reach the lower device, and the cache keeps them apart, the way
`dm-integrity` keeps its ranges in flight:

- A read from the lower device is put into the tree of reads of the cache before it is sent, and taken out when
  it completes. The node is in the per-bio data of the read, so this allocates nothing.
- A write back of an entry waits until no read of its chunk is in flight: a read that met it could get the data of
  one version of a sector and the CRC of another, and fail.
- New reads of the clean sectors of an entry under write back wait in `dcorr_map`, so the reads of a chunk end. Reads
  of its dirty sectors are copied from the cache.
- The jobs of the chunks of one metadata sector go one at a time, as each writes that sector from the same memory:
  a second one would change it under the first. The end of one starts the next, without a worker waiting.

The cache has one spinlock, held only for a lookup and a copy of at most one chunk, never across I/O. The worker
waits for no job or no write back in flight without it, before a sync or a discard, and then takes it once: the
completion of the last job lowers the counters and sets the bit of its chunk in one hold of the lock, and the
sync must not write the bitmap before that hold ends.

### Memory

Nothing on the I/O path allocates memory. The cache, with its pages and 256 write back jobs, the metadata in RAM,
with its 32 areas and a scratch area where the trailing sectors are built, and the bitmap, 32 MiB per TiB, are
allocated when the target is created. A part lives in the per-bio data of its bio, or in a job, with its metadata
structure and its metadata bio embedded in it. `dcorr_map` and the worker wait for an area to be read, or let go when
all are in use; the workers of `transform_wq` never wait.

At most 4096 parts, reads and jobs, are in flight per device. A bio-based device has no request queue with tags,
so `dcorr_map` and the worker wait for a place instead, which slows down the submitter as a full disk queue would.
Ordinary load never reaches the limit: 4096 parts are 16 MiB of data.

## Errors

A failed lower bio or a CRC mismatch fails the part with `BLK_STS_IOERR`. A failed write back fails the flushes
until the chunk is written. An error is a strong sign that the drive is failing (D22), so each is a signal:

- **Counters** in `dmsetup status`, see [Interface](#interface): failed reads of data, sectors that match neither
  CRC (a read checks all its sectors), failed write backs, sectors of the metadata that fail to read, failed
  flushes of the lower device; and those of the metadata and the bitmap from before.
- **A device mapper event** at the first error since the table was created, of any kind counted, from a work
  item; `dmsetup wait` and `dmeventd` see it, and read the counters. Later errors raise none.
- **A line in the kernel log**, naming the device as `dmsetup` does and the logical sector, never the physical
  one; every message that I/O can repeat is rate limited, 10 in 5 s for each place in the code. The messages of
  a device are printed from process context, as the name is looked up under a mutex of device mapper: a failed
  read is logged by `complete_work`, not by the completion of its bio.

## Interface

**`dcorrsetup`** (`tools/dcorrsetup.c`): `format` writes the headers, refusing a device in use, one smaller than
two groups, and one that already holds a valid superblock unless given `--force`; `--group-size` chooses the size
of a group, a power of two from `16M` to `4G`, `1G` by default. `dump` prints the superblock and the layout as
`key=value`, `table` the line for `dmsetup`.

**The table line** is `0 <capacity> dcorr <lower device>`; the length must be the capacity in the superblock.
`dmsetup table` gives the lower device as major:minor, as every target does, so the line it prints loads again.

**`dmsetup status`** prints 26 counters after `<start> <length> dcorr`, in this order. In the driver they are the
fields of `struct dcorr_stats` (`src/stats.h`), with the same names, but `dirty` and `failed`, which are states of
the cache; `dcorr_status` prints them:

| # | Name in the tests | What it counts |
| --- | --- | --- |
| 1 | `map_waits` | Reads that waited in `dcorr_map` for a place among the parts in flight |
| 2 | `free_waits` | Writes that waited for a free entry of the cache |
| 3 | `busy_waits` | Writes that waited for an entry under write back |
| 4 | `read_waits` | Reads of the lower device that waited for the write back of their chunk |
| 5 | `dirty` | Entries with data not yet on the lower device |
| 6 | `failed` | Entries whose write back failed |
| 7 | `metadata_loads` | Metadata areas read from the lower device |
| 8 | `metadata_waits` | Waits for a metadata area to be let go, as all were in use |
| 9 | `trail_errors` | Sectors of the trailing copy of the metadata that failed to write |
| 10 | `crowded_flushes` | Syncs the worker made by itself, as too many metadata areas were busy |
| 11 | `barriers` | Syncs before a write back of a chunk written back since the last flush, or of a chunk whose bit is clear while a clear is not yet synced |
| 12 | `settle_reads` | Chunks read before a write back, as their two copies of the metadata differed |
| 13 | `settle_mismatches` | Sectors so read that matched neither copy, or did not read |
| 14 | `unwritten_reads` | Chunks read as zeros without a read of the lower device, as never written |
| 15 | `read_only_blocks` | Blocks of the bitmap invalid in both copies when the device was created |
| 16 | `single_blocks` | Blocks of the bitmap with one valid copy then, repaired by the next flush |
| 17 | `bad_superblocks` | Copies of the superblock of groups 2 and on that are invalid or differ |
| 18 | `bitmap_write_errors` | Copies of blocks of the bitmap that failed to write |
| 19 | `refused_writes` | Writes and discards refused in a read only range |
| 20 | `discards` | Discards that reached the target, those covering no whole chunk among them |
| 21 | `discarded_chunks` | Whole chunks they covered |
| 22 | `read_errors` | Reads of data from the lower device that failed |
| 23 | `crc_mismatches` | Sectors read from the lower device that matched neither CRC of their chunk |
| 24 | `write_errors` | Write backs that failed, at the leading metadata sector or at the data |
| 25 | `metadata_read_errors` | Sectors of a copy of the metadata that failed to read, counted at each read of the area |
| 26 | `flush_errors` | Flushes of the lower device that failed |

The first error that any of `trail_errors`, `settle_mismatches`, `read_only_blocks`, `single_blocks`,
`bad_superblocks`, `bitmap_write_errors` and counters 22 to 26 counts raises a device mapper event, see
[Errors](#errors).

**Queue limits:** the limits of the lower device are stacked through `iterate_devices`, over the part of it
the layout uses, then `io_hints` puts what the target does itself (D23): logical blocks of 512 bytes, the lower
device refused otherwise; the physical block and the minimal I/O a chunk, 4 KiB, or larger if the lower device
has them; no optimal I/O and no alignment offset, as the layout breaks those of the lower device; discard in
chunks, `discard_granularity` 4 KiB and `max_hw_discard_sectors` of `UINT_MAX >> 9`; write zeroes of the same
length where the lower device has it; no polling and no stable pages. The device reports a write cache with FUA.
A zoned lower device is refused by device mapper, as the target is not zoned.

## Open questions

- **Proportions.** How much data one metadata block covers: 32 KiB per sector of metadata today. A larger unit
  means less overhead and fewer metadata requests, but more read amplification for small reads, and it sets the
  unit of the cache and of ECC. To be measured against the baseline. It also has to fit a lower device with 4 KiB
  logical blocks: then the metadata is written in blocks of 4 KiB, 64 chunks to a block.
- **ECC.** The code, how much space it takes, and how it combines with the CRC. What the reading on drive failures
  settled: it corrects erasures between chunks, as a drive returns an error and not damaged bits; a stripe is not
  made of neighbours, as damage comes in consecutive blocks; on an HDD its redundancy lies far from the data;
  parity is updated only from data that passed its CRC, or one error spreads over the stripe.
- **What correction does**: rebuild the data, write it back in place or elsewhere, and what it counts.
- **Writing the superblock**: when the driver writes the header and raises its generation, putting a damaged copy
  right, and growing a device, which is a feature of its own.

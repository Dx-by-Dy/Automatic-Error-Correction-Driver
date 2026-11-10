# Architecture

Draft. This file holds the global decisions: what the driver protects against, what it promises to the layer
above, the on-disk format and the shape of the I/O path. How the driver works today is in [README.md](README.md),
what is not done yet is in [TODO.md](TODO.md).

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

In scope, **Decided** for the first two, **Proposed** for the third:

- **A sector fails to read.** The lower device returns an error for a sector or a range (a latent sector error,
  an unrecoverable read). Only the data that depends on that sector may fail; the rest of the device stays
  readable. With ECC the data is rebuilt from redundancy. Redundancy next to the data may fail along with it,
  which matters when choosing where it lives.
- **Data is damaged silently.** The lower device returns data without an error, but it differs from what was
  written: decay of the medium, a firmware or a transfer fault. The CRC detects it, ECC will repair it.
- **A write fails.** A degrading drive returns errors on writes. The error reaches the layer above, see
  [Contract](#contract-with-the-layer-above).

Not a threat to the data, but a requirement, **Proposed**:

- **A crash or a power loss.** By itself it damages nothing: which writes survive is the business of the
  filesystem journal, which relies on flushes and FUA. The driver must not turn a write cut short by the crash
  into a read error, see the contract.

**Open**, until the published work on drive failures is read (postponed on 2026-11-10):

- A region that reads back as zeros: lost by the drive, trimmed, or never written.
- A lost write: the drive acknowledges it, but the old contents stay.
- A misdirected write: the data lands on another sector. The sector number is not part of the CRC today.

The answers decide the seed of the CRC, whether the position is mixed into it, and whether the driver needs a
"never written" state.

Out of scope, **Proposed**:

- **Deliberate modification.** CRC64 is not a cryptographic hash. That is the task of `dm-verity` or of
  `dm-integrity` with an HMAC.
- **Loss of the whole device.** That takes redundancy across devices, as in RAID.
- **Memory errors** in the host.

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

**Current.** Points 1 and 2 hold: an empty flush goes to the lower device as it is, and a FUA write is FUA
for both its data and its metadata. As a write completes only once both have, a flush covers every write
completed before it. Point 3 does not hold: data and CRC are two writes ("Data and CRC are not written
atomically" in `TODO.md`).

## On-disk format

**Current.** Not final: there is no superblock and no version, so a change of format needs no migration.

- The lower device is a sequence of chunks of 9 sectors: 8 data sectors, then 1 metadata sector. The logical
  sector `s` is at `s / 8 * 9 + s % 8` on the lower device. The capacity is `lower / 9 * 8`, rounded down.
- The metadata sector holds 8 `__le64` values, `crc64_be` of each data sector with a zero seed, in order. The
  other 448 bytes are zero and unused.
- There is no "never written" state. A device has to be zeroed before use; a chunk of zeros with zero metadata
  passes the check.
- Only a lower device with 512-byte logical blocks works, as metadata is written as one 512-byte sector.
- The tests have their own copy of the layout in `correction-driver/tests/harness.py`.

**Decided.** Metadata stays next to its data. A run of data and its metadata are neighbours on the lower
device, so the cache can read or write them in one request, and no seek separates them.

**Open:**

- **Proportions.** How much data one metadata block covers: 4 KiB per sector of metadata today. A larger unit
  means less overhead and fewer metadata requests, but more read amplification for small reads, and it sets
  the unit of the cache and of ECC. To be measured after the cache, against the baseline. It also has to fit a
  lower device with 4 KiB logical blocks.
- **CRC unit.** Per 512-byte sector, as now, tells which sector is bad, which helps correction. Per 4 KiB takes
  less space.
- **ECC.** The code, the unit it corrects (bits, a sector, a run), how much space it takes, where the redundancy
  lives (next to the data it may fail along with it), and how it combines with the CRC.
- **Seed and position** in the CRC: after the threat research, see above.
- **Superblock and version**: once the format settles. It will hold the version, the layout parameters and the
  state needed for the points above.

## I/O path

**Decided**, the rules from stage 2 that any new design keeps:

- Nothing on the I/O path allocates in a way that can fail: per-bio data, embedded structures, mempools.
- All waiting happens in `dm_map`, which slows down the submitter as a full disk queue would. A worker never
  waits for memory, a limit or a lock, as workers run the completions that give those back.
- A part never holds one element of a pool while waiting for another from the same pool.
- The number of requests in flight is bounded.

**Current.** Device mapper splits each bio at chunk boundaries (`max_io_len` of 8 sectors). Each piece is a part
in the per-bio data of its bio, takes the lock of its chunk, and goes to the lower device as a data bio and a
metadata bio. A write computes the CRC in `dm_map`; a partial write reads the old metadata first. A read checks
the CRC in a worker. Details are in [README.md](README.md).

**Decided**, why this has to change: upper bios are tied to lower bios one chunk at a time. A large request
becomes many 4 KiB pieces, each with its own metadata request, and a read takes two lower requests per chunk.
This is expected to cost much of the throughput at large volumes. Splitting at chunk boundaries is an interim
step, taken because synchronizing overlapping upper bios with lower bios in flight was the main source of
complexity and bugs.

## Cache

**Draft.** The next large piece of work, after the test base. Only its purpose is decided; the rest is to be
discussed before it is designed.

**Decided:**

- **Purpose: aggregation.** The cache separates the work with bios from above from the work with bios below.
  The data of an upper bio is copied into pages of the driver in RAM. The driver builds its own lower bios over
  runs of chunks, computes the CRC (and later ECC) only when it writes to the lower device, and checks it only
  when it reads from it.
- **Pages are copied**, so a page changed by the layer above after it was submitted no longer matters. This
  closes "Pages can change after their CRC is computed" in `TODO.md`.
**Open**, whether a journal is needed. The user's view: with flushes and FUA handled correctly, the
filesystem journal decides which writes survive a crash, so the cache needs no journal of its own. That holds
for the order of writes, but point 3 of the contract stays with the driver, see the first open question below.

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
  metadata are still separate writes, and a drive is atomic only per sector. The options known so far:

  | Option | How | Cost |
  | --- | --- | --- |
  | Bitmap, as in `dm-integrity` | Mark the regions of a write back dirty, flush, write data and metadata. After a crash, recompute the CRC of the dirty regions | No detection in the regions dirty at the crash |
  | Two CRCs | Write metadata with both the old and the new CRC, flush, write the data. A read takes either | Keeps detection; ECC would need both the old and the new redundancy |
  | Journal | Every write goes to a journal first, then to its place | Every write twice |

  The choice depends on the design of ECC. The write back of the cache has to leave room for this step; the
  decision is due before correction.
- **What happens to dirty data whose write back failed**: kept in RAM and retried, or dropped once the error is
  reported. It matters for the goal of moving data off a failing drive.
- **The unit of the cache**, its size, and when it writes back: on a flush, by age, by the share of dirty pages,
  under memory pressure.
- **Reads.** The page cache above already caches data, so the cache serves reads mainly to stay coherent with
  dirty data and to read whole runs. Whether clean data is kept after a read is open.
- **`dm-bufio`**, the device mapper library for caching metadata blocks: whether it fits, or the cache is a
  structure of its own.

## Errors

**Current.** A failed lower bio or a CRC mismatch fails the part with `BLK_STS_IOERR`, and a mismatch prints a
line with `pr_err`, with no rate limit and without the name of the device.

**Proposed**, as the goal is to move data off a failing drive: an error must not make healthy data unreadable,
and errors must be visible to the user as counters in `dmsetup status`.

**Open.** What correction does once ECC exists: rebuild the data, write it back in place or elsewhere, and what
it counts.

## Testing

**Decided:**

- Everything runs in the development VM with a debug kernel, never on the host: [deploy/README.md](deploy/README.md).
- Crash consistency is tested with `dm-log-writes` below the driver and `replay-log` from xfstests: the log
  holds every lower request with its flushes and FUA, and replaying a prefix of it to a clean device gives the
  state after a crash at that point. A prefix that ends at a flush must keep everything the filesystem made
  durable. A prefix that cuts a write between its data and its metadata is a strict `xfail` until the open
  question in [Cache](#cache) is decided.
- Failures of the lower device are tested with `dm-dust` (reads of chosen blocks fail) and `dm-flakey` (writes
  fail or are dropped for a while).

## Decision log

| Date | Decision | Why |
| --- | --- | --- |
| 2026-11-09 | Device mapper splits requests at chunk boundaries, the part lives in per-bio data | Removes the bugs of pairing upper and lower bios by hand; an interim step, the cache replaces it |
| 2026-11-09 | Nothing on the I/O path can fail to allocate; waits only in `dm_map`; at most 4096 parts in flight | Workers that wait hang the device; a bio-based device has no queue to bound the load |
| 2026-11-10 | The cache comes right after the test base, before the format and the rest of integrity | It changes the I/O path, the unit of the format and how flushes work, so later work would be redone |
| 2026-11-10 | The cache copies data and aggregates writes; CRC and ECC are computed only towards the lower device | Performance at large volumes, and the stable page problem goes away |
| 2026-11-10 | Metadata stays next to the data; the proportions are measured later | One request for data and metadata; the right proportion needs the cache and the baseline |
| 2026-11-10 | Seed, position in the CRC and the "never written" state wait for research on drive failures | Not clear how real the threat of zeroed regions is for a degrading drive |

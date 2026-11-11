# Architecture

Draft. This file holds the global decisions: what the driver protects against, what it promises to the layer
above, the on-disk format and the shape of the I/O path. How the driver works today is in [README.md](README.md),
what is not done yet is in [TODO.md](TODO.md), the reasons behind the decisions are in [RESEARCH.md](RESEARCH.md).

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

**Current.** Points 1 and 2 hold: an empty flush and a FUA write wait until the cache has written back
everything dirty and the lower device has flushed. Point 3 does not hold: data and CRC are two writes ("Data
and CRC are not written atomically" in `TODO.md`). Point 5 holds as written: a failed write back fails every
flush until the chunk is written.

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
  lower device with 4 KiB logical blocks. Two CRCs make the metadata durable before the data, so with 8 data
  sectors to 1 of metadata a run is no longer one request, see
  [RESEARCH.md](RESEARCH.md#a-write-cut-short-by-a-crash-two-crcs).
- **CRC unit.** Per 512-byte sector, as now, tells which sector is bad, which helps correction. Per 4 KiB takes
  less space. With two CRCs it cannot be larger than what the drive writes atomically.
- **ECC.** The code, the unit it corrects (bits, a sector, a run), how much space it takes, where the redundancy
  lives (next to the data it may fail along with it), and how it combines with the CRC.
- **Seed and position** in the CRC: after the threat research, see above.
- **Superblock and version**: once the format settles. It will hold the version, the layout parameters and the
  state needed for the points above.

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
into the cache and completes. The worker writes an entry back as one part per run of its dirty sectors: the part
takes the lock of its chunk and goes to the lower device as a data bio and a metadata bio, and a partial chunk
reads the old metadata first. A read takes the sectors the cache holds from it; the rest is a part in the
per-bio data of its bio, which reads from the lower device and checks the CRC in a worker. Details are in
[README.md](README.md).

**Decided**, why this has to change: upper bios are tied to lower bios one chunk at a time. A large request
becomes many 4 KiB pieces, each with its own metadata request, and a read takes two lower requests per chunk.
This is expected to cost much of the throughput at large volumes. Splitting at chunk boundaries is an interim
step, taken because synchronizing overlapping upper bios with lower bios in flight was the main source of
complexity and bugs.

## Cache

**Draft.** The next large piece of work, after the test base. How other targets do this, and what it costs, is in
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
  requires is in [RESEARCH.md](RESEARCH.md#a-write-cut-short-by-a-crash-two-crcs).
- **The layout stays 8 data sectors to 1 of metadata**; a larger metadata block is considered only after
  measuring the cache and two CRCs on it.
- **A failed write back:** the error is per chunk, not for the device. The data stays in RAM, and the cache has one
  place where a reserved area can be plugged in later. When such chunks fill the cache, new writes are refused.
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
  a reload is lost, with its number in the kernel log. The reserved area will give it somewhere to go.
- **The lock of a chunk moves into the cache**, after the first version of the cache and before runs: a read of
  the lower device registers its range in the tree of the cache while in flight, and a write back waits for the
  reads in flight on its chunks, while new reads of their clean sectors wait for it. A run spans many chunks, and
  a part may not hold many chunk locks.
- **Defaults are constants for now:** 64 MiB of cache per device, write back from 50% used down to 45%, an age of
  1 s. They are to be tuned later.


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
- **A reserved area for failed write backs.** Proposed, not decided: such a chunk moves to a slot on the lower
  device, with a table that redirects later access. As slots run out the device warns, then accepts only writes
  that matter for the filesystem, then becomes read only. A write back that found a slot does not fail the next
  flush. It needs a superblock, so it waits for the format. See
  [RESEARCH.md](RESEARCH.md#a-failed-write-back-a-reserved-area).

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
- Crash consistency is tested with `dm-log-writes` below the driver, and a replay of its log in the tests
  (the format of `replay-log` from xfstests): the log holds every lower request with its flushes and FUA, and
  replaying a prefix of it to a clean device gives the state after a crash at that point. A crash right after
  an `fsync` must keep everything the filesystem made durable, and so must a crash at any flush or FUA write
  while other writes of the filesystem are in flight. A crash between the data and the metadata of one write is
  strict `xfail` until the two CRCs of [Cache](#cache) are written.
- Failures of the lower device are tested with `dm-dust` (reads of chosen sectors fail, and writes to them a
  chosen number of times) and `dm-flakey` (every write fails, reads go through). Writes that are dropped
  silently wait for the threat model, as lost writes are an open threat.

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
| 2026-11-11 | Every flush fails while unwritten chunks remain; partial chunks keep a dirty mask; a write to a chunk under write back waits, a second copy is left for optimization | A flush must not promise what is not on the device; a bad neighbouring sector must not stop a write; simplest first |

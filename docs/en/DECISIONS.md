# Decisions

Why dm-dcorr is built the way [ARCHITECTURE.md](ARCHITECTURE.md) describes. Each decision says why a choice was
needed, which options were on the table, what was chosen and why, with the reading behind it in
[RESEARCH.md](RESEARCH.md). A decision is changed only by a new one that says it supersedes it; superseded
decisions stay here for their reasoning. "The user" is the author of the project, who settles each design point.

| # | Date | Decision | Status |
| --- | --- | --- | --- |
| [D1](#d1-tests-run-in-a-vm-crashes-are-replayed-from-a-log) | stage 1 | Tests run in a VM; crashes are replayed from a log | In force |
| [D2](#d2-device-mapper-splits-requests-at-chunk-boundaries) | 2026-11-09 | Device mapper splits requests at chunk boundaries | In force |
| [D3](#d3-nothing-on-the-io-path-can-fail-to-allocate) | 2026-11-09 | Nothing on the I/O path can fail to allocate; waits only in `dm_map` and the worker | In force |
| [D4](#d4-a-write-back-cache-of-our-own-in-ram) | 2026-11-10, 11-11 | A write back cache of our own in RAM, before the format | In force |
| [D5](#d5-a-write-cut-short-by-a-crash-two-crcs) | 2026-11-11 | A write cut short by a crash: two CRCs | Realized as D10 |
| [D6](#d6-a-failed-write-back-stays-in-ram) | 2026-11-11 | A failed write back stays in RAM; flushes fail meanwhile | In force |
| [D7](#d7-simplest-first-in-the-cache) | 2026-11-11 | Simplest first in the cache: FUA as a flush, waits for an entry under write back | In force, for optimization |
| [D8](#d8-reads-in-flight-instead-of-chunk-locks) | 2026-11-11 | Reads in flight in the tree of the cache instead of chunk locks | In force |
| [D9](#d9-metadata-in-an-area-per-region) | 2026-11-11 | Metadata in an area per region | In force |
| [D10](#d10-the-two-copies-of-the-metadata-are-the-two-crcs) | 2026-11-14 | The two copies of the metadata are the two CRCs | In force |
| [D11](#d11-metadata-in-ram) | 2026-11-14 | Metadata in RAM, a pool of its own | In force |
| [D12](#d12-runs-after-the-format) | 2026-11-14 | Runs after the format, their shape decided | In force, order changed by D21 |
| [D13](#d13-the-threat-model) | 2026-11-15 | The threat model, after the reading on drive failures | In force |
| [D14](#d14-the-crc-stays-per-512-byte-sector) | 2026-11-15 | The CRC stays per 512-byte sector | In force |
| [D15](#d15-no-reserved-area) | 2026-11-15 | No reserved area for failed write backs | In force |
| [D16](#d16-a-superblock-written-by-a-utility-in-userspace) | 2026-11-15 | A superblock written by a utility in userspace | In force; its two copies superseded by D17 |
| [D17](#d17-groups) | 2026-11-15 | Groups, a superblock in each, parity reserved in columns | In force |
| [D18](#d18-a-bitmap-of-written-chunks) | 2026-11-15 | A bitmap of written chunks, a bit on the device meaning durable data | In force |
| [D19](#d19-the-seed-salt-logical-sector-data) | 2026-11-15, 11-16 | The seed: salt, logical sector, data | In force |
| [D20](#d20-discard-through-the-bitmap) | 2026-11-16 | Discard through the bitmap; no write zeroes yet | In force; write zeroes superseded by D23 |
| [D21](#d21-device-mapper-integration-and-docs-before-runs) | 2026-11-16 | Device mapper integration and docs before runs | In force |
| [D22](#d22-errors-as-a-signal-counters-one-event-the-name-of-the-device) | 2026-11-16 | Errors as a signal: counters, one event, the name of the device | In force |
| [D23](#d23-the-limits-of-the-lower-device-and-write-zeroes) | 2026-11-16 | The limits of the lower device, and write zeroes | In force; supersedes the write zeroes of D20 |

## D1. Tests run in a VM; crashes are replayed from a log

**Why a choice was needed.** A kernel driver under development can take the machine down, and its hardest
property, what survives a crash, cannot be checked by pulling the plug.

**Options.** Tests on the host; a VM per run with virtme-ng; a QEMU VM with a debug kernel and SSH. For crashes:
real power cuts, or a log of the writes below the driver replayed to a clean device.

**Chosen.** Everything runs in a QEMU VM with a debug kernel (KASAN, lockdep, kmemleak), driven by
`deploy/vm.sh`, never on the host ([DEPLOY.md](DEPLOY.md)). Crash consistency is tested with `dm-log-writes`
below the driver: replaying a prefix of its log to a clean device gives the state after a crash at that point.
Failures of the lower device are made with `dm-dust`, `dm-flakey` and `dm-delay` ([TESTS.md](TESTS.md)).

**Why.** The user already had the VM; a debug kernel finds memory and locking bugs the tests would not see. A
replay checks every point between two flushes, which no number of power cuts does. Its limit: the log is in the
order writes complete, so an order inside one flush is checked in the log itself, not by replays.

## D2. Device mapper splits requests at chunk boundaries

**Why a choice was needed.** The first version paired every upper bio with lower bios by hand, and synchronizing
overlapping upper bios with lower bios in flight was the main source of complexity and bugs, a use-after-free
among them.

**Options.** Point fixes to that pairing; or letting device mapper split each bio at chunk boundaries
(`max_io_len`) and keeping the state of a piece in its per-bio data.

**Chosen.** Device mapper splits; a part lives in the per-bio data of its bio.

**Why.** It removes the pairing bugs at once. It is an interim step: a large request becomes many 4 KiB pieces,
which costs throughput, and the cache (D4) and runs (D12) were planned to take the aggregation over, so no complex
machinery was to be built around the pairing.

## D3. Nothing on the I/O path can fail to allocate

**Why a choice was needed.** Workers that waited for memory or a lock hung the device, as they also run the
completions that give those back; and a bio-based device has no request queue to bound the load.

**Chosen.** Nothing on the I/O path allocates in a way that can fail: per-bio data, embedded structures, pools
allocated with the target. All waiting happens in `dm_map` or in the worker of the cache; the workers of
`transform_wq` never wait. `dm_map` never waits for a lower bio of its own. At most 4096 parts in flight per
device, waited for in `dm_map`, counted in `dmsetup status`.

**Why.** The rules make a hang under memory pressure impossible by construction, and `test_memory.py` checks it
with fault injection. 4096 parts are 16 MiB of data, more than any disk queue, so ordinary load never waits.

## D4. A write back cache of our own in RAM

**Why a choice was needed.** With requests cut at chunks (D2) every 4 KiB is its own metadata request, and the
pages of the layer above may change after their CRC is computed (the stable page problem). The cache also
changes the I/O path, the unit of the format and how flushes work, so it had to come before the format.

**Options**, from [RESEARCH.md](RESEARCH.md#caches-and-integrity-in-device-mapper): `dm-bufio` for the data;
a structure of our own in the shape of the pmem mode of `dm-writecache`; keeping clean data too or only dirty.

**Chosen.** On 2026-11-10: the cache copies the data of an upper bio into pages of the driver and aggregates
writes; CRC and ECC are computed only towards the lower device; it comes right after the test base. On
2026-11-11: a structure of our own (a pool allocated up front, a tree by chunk, a list by age, two watermarks
and an age for write back), the chunk as its unit, only dirty data kept, no `dm-bufio`.

**Why.** Copying ends the stable page problem and separates the bios from above from the bios below, so the
driver can build its own large requests. `dm-bufio` is made for metadata: it refuses to run from `map`, lets a
thread hold one buffer, and `dm-ebs` writes the dirty buffers before completing each batch, so nothing would be
deferred. A structure of our own keeps write back under the control of the driver. Unlike `dm-writecache`, a
flush has to reach the lower device, as RAM is volatile.

## D5. A write cut short by a crash: two CRCs

**Why a choice was needed.** Point 3 of the contract: after a crash each sector reads its old or its new
contents. Data and metadata are separate writes, and a drive is atomic only per sector, so a crash between them
leaves data that does not match its CRC.

**Options** ([RESEARCH.md](RESEARCH.md#a-write-cut-short-by-a-crash-two-crcs)):

| Option | How | Cost |
| --- | --- | --- |
| A bitmap, as in `dm-integrity` | Mark the regions of a write back dirty, flush, write; after a crash recompute their CRCs | No detection in the regions dirty at the crash |
| Two CRCs | Metadata holds the old and the new CRC, made durable before the data; a read takes either | Keeps detection; ECC needs the old and the new redundancy |
| A journal | Every write goes to a journal first | Every write twice; `dm-integrity` loses half its throughput |

**Chosen.** Two CRCs, no journal of the cache.

**Why.** No blind spot and no double write, and it fits the format. What it requires: the metadata durable
before the data, the old CRCs known, a way to tell which CRC is current after a crash. How it was realized is
D10.

## D6. A failed write back stays in RAM

**Why a choice was needed.** With a write back cache the bio has completed before its write back fails, so the
error has to reach the layer above some other way, and the data must not be lost.

**Options.** One error for the whole device, as `dm-writecache` and `dm-integrity` do (writes or everything
fail); an error per chunk; a reserved area to put the chunk elsewhere (D15).

**Chosen.** The error is per chunk: the data stays in RAM, every flush fails while such a chunk remains, and it is
retried on a flush, a suspend, or a new write to it; when such chunks fill the cache, new writes are refused and
reads go on. A suspend cannot fail, so a chunk that still fails then is lost, named in the kernel log.

**Why.** A flush that succeeds promises that the data is on the device, so it must fail; but one bad place must
not stop the whole device, whose purpose is to keep the rest readable. Retrying only at those moments needs no
timer of its own.

## D7. Simplest first in the cache

**Why a choice was needed.** Several behaviours of the cache had a simple and a fast form.

**Chosen**, each left for the optimization stage ([TODO_OPTIMIZATION.md](TODO_OPTIMIZATION.md)):

- **A FUA write goes the way of a flush**: everything dirty is written back and the lower device flushed. One
  path of code.
- **A partial chunk keeps a mask** of its dirty sectors; write back writes only those, without reading the
  rest.
- **A write to a chunk under write back waits** in `dm_map`, counted. A second copy of the chunk, as in
  `dm-writecache`, is the likely final answer.
- **Defaults are constants:** 64 MiB of cache, write back from 50% used down to 45%, an age of 1 s.

**Why.** Correctness first, with counters to show where the simple form costs; the numbers of the baseline
decide what to optimize.

## D8. Reads in flight instead of chunk locks

**Why a choice was needed.** A part locked its chunk, and parts waited on a list of the lock. A run (D12) spans
many chunks, and a part may not hold many chunk locks; with the cache there were two state machines, the locks and
the entries.

**Options.** Keep chunk locks and take them for every chunk of a run; or register the reads of the lower device
in flight in the tree of the cache, as `dm-integrity` keeps its ranges in flight.

**Chosen**, on 2026-11-11, before runs: a read of the lower device is in the tree of reads of the cache while in
flight; a write back waits for the reads in flight on its chunk, and new reads of its clean sectors wait for the
write back. The jobs of the chunks of one metadata sector go one at a time.

**Why.** A read that met a write back could see the data of one version and the CRC of another; this rule is all
that is needed to prevent it, and the node lives in the per-bio data of the read, so nothing is allocated. One
state machine in the driver instead of two.

## D9. Metadata in an area per region

**Why a choice was needed.** On 2026-11-10 the metadata stayed next to its chunk, a metadata sector after every 8
data sectors, until the proportions were measured. Two CRCs (D5) then made the metadata a write that must
complete before the data, and the driver is meant for SSDs and HDDs both.

**Options.** Metadata after each chunk; one area for the whole device; an area per region, as in `dm-integrity`.

**Chosen**, on 2026-11-11, an idea of the user: regions of 1024 slots, each with its metadata area in front of
the slots, entries of 64 bytes packed 8 to a sector, and room for a copy of the area in the next region.

**Why.**

- **Two CRCs**: with metadata after every chunk a run became a row of scattered metadata writes, then the data;
  with an area per region it is two sequential requests.
- **Alignment**: chunks at `9k` were not aligned to 4 KiB, so a drive with 4 KiB physical sectors did a
  read-modify-write for every chunk, and a lower device with 4 KiB logical blocks could not work at all.
- **Density**: a sector per chunk used 64 of its 512 bytes, 12.5% of the device; packed, 1.6%, 3.1% with the
  copy, small enough to keep its hot part in RAM.
- **Locality**: a region of 4 MiB keeps the metadata near its data on an HDD; one area for the device would put
  a seek between them.
- **The copy** guards a failed metadata sector, which now covers 8 chunks.

## D10. The two copies of the metadata are the two CRCs

**Why a choice was needed.** D5 asked for an old and a new CRC per sector; a pair in one entry would double the
entry, and the copy of D9 would cost a second write for every change of metadata anyway.

**Options.** A pair of CRCs in one entry, with an epoch to tell which is current after a crash; or the two copies
of the metadata as the two slots.

**Chosen**, on 2026-11-14, an idea of the user: the leading copy gets the new CRC with a FUA write before the
data; the trailing copy keeps the CRC of the durable data until a flush makes the new data durable, and is
written then. A chunk written back since the last flush waits for a flush first (a barrier). A chunk whose
copies differ in the sectors to be written, after a crash or a failed write back, is read first (settled): a
sector matching the leading copy has that CRC written into the trailing one with FUA.

**Why.** The entry and the layout stay as they are, and in the steady state both copies are equal, so the copy
still guards a lost metadata sector. The barrier comes from a trap found on the way: a completed write is not
durable, so two write backs between flushes may leave any of three versions, with two slots. The settle replaces
the epoch: in the steady state the copies are equal, so a difference marks a chunk left by a crash, and the read
is valid as it comes after the flush. Not covered: a crash in the window together with a lost sector of the
other copy, two faults at once.

## D11. Metadata in RAM

**Why a choice was needed.** A write of the metadata of one chunk needs the other 7 entries of its sector, and a
read needs both copies of its entry; reading them from the device each time doubles the requests.

**Options.** `dm-bufio` or a structure of our own; one pool shared with the data cache or a pool of its own; which
unit to read.

**Chosen**, on 2026-11-14: the metadata area of a region as the unit, both copies, read whole the first time the
region is used; a structure and a pool of our own, 32 areas, 4 MiB; clean areas dropped by LRU and on a suspend;
a write back changes the entry in place just before it writes the sector; an area with chunks written back since
the last flush pinned until their trailing copy is written; when half the areas are busy, the worker syncs by
itself.

**Why.** The next request is likely near the last one. Two pools, the choice of the user after the trade-off: a
shared pool brings a deadlock, a write back needing room for its metadata among dirty data, and policies whose
gain is not measured. Dropping on a suspend is needed as the lower device may change across a reload.

## D12. Runs after the format

**Why a choice was needed.** A write back is one job per run of dirty sectors inside a chunk, so a sequential
1 MiB is 256 FUA writes and 256 data writes. Runs, neighbouring chunks as one bio, change no logic or guarantee,
while the format could change what a write back writes.

**Chosen**, on 2026-11-14, proposed by the user: runs move after the format stage and before the baseline, so
that the cache is measured with them. Their shape is decided: a run is a contiguous range of dirty sectors inside
one region, one FUA write of its range of leading metadata sectors, then one data bio; a clean hole breaks it,
with no read to fill it; dirty neighbours join before they are due by age; the longest run comes from
`max_sectors` of the lower device; runs that share a metadata sector at their ends go one after another; a failed
run fails all its chunks. The limits and a scheme without the queue are tuned in the optimization stage. On
2026-11-16 device mapper integration was put before them (D21).

## D13. The threat model

**Why a choice was needed.** Whether zeroed ranges, lost and misdirected writes are real threats for a degrading
drive decided whether the format needed a seed, a "never written" state and a reserved area; on 2026-11-10 these
waited for a reading of field studies.

**Chosen**, on 2026-11-15, after [the reading on drive failures](RESEARCH.md#drive-failures): the threat table of
[ARCHITECTURE.md](ARCHITECTURE.md#threat-model). Zeroed ranges and misdirected writes are in scope; lost writes
where the layout detects them; deliberate modification, loss of the whole device, memory errors, drives that
ignore flushes or hang are out.

**Why.** Latent sector errors are common and come in consecutive blocks; SSDs tore writes at 512 bytes and lost
completed writes at power faults; the first error strongly predicts the end of a drive. The consequences are D14,
D15, D18, D19, and ECC between chunks, far from the data, updated only from verified data, for the correction
stage.

## D14. The CRC stays per 512-byte sector

**Options.** A CRC per 512-byte sector, or per 4 KiB chunk, which would halve the metadata.

**Chosen.** Per 512-byte sector; per 4 KiB only for a drive known to write 4 KiB atomically.

**Why.** SSDs were seen to tear a 4 KiB write at a power fault in units of 512 bytes
([RESEARCH.md](RESEARCH.md#power-faults)), so a CRC over 4 KiB would turn a crash into a read error, against point
3 of the contract.

## D15. No reserved area

**Why a choice was needed.** An idea of the user on 2026-11-11: a small area set aside, where a chunk whose write
back failed is put, with a table redirecting it, as `dm-bbr` once did. It needed a superblock, so it waited for
the format.

**Chosen.** Rejected on 2026-11-15. Data rebuilt by ECC is written in place.

**Why.** By the time a write error reaches the host the spare of the drive is gone, and on an SSD an LBA says
nothing about the place on flash, so moving the chunk elsewhere buys little. The reasoning is kept in
[RESEARCH.md](RESEARCH.md#a-failed-write-back-a-reserved-area).

## D16. A superblock written by a utility in userspace

**Why a choice was needed.** The seed, the bitmap and the layout needed a place on the device, and a fresh device
had to be zeroed by hand.

**Options.** The constructor formats a device; or a utility in userspace, as `integritysetup format`. One copy of
the superblock, or two.

**Chosen**, on 2026-11-15: `dcorrsetup`, in C without libraries, formats; the constructor refuses a device
without a valid superblock and never writes one. All layout parameters live in the superblock, and version 1
accepts only the current values, so the I/O path keeps its constants. The layout is computed by one header,
`dcorr-format.h`, shared by the driver and the utility; the tests keep a copy of their own as the independent
check. At run time the utility talks to the driver through `dmsetup message`, `status` and events, as targets
have no sysfs of their own. The size of the lower device must be the formatted one, and the table length the
capacity. The two copies, at the start and in the middle, were superseded by D17 the same day.

**Why.** Formatting in userspace keeps the constructor simple, and a format open to change needs no variables on
the I/O path now.

## D17. Groups

**Why a choice was needed.** Two copies of the superblock, at the start and in the middle, survive one lost range
but not growing the device, and the parity of the correction stage needed a place decided before data is written.

**Options.** Two copies (D16); a header per group of a fixed size; a header sized to its contents; parity rotated
over the stripes or in fixed columns; short regions or only whole ones.

**Chosen**, on 2026-11-15, an idea of the user: the device is a sequence of groups of one size, a power of two
from 16 MiB to 4 GiB, 1 GiB by default; each has a fixed header of 1 MiB with a full copy of the superblock
naming its group, and as many whole regions as fit. The bitmap of a group leads in its header and trails in the
next. P+Q parity over 30 + 2 in fixed columns at the end of each group, without rotation, the space reserved now.
The constructor takes the superblock from groups 0 and 1, and probes the start of group 1 for every size when
group 0 is damaged.

**Why.** A superblock in every group survives any lost range, and growing adds groups of the same size, as
`xfs_growfs` does. The fixed header, chosen by the user, keeps the groups aligned to 1 MiB and leaves room for
later versions; whole regions, also the user's choice, keep the mapping simple, the rest of a group left for the
optimization stage. Parity in columns lies far from its data: a damaged range shorter than a column takes at most
one member of a stripe, two across a column boundary, which two parity members cover, and data stays contiguous in
the first 30/32 of a group. Reserving the space now means ECC will not change the layout.

## D18. A bitmap of written chunks

**Why a choice was needed.** A fresh device holds garbage, so either it is zeroed, or the driver knows which
chunks were never written; discard needs the same state, and a range that reads back as zeros must not pass as a
chunk never written.

**Options.** Zero the device at format; a "never written" mark in the metadata, lost together with it; a bitmap
apart from the data it describes.

**Chosen**, on 2026-11-15, the bitmap the choice of the user: one bit per chunk, in blocks of 4 KiB with a header
(generation, CRC from the salt, group, index, role), in the headers of the groups and whole in RAM. A bit reaches
the device only after the data is durable: the sync writes the first copy of the changed blocks after the flush
of the data, flushes, completes the flushes from above, then writes the other copy with the trailing metadata.
Details agreed the same day:

- the first write back of a chunk with its bit clear writes it whole, zeros around what was written, without a
  settle, and sets the bit in RAM once it succeeds;
- a block valid in one copy is repaired by the next flush; a block invalid in both makes its range read only,
  its chunks read as written so that the CRC decides, never silent zeros, and writes there fail;
- the header of every group is read on the first resume, one request each, the simple way; not in the
  constructor, as on a reload the constructor of the new table runs while the old one still writes, found by
  `test_table_reload_under_load`;
- the CRC of a block does not take its place: group, index and role under a CRC from the salt are enough;
- the first copies are written without FUA and flushed once: libata turns FUA off by default, and an emulated FUA
  costs a flush per block.

**Why.** A bit on the device then means durable data, so a fresh device needs no zeroing, and a crash leaves a
first write as zeros or new data. Lying apart from the data, the bitmap still says a chunk held data when its
range is lost with its metadata. It costs 32 MiB per TiB on the device and in RAM.

## D19. The seed: salt, logical sector, data

**Why a choice was needed.** With a zero seed the CRC of zeros is zero, so a zeroed chunk with zeroed metadata
passed, and so did a chunk copied with its metadata, a misdirected write of equal data, or a table off by a whole
number of regions.

**Options.** The place as the chunk or as each sector; a salt or not; a new version of the format or not.

**Chosen.** On 2026-11-15: a nonzero seed with the logical sector and a random salt per device, kept in the
superblock. On 2026-11-16: as in `dm-integrity`, the CRC runs over the salt, the logical sector as `le64`, then
the data; the CRC of the salt is computed once per table; the logical number of each sector, not of its chunk;
the format stays version 1, as no device is in use; parity slots, which have no logical sector, get their CRC in
the correction stage.

**Why.** A sector has no header for its place, unlike a block of the bitmap, so the place goes into the seed, and
per sector catches sectors swapped inside a chunk with their CRCs. As a CRC is linear, equal data in two places of
one device gives different CRCs for certain, not by chance. The salt catches data from another device. The cost,
a CRC over 8 bytes more per sector, is measured in the baseline stage.

## D20. Discard through the bitmap

**Why a choice was needed.** The device refused discard. A discard should make its chunks read as zeros, cost
nothing below, and keep the guarantees of the bitmap.

**Options.** For the trap below: a sync per batch of discards; a second bitmap of the bits on the device; a
generation of clears. For write zeroes: leave it out, add `iterate_devices` now, or an `iterate_devices` that
names no device.

**Chosen**, on 2026-11-16: discard in whole chunks, not passed down, with no limit of its own on the length; the
worker of the cache drops the entries of the chunks and clears their bits, not `dm_map`; a generation of clears,
the choice of the user; no write zeroes until `iterate_devices`, in the stage of device mapper integration.

**Why.**

- Device mapper does not split a discard at `max_io_len`, checked in the source of 7.2.15; the block layer cuts an
  unaligned head into a bio of its own.
- A sync writes a block of the bitmap from its page in RAM after computing its CRC, so a bit cleared meanwhile
  would leave a copy whose CRC does not match: only the worker, which runs the syncs, may clear bits.
- The trap: the first write back of a chunk skips the settle, right only while its bit is clear on the device
  too; after a discard the bit is clear in RAM and still set on the device until the next sync. So such a write
  back syncs first. The generation costs no memory, and only first writes between a discard and the next flush
  pay; if that sync fails, the chunk is settled as one written before.
- Device mapper offers write zeroes only through `iterate_devices` with every device below capable; there is no
  flag for a target that emulates it. Until then `blkdev_issue_zeroout` writes zero pages, correct and slower.
- A discard and a write racing on one chunk may land in either order: concurrent I/O, the business of the layer
  above.

## D21. Device mapper integration and docs before runs

**Chosen**, on 2026-11-16, the choice of the user after the format stage closed: the interface of the driver
(status, table, queue limits, write zeroes) and its documentation come before runs, which stay before the
baseline (D12).

**Why.** The documentation describes the driver as it is now, and the interface is what a user of it sees first.

## D22. Errors as a signal: counters, one event, the name of the device

**Why a choice was needed.** By the threat model (D13) the first error is a strong sign that a drive is failing,
and the purpose of the driver is to keep the data readable long enough to move it. Until stage 5 an error was only
a line in the kernel log, with no rate limit for a mismatch, the physical sector and no name of the device.

**Options.** For the shape of the status: positional counters appended, or `key:value` pairs. For the event: at
every error, at the first one, or at the first of each kind. For the name in the log: major:minor, as
`dm_table_device_name` gives it and `dm-verity` prints it, or the name of `dmsetup`. For a mismatch: count reads
or sectors.

**Chosen**, on 2026-11-16, the choices of the user: five counters appended to the positional status
(`read_errors`, `crc_mismatches` in sectors, `write_errors`, `metadata_read_errors` in sectors, `flush_errors`),
more later if needed; a device mapper event at the first error since the table was created, of any kind; the
name the user knows, from `dmsetup`, in every message of a device, with the logical sector; every message that
I/O can repeat rate limited.

**Why.**

- Positional counters are what other targets give, and `key:value` pairs are a convention of table arguments,
  not needed now; a new counter goes at the end, so readers by position keep working.
- One event is enough to wake `dmsetup wait` or `dmeventd`, which then read the counters; an event per error
  would keep them busy while a failing drive floods the driver with errors. A new table starts over.
- `check_crc` checks every sector of a read, so `crc_mismatches` counts damaged sectors: the size of the damage,
  not how often it was read.
- `dm_copy_name_and_uuid` takes only a mutex of device mapper that guards the name, never held while waiting for
  I/O, so it is safe from the workers; the completion of a bio cannot take it, so a failed read is logged by
  `complete_work` and a failed write back by the cache. `dm_table_event` takes a mutex too, so the event is
  raised from a work item.

## D23. The limits of the lower device, and write zeroes

**Why a choice was needed.** Without `iterate_devices` the device took none of the limits of the lower device,
and device mapper offers write zeroes only through it. A lower device with logical blocks of 4 KiB was taken,
although the metadata is written in sectors of 512 bytes.

**Options.** For write zeroes: offered only where the lower device has it, or always, with an `iterate_devices`
that names no device. For a lower device with 4 KiB logical blocks: refuse it, or write the metadata in blocks of
4 KiB, a question of the format (see the open questions of [ARCHITECTURE.md](ARCHITECTURE.md#open-questions)).

**Chosen**, on 2026-11-16, the choices of the user: `iterate_devices` over the part of the lower device the layout
uses; a lower device whose logical block is not 512 bytes refused by the constructor; the physical block and the
minimal I/O a chunk; write zeroes only where the lower device has it, the whole chunks cleared as by a discard and
the partial ends written as zeros through the cache, `REQ_NOUNMAP` ignored; the target version stays 1.0.0.

**Why.**

- Without a device below, `iterate_devices` would hide the device from what device mapper checks, and write zeroes
  would be offered over a device where zeroing is slow; with it, the area of the lower device is checked, and the
  limits that do not depend on the layout, as the largest request, are taken.
- What the target does itself overrides what is stacked: discard and write zeroes are not passed down, so the
  limits of the lower device for them do not matter; the optimal I/O and the alignment of the lower device say
  nothing of the logical sectors on top, as groups and regions move the data; every request completes from a
  workqueue, so polling gives nothing; a write is copied into the cache, so stable pages are not needed.
- A zoned lower device is refused by device mapper itself, as the target does not declare zones.
- A FUA write zeroes is carried out as a FUA write, through the flushes of the worker; nothing in userspace sends
  one, so it is not tested.


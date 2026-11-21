# Research

What the decisions in [DECISIONS.md](DECISIONS.md) are based on: how others solved the same problems, what it
costs, and what follows for this driver. The decisions live in `DECISIONS.md`, the driver as it is in
[ARCHITECTURE.md](ARCHITECTURE.md); this file holds the reading.

Unless said otherwise, the findings come from reading the sources of Linux v7.2. Nothing here was run or
measured, so there are no performance numbers of our own.

## Caches and integrity in device mapper

Read on 2026-11-11, to answer the open points of the cache, decided as [D4](DECISIONS.md#d4-a-write-back-cache-of-our-own-in-ram).

Sources: [`dm-writecache.c`][wc] and [its documentation][wc-doc], [`dm-integrity.c`][int] and
[its documentation][int-doc], [`dm-bufio.c`][buf] and [`dm-bufio.h`][buf-h], [`dm-ebs-target.c`][ebs].

### Comparison

| Question | `dm-writecache` | `dm-integrity` | `dm-bufio` |
| --- | --- | --- | --- |
| Unit | A block up to a page, 4 KiB recommended | A block of 512 B to 4 KiB | Any multiple of 512 B, [9 sectors too][buf-size] |
| Size | The whole cache device, entries allocated up front | A journal on disk, [up to 64 MiB by default][int-jsize], and its copy in RAM | One limit for all clients, [2% of RAM by default][buf-limit] |
| When it writes | [Starts at 50% used, stops at 45%][wc-wm]; optionally by age | Journal commit [on a flush, a timer of 10 s or when filling up][int-commit]; [copy to the final place][int-writer] when 50% full | On an explicit call, [when dirty buffers outnumber clean ones three to one][buf-wm], [under memory pressure][buf-shrink] |
| Aggregation | [Neighbours, up to 256 blocks in a request][wc-run] | [Neighbours inside one journal section][int-merge] | [One bio per buffer][buf-bio], merging left to the block layer |
| Structure | Its own: a tree by sector, an LRU, one mutex | [A journal of its own for data][int-copy], `dm-bufio` [for tags][int-tag] | |
| Reads | [Clean data is not kept][wc-read]; only blocks not yet written back are served | Clean data is not kept; [recent blocks come from the journal in RAM][int-jread] | Everything is kept; [a block is read whole and synchronously][buf-read] |
| Failed write | [One error for the device][wc-err]: writes and flushes fail, reads go on, [the data stays in the cache][wc-keep], no retry | [One error for the device][int-err]: [everything fails, reads too][int-fail] | No retry: [the buffer is marked clean before the write][buf-clean], [freed on release][buf-release]; [one error per client, reported once][buf-async] |
| Crash | [Write to a new place][wc-copy], [commit through a counter in the superblock][wc-commit], [what is not committed is dropped][wc-resume] | Journal with a commit id in each sector, a bitmap, or nothing | Not its task |

### Trade-offs

- **`dm-writecache`** is safe thanks to its persistent medium: [a flush stops at the cache][wc-flush] and never
  reaches the origin. A cache in RAM does not have this. Its pmem mode is the closest to us in shape: it copies
  the data of the bio, completes it at once, and [waits for a free entry in `map`][wc-wait].
- **`dm-integrity` with a journal** is atomic, but its documentation says write throughput drops by half.
- **`dm-integrity` with a bitmap** writes once. [A bit is set and written with FUA before the first write to a
  region][int-bit], one bit covers 16 MiB by default, and [clearing the bits every 10 s stops all I/O][int-bitflush].
  After a crash the tags of dirty regions are recalculated, so damage in them is not detected, and
  [reads there are not checked until then][int-skip].
- **`dm-integrity` and errors.** [A read error during that recalculation fails the whole device][int-recalc]. A
  failed read of a tag buffer fails the bios it covers: 8 MiB of data with the default buffer and 4-byte tags.
  A CRC mismatch [fails only its bio][int-recheck], which is what we want.
- **`dm-bufio`** is made for metadata. [`dm_bufio_read` and `dm_bufio_new` refuse to run from `map`][buf-map], and
  [a thread may hold only one buffer][buf-hold] outside the reserved ones. `dm-ebs` passes data through it, but
  [writes the dirty buffers before completing each batch][ebs-write], so it defers nothing.

### What follows for this driver

- **Structure.** A structure of our own in the shape of the pmem mode of `dm-writecache`, without `dm-bufio`, so
  that write back stays under our control. See [Cache](ARCHITECTURE.md#cache).
- **Flush.** Unlike `dm-writecache`, a flush has to reach the lower device, so `fsync` waits for the write back of
  everything dirty before it.
- **Reads.** Only dirty data is served from the cache for now, as in both analogues.
- **Waiting.** The rule "all waiting happens in `dcorr_map`" of [I/O path](ARCHITECTURE.md#io-path) needs one
  limit: `dcorr_map` may wait for a free page, but never for a lower bio of its own, which
  [stays on `current->bio_list` until `map` returns][int-sleep]. Both modules give flushes to a worker of their own.

## A write cut short by a crash: two CRCs

Discussed on 2026-11-11, for point 3 of the [contract](ARCHITECTURE.md#contract-with-the-layer-above) and the
options of [D5](DECISIONS.md#d5-a-write-cut-short-by-a-crash-two-crcs). The metadata holds the old and the new CRC of each sector and is made
durable before the data; a read accepts either. A drive is atomic per sector, so after a crash each sector
holds its old or its new contents, and one of the two matches.

Why it fits: there is no blind spot as with a bitmap, no double write as with a journal, and it fits the format,
as 8 pairs take 128 of the 512 bytes of a metadata sector.

What it requires, all still open:

1. **Order against one request.** Metadata has to be durable before the data: a FUA write of the metadata, wait,
   then the data. With 8 data sectors and 1 of metadata, the first step is a row of scattered 512-byte writes, so
   a run can no longer be one request, as [On-disk format](ARCHITECTURE.md#on-disk-format) assumed. A larger
   metadata block per run would give two sequential requests. This raises the weight of the proportions question.
2. **The old CRCs have to be known.** A write back of a chunk needs its old metadata: a read, unless metadata is
   kept in RAM.
3. **Which CRC is current on the next overwrite.** After a completed write the new one is. After a crash a chunk
   that was in flight is ambiguous, and writing `{new, newer}` over data that is still old would break on a second
   crash. Such chunks need one read of the data to settle it. They could be told apart by an epoch in the
   metadata, raised at each unclean start.
4. **Lost writes.** The old CRC stays valid until the next overwrite, so a write the drive dropped passes as the
   old contents. Lost writes are an open threat in the [threat model](ARCHITECTURE.md#threat-model). Rewriting the
   metadata with a single CRC once the data is durable closes it, at the cost of one more write.
5. **The CRC unit is limited by what the drive writes atomically.** A CRC over 4 KiB does not work on a drive
   atomic per 512 bytes, as a torn block matches neither CRC.
6. **ECC.** It needs the old and the new redundancy, or a scheme of its own. Due before correction.

Revised on 2026-11-14, an idea of the user: the two CRCs are not a pair in one entry but the two copies of the
metadata, the leading one in the region and the trailing one in the next. The leading copy gets the new CRC
before the data, the trailing copy keeps the old one until a flush makes the new data durable, and is written
then. The entry stays 64 bytes. In the steady state both copies are equal, so the copy still guards against a
lost metadata sector, point 3 needs no record of which CRC is current, and point 4 is closed once the trailing
copy is written. A crash in the window together with a lost sector of the other copy is not covered.

A trap found on the way, which holds for a pair in one entry too: a completed write is not durable until a
flush. A chunk written back twice between two flushes may hold any of three versions after a crash, with two
slots, so the second write back needs a flush first.

Point 3 in the end: a chunk whose copies differ is read before its next write back, which is enough without an
epoch, as in the steady state they are equal. The read is valid only for data that is durable, so it comes
after the flush that a chunk written back since the last one waits for anyway. Point 1: the leading copy is a
FUA write of one sector per write back, and the data waits for it, two requests in a row; runs will make the
first a range of the metadata area.

## A failed write back: a reserved area

**Rejected on 2026-11-15**, agreed with the user, after the [reading on drive failures](#drive-failures): by the
time a write error reaches the host the spare of the drive is gone, and an LBA says nothing about the place on
flash. Kept for the reasoning.

Discussed on 2026-11-11, an idea of the user, not decided. A small area is set aside in advance. A write back that
failed goes to a slot there, and a table redirects later reads and writes of that chunk. The device keeps working
when partly damaged, with warnings, and past some point only writes that matter for the filesystem are accepted.

It is feasible, and has been done:

- **Drives** relocate sectors in firmware, so an error that reaches the host on a write suggests that this
  is exhausted or that the region is in a bad way.
- **`dm-bbr`**, from the EVMS project, did exactly this: [the patch][bbr-patch] kept a table of bad and replacement
  sectors with a signature and a CRC on disk, looked up through a binary tree, and was meant for when the
  drive's own relocation is exhausted. It was [posted to dm-devel in 2007][bbr-list]; there is no `dm-bbr.c` or
  mention of it in `drivers/md` of v7.2. We know it from search results and the patch header, not from a full reading.
- **md** has a [bad block log][md-doc], which records but does not relocate. Its [`narrow_write_error`][raid1-narrow]
  retries a failed write block by block to find what is really bad, and we need the same.

What it takes:

- **A superblock**, for where the area is. The capacity shrinks, and the layout in the tests changes.
- **Narrowing.** A failed bio over a run says nothing about which chunk is bad, so each chunk is retried alone.
- **A slot holds a whole chunk with its metadata**, so it is self-describing. If the position goes into the CRC, it
  has to be the logical one.
- **Partial chunks.** The rest of the chunk has to be read from the old place, and that may fail, so a slot needs a
  mark for bad sectors. The metadata sector has room.
- **Commit order.** The slot is made durable, then the table entry with FUA, and only then is the RAM freed.
- **The table lives on the failing drive**, so two copies with a generation and a CRC.
- **In RAM the table is allocated up front** and searched before mapping. For example, 64 MiB of slots of 4.5 KiB
  is about 14500 entries, around 230 KiB. Nothing allocates on the I/O path.
- **Failures of the area.** A failed slot is skipped. Several in a row mean the device itself is gone, and then
  relocation should stop instead of burning all slots.
- **Correction gets it for free:** data rebuilt by ECC has somewhere to go, which is an open point of
  [Errors](ARCHITECTURE.md#errors).

Stages of degradation, as a proposal: healthy; degraded, once a slot is used (counters in `dmsetup status`,
rate-limited warnings, a device mapper event); critical, when few slots are left (only priority writes accepted);
read only, when none are left.

What counts as a priority write:

- **Refusal has to happen in `dcorr_map`.** A plain write is acknowledged before its write back, so by the time the
  write back fails it can no longer be refused.
- **FUA alone is not enough.** [Journal blocks of `jbd2`][jbd2-log] carry [`REQ_META | REQ_SYNC | REQ_IDLE`][jbd2-flags]
  and no FUA; only [the commit block][jbd2-commit] has `REQ_PREFLUSH | REQ_FUA`. Refusing them
  [aborts the journal][jbd2-abort] at the next commit, and the filesystem stops writing. A better rule is to accept
  flushes, FUA and `REQ_META`, and refuse plain data.
- **Only a failed write consumes a slot**, so writes to healthy places need not be refused until the slots run out.
- **Not checked:** what refused plain data does to ext4 in ordered mode. This needs a test in the VM.

## Drive failures

Read on 2026-11-15, to settle the open threats of the [threat model](ARCHITECTURE.md#threat-model) and the
reserved area. The user collected the material; the numbers below were checked against the papers themselves,
with the section given, except where said otherwise.

Sources: [Pinheiro et al., FAST'07][pinheiro] (Google, over 100 000 consumer HDDs), [Backblaze][bb-smart]
(SMART of 67 814 HDDs), [Schroeder et al., FAST'16][schroeder] (Google, SSDs of ten models over 6 years),
[Maneas et al., FAST'20][maneas] (NetApp, 1.4 million enterprise SSDs), [Bairavasundaram et al., FAST'08][bairava]
(NetApp, silent corruption on 1.53 million disks over 41 months), [Krioukov et al., FAST'08][krioukov] (what
each protection technique detects), [Zheng et al., FAST'13][zheng] (15 SSDs under power faults).

### Hard disks

- **The first error is a strong signal.** After the first scan error a drive is 39 times more likely to fail
  within 60 days than one without, 14 times after the first reallocation, 21 after the first offline
  reallocation, 16 after the first probational (pending) sector (Pinheiro, 3.5). At Backblaze at least one of
  SMART 5, 187, 188, 197 and 198 is above zero on 76.7% of failed drives and 4.2% of working ones.
- **Many drives die without a warning.** Over 56% of failed drives had none of the four strong signals above,
  and over 36% no SMART signal at all (Pinheiro, 3.5.6). Temperature and utilization correlate weakly with
  failures; only very high temperatures show an effect (Pinheiro, 3.4).
- **Latent sector errors** hit about 19% of nearline and 2% of enterprise disks within 2 years
  (Bairavasundaram et al., SIGMETRICS'07, as quoted by Krioukov, 2.2; not read ourselves).

### SSDs

- **Uncorrectable errors are common:** 20 to 63% of drives have at least one within four years, on 2 to 6 of
  1000 drive days. SSDs are replaced less often than HDDs, but have significantly more uncorrectable errors
  (Schroeder, summary and 8).
- **Errors cluster.** In the month after an uncorrectable error the chance of another is nearly 30%, against 2%
  in a random month; prior errors raise it by more than an order of magnitude (Schroeder, 5.6).
- **Bad blocks and chips.** 30 to 80% of drives develop bad blocks within four years, a median of 2 to 4. After
  the second, the median total for MLC jumps to about 200, likely a failing chip. 2 to 7% develop a bad chip. A
  block is declared bad after a final read error, a write error or an erase error, and remapped (Schroeder, 6).
- **Age matters apart from wear.** Errors grow with P/E cycles, but linearly rather than exponentially, and the
  age of a drive affects reliability independently of use (Schroeder, summary).
- **No rise at the end of life, a long infant mortality.** At NetApp failure rates rise for 12 to 15 months and
  are 2 to 3 times higher than later; there is no rise at the end of life, but few drives get there: 99% of
  systems use at most 15% of the rated life of their drives (Maneas, 5.1 and 8).
- **Not checked:** that drives at the end of their endurance go read only or disappear, as in the material of the
  user, from the endurance experiment of The Tech Report (2015). The original article is gone, and secondary
  reports do not agree on the details.

### Silent corruption

- **NetApp** saw about 400 000 checksum mismatches over 41 months, on 0.86% of nearline and 0.065% of
  enterprise disks. On a disk with several of them, the blocks are often consecutive (Bairavasundaram, 4).
- **Lost and misdirected writes** showed as identity discrepancies on 365 disks, more than an order of magnitude
  fewer than checksum mismatches (Bairavasundaram, 5.1); Krioukov gives 0.04% of nearline and 0.007% of
  enterprise disks within 17 months (2.2). NetApp knows of disk firmware that reported writes never written.
- **What detects what** (Krioukov, 4): a checksum kept with its block detects neither a lost write (the old data
  and the old checksum agree) nor a misdirected one. An identity in the block, physical (disk and sector) or
  logical (inode and offset), detects misdirected writes; a checksum kept in a parent block detects lost ones.
  **Parity pollution:** parity recomputed from data that was not verified spreads one error over the stripe.

### Power faults

Zheng et al. cut the power of 15 SSDs of five vendors, and 13 of them failed (5):

- **Bit corruption** on 3 devices.
- **Shorn writes** on 3, two of them sold as enterprise: a 4 KiB block partly new and partly old, always in
  multiples of 512 bytes; 72 in 441 iterations.
- **Unserializable writes** on 8 SSDs and on 1 of the 2 HDDs: completed writes lost or reordered, so the drive
  likely ignores flushes.
- **Metadata corruption** on 1: after 8 faults 30.5% of the device could not be read, and access there hung.
- **A dead device**, 1, after 136 faults.
- **No misdirected writes**, and no range that reads back as zeros.

### What the drive does by itself

- **ECC per sector or page.** An error that reaches the host means its ECC gave up, and the host gets an error,
  not damaged bits to correct.
- **Relocation.** An HDD remaps a pending sector when it is written; an SSD writes to a new page anyway and
  remaps bad blocks itself. A write error that reaches the host means the spare is exhausted, or the region is in
  a bad way.

### Other systems

- **btrfs** checks all data, with crc32c by default, and [keeps metadata in two copies on a single device by
  default since btrfs-progs 5.15][btrfs-mkfs]. Data can be kept in two copies too, at twice the space; there is
  no parity on one device.
- **ZFS** has `copies=2` per dataset, out of the tree of the kernel.
- **bcachefs** has erasure coding only across devices, and was [removed from the mainline in 6.18][bcachefs].
- **`dm-integrity`** [mixes the logical sector into every checksum][int-seed], and with `fix_hmac` also [a
  random salt from its superblock][int-salt]. It has no correction.

So redundancy on one device cheaper than a full copy, below any filesystem, is not offered by any of them;
LVM RAID can be assembled to give it, see [Redundancy on a single drive](#redundancy-on-a-single-drive).

### What follows for this driver

1. **ECC between blocks, not inside a sector.** It corrects erasures: chunks that failed to read or did not
   match their CRC, whose place is known. Mismatches come in consecutive blocks and SSD errors cluster, so a
   stripe must not be made of neighbours. On an HDD its redundancy lies far from the data; on an SSD distance in
   LBA means nothing, and only more redundancy per stripe helps. Parity is updated only from verified data. For
   the correction stage.
2. **The CRC stays per 512-byte sector.** Shorn writes come in units of 512 bytes, so a CRC over 4 KiB would
   turn a crash into a read error, against point 3 of the contract.
3. **No reserved area.** Data rebuilt by ECC is written in place: an HDD remaps the sector, an SSD writes to a
   new page.
4. **Errors as a signal to move the data off.** The first error is a strong predictor for both kinds of drive,
   so it has to reach the user: counters in `dmsetup status` and a device mapper event, not only the kernel log.
   Half the drives die without a warning, so integrity cannot wait for one.
5. **Reads go on when writes fail**, as for a drive gone read only. This holds already.
6. **A nonzero seed with the logical sector and a salt per device.** It costs nothing. A zero chunk with zero
   metadata no longer passes. The position catches a misdirected write whose data equals that of its victim, a
   table offset wrong by a whole number of regions (every check passes today), and a chunk copied with its
   metadata. The salt catches data from another device of ours.
7. **Lost writes are partly detected by the layout.** Data and metadata are separate writes, and once the flush
   after a write back has passed both copies hold the new CRC, so data that was not written no longer matches.
   Not covered: the window before that flush, and a write lost together with both copies of its metadata, as by a
   drive that ignores flushes. A generation kept far away, as a checksum in a parent, would close it.
8. **Ranges that read back as zeros** have no field data behind them, only mechanisms: a discard by mistake, a
   discarded range read back, the mapping of an FTL lost. They are handled because "never written" is needed
   anyway, for fresh devices and for discard. Decided by the user: a bitmap of written chunks in the superblock
   and in RAM, apart from the data it describes.
9. **An SSD that deduplicates** could keep the two equal copies of the metadata once. Rare today; mixing the
   number of the copy into its contents would answer it.

## Redundancy on a single drive

Read on 2026-11-17, to place the driver among what exists: what other systems give on one drive, and at what
cost. Unlike the sections above, this one comes from documentation, not from sources.

Sources: the documentation of [`dm-integrity`][int-doc], [`dm-verity`][verity-doc] and [data integrity in the
block layer][bi-doc] in Linux v7.2, [`lvmraid(7)`][lvmraid], [`zfsprops(7)`][zfsprops] and [the checksums of
OpenZFS][zfs-sum], [`mkfs.btrfs`][btrfs-mkfs], [ReFS integrity streams][refs], [par2cmdline][par2].

### Comparison

| System | Level | Detects | Corrects on one drive | Cost |
| --- | --- | --- | --- | --- |
| `dm-integrity`, standalone | Block device | A tag per sector, [silent corruption on the disk or in the I/O path][int-standalone] | No | The tags; [the journal writes everything twice][int-modes] |
| LVM RAID with `--raidintegrity` over partitions of one drive | Block device | `dm-integrity` under each image | Yes: [dm-raid reads another image and writes the good data back][lvmraid-int] | A full copy for raid1, half again for raid5 over three partitions; [the journal of integrity by default][lvmraid-mode]; on an HDD a stripe lies in partitions far apart |
| `dm-verity` with FEC | Block device, [read only][verity-ro] | A tree of hashes | Yes: [Reed-Solomon interleaved over the whole device, the hashes give the places of the erasures][verity-fec] | [About 0.8% with `fec_roots=2`][verity-roots] |
| T10 PI (DIF, DIX) | Drive and HBA | [8 bytes per sector with a 16-bit CRC][bi-dif] | No | Drives formatted [with 520 or 4104 byte sectors][bi-dif] |
| ZFS, `copies=2` or 3 | Filesystem | [A checksum per block, in its block pointer][zfs-sum] | Yes, [from another copy][zfs-sum] | [Space ×2 or ×3; the copies go to different disks when possible][zfsprops] |
| btrfs, data in `DUP` | Filesystem | crc32c by default, see [Other systems](#other-systems) | Yes, from the other copy | Space ×2; [an SSD may keep the two copies once, or in one unit that dies with both][btrfs-mkfs] |
| ReFS, integrity streams | Filesystem | A checksum of the data of a file | [Only on a mirror or parity space; on a bare drive an error][refs] | [Every write is allocated anew, so files fragment][refs] |
| par2 | Files, by hand | Its own checksums | Yes: [Reed-Solomon recovery files of the size chosen][par2] | The size chosen; made and used by hand, over files that no longer change |
| `dm-dcorr` | Block device | CRC64 per 512 B sector, two copies, with the place and the salt | Not yet: ECC between chunks, in the correction stage | About 3% for the metadata and 6.25% reserved for the parity |

### What follows

- **Correction on one writable drive, below any filesystem, at less than a full copy** can be assembled today
  only by hand: LVM raid5 with integrity over three partitions of one drive. It is not made for it: three
  members of a stripe far apart on an HDD, writes multiplied by RAID and by the journal, and detection only after
  the tags of the whole device are [initialized][lvmraid-init]. Filesystems give it at a full copy, and only for
  themselves.
- **`dm-verity` is the closest model for the correction stage**: it corrects with Reed-Solomon over blocks
  interleaved across the device, and uses its hashes for the places of the erasures, as point 1 of
  [the section above](#what-follows-for-this-driver-1) plans with the CRCs. It is read only, so it never updates
  its parity, which is the hard part for us.
- **Copies on one drive share its fate.** btrfs warns that an SSD may deduplicate the copies or keep them in one
  unit, as point 9 of [the section above](#what-follows-for-this-driver-1) says for our metadata; and nothing on
  one drive survives the loss of the whole drive.
- **Crash consistency without a journal** sets the driver apart from `dm-integrity`, which [either journals
  every write or, with a bitmap, loses detection in the regions dirty at a crash][int-bitmap]: two copies of the
  CRCs and the settle cost one FUA metadata write per write back, and nothing is left unchecked, see
  [A write cut short by a crash](#a-write-cut-short-by-a-crash-two-crcs).

[wc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2
[wc-doc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/writecache.rst?h=v7.2
[wc-wm]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n22
[wc-run]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n2029
[wc-read]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1349
[wc-err]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1443
[wc-keep]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1729
[wc-copy]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1381
[wc-commit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n793
[wc-resume]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1066
[wc-flush]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1502
[wc-wait]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-writecache.c?h=v7.2#n1476
[int]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2
[int-doc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/dm-integrity.rst?h=v7.2
[int-jsize]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n4850
[int-commit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2820
[int-writer]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n3066
[int-merge]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2960
[int-copy]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2208
[int-tag]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n1412
[int-jread]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2158
[int-err]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n380
[int-fail]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2299
[int-bit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n3445
[int-bitflush]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n3463
[int-skip]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2480
[int-recalc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n3218
[int-recheck]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n1795
[int-sleep]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n2375
[buf]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2
[buf-h]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/dm-bufio.h?h=v7.2
[buf-size]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n2509
[buf-limit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n38
[buf-wm]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n1737
[buf-shrink]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n2419
[buf-bio]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n1337
[buf-read]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n1871
[buf-clean]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n1460
[buf-release]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n2065
[buf-async]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n2194
[buf-map]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-bufio.c?h=v7.2#n1956
[buf-hold]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/dm-bufio.h?h=v7.2#n51
[ebs]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-ebs-target.c?h=v7.2
[ebs-write]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-ebs-target.c?h=v7.2#n227
[bbr-patch]: https://evms.sourceforge.net/patches/2.5.0/kernel/dm-bbr.patch
[bbr-list]: https://listman.redhat.com/archives/dm-devel/2007-February/004562.html
[md-doc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/md.rst?h=v7.2#n625
[raid1-narrow]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/raid1.c?h=v7.2#n2517
[jbd2-log]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/jbd2/commit.c?h=v7.2#n752
[jbd2-flags]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/jbd2.h?h=v7.2#n1399
[jbd2-commit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/jbd2/commit.c?h=v7.2#n153
[jbd2-abort]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/jbd2/commit.c?h=v7.2#n892
[pinheiro]: https://www.usenix.org/legacy/events/fast07/tech/full_papers/pinheiro/pinheiro.pdf
[bb-smart]: https://www.backblaze.com/blog/what-smart-stats-indicate-hard-drive-failures/
[schroeder]: https://www.usenix.org/conference/fast16/technical-sessions/presentation/schroeder
[maneas]: https://www.usenix.org/conference/fast20/presentation/maneas
[bairava]: https://www.usenix.org/legacy/event/fast08/tech/full_papers/bairavasundaram/bairavasundaram.pdf
[krioukov]: https://www.usenix.org/legacy/event/fast08/tech/full_papers/krioukov/krioukov.pdf
[zheng]: https://www.usenix.org/conference/fast13/technical-sessions/presentation/zheng
[btrfs-mkfs]: https://btrfs.readthedocs.io/en/stable/mkfs.btrfs.html
[bcachefs]: https://lwn.net/Articles/1040120/
[int-seed]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n1668
[int-salt]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/md/dm-integrity.c?h=v7.2#n4170
[int-standalone]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/dm-integrity.rst?h=v7.2#n23
[int-bitmap]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/dm-integrity.rst?h=v7.2#n28
[int-modes]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/dm-integrity.rst?h=v7.2#n75
[verity-doc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/verity.rst?h=v7.2
[verity-ro]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/verity.rst?h=v7.2#n7
[verity-roots]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/verity.rst?h=v7.2#n119
[verity-fec]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/device-mapper/verity.rst?h=v7.2#n223
[bi-doc]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/block/data-integrity.rst?h=v7.2
[bi-dif]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/block/data-integrity.rst?h=v7.2#n45
[lvmraid]: https://man7.org/linux/man-pages/man7/lvmraid.7.html
[lvmraid-int]: https://man7.org/linux/man-pages/man7/lvmraid.7.html#DATA_INTEGRITY
[lvmraid-mode]: https://man7.org/linux/man-pages/man7/lvmraid.7.html#DATA_INTEGRITY
[lvmraid-init]: https://man7.org/linux/man-pages/man7/lvmraid.7.html#DATA_INTEGRITY
[zfsprops]: https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html
[zfs-sum]: https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Data%20Storage/Checksums.html
[refs]: https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams
[par2]: https://github.com/Parchive/par2cmdline

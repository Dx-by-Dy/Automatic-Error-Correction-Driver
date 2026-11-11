# Research

What the decisions in [ARCHITECTURE.md](ARCHITECTURE.md) are based on: how others solved the same problems, what
it costs, and what follows for this driver. Decisions live in `ARCHITECTURE.md`; this file holds the reasons.

Unless said otherwise, the findings come from reading the sources of Linux v7.2. Nothing here was run or
measured, so there are no performance numbers of our own.

## Caches and integrity in device mapper

Read on 2026-11-11, to answer the open points of [Cache](ARCHITECTURE.md#cache).

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
- **Waiting.** The rule "all waiting happens in `dm_map`" of [I/O path](ARCHITECTURE.md#io-path) needs one
  limit: `dm_map` may wait for a free page, but never for a lower bio of its own, which
  [stays on `current->bio_list` until `map` returns][int-sleep]. Both modules give flushes to a worker of their own.

## A write cut short by a crash: two CRCs

Discussed on 2026-11-11, for point 3 of the [contract](ARCHITECTURE.md#contract-with-the-layer-above) and the
options in [Cache](ARCHITECTURE.md#cache). The metadata holds the old and the new CRC of each sector and is made
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

## A failed write back: a reserved area

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

- **Refusal has to happen in `dm_map`.** A plain write is acknowledged before its write back, so by the time the
  write back fails it can no longer be refused.
- **FUA alone is not enough.** [Journal blocks of `jbd2`][jbd2-log] carry [`REQ_META | REQ_SYNC | REQ_IDLE`][jbd2-flags]
  and no FUA; only [the commit block][jbd2-commit] has `REQ_PREFLUSH | REQ_FUA`. Refusing them
  [aborts the journal][jbd2-abort] at the next commit, and the filesystem stops writing. A better rule is to accept
  flushes, FUA and `REQ_META`, and refuse plain data.
- **Only a failed write consumes a slot**, so writes to healthy places need not be refused until the slots run out.
- **Not checked:** what refused plain data does to ext4 in ordered mode. This needs a test in the VM.

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

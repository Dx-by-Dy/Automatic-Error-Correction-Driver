# dm-dcorr

Linux Device Mapper target providing block-level data integrity verification using CRC64 checksums.

## Overview

dm-dcorr, disk correction, is a Linux kernel module implemented as a Device Mapper target. The driver creates a virtual block device on top of an existing storage device and transparently intercepts read and write requests.

For each data block, the driver calculates a CRC64 checksum and stores it in a dedicated metadata area. During read operations, the checksum is recalculated and compared with the stored value, allowing detection of silent data corruption.

The project serves as a foundation for future implementation of Error Correcting Codes (ECC), enabling not only error detection but also automatic data recovery.

## Features

* Device Mapper target implementation
* Transparent block-level integrity verification
* CRC64 checksum calculation and validation
* Dedicated metadata storage
* Concurrent I/O processing
* Chunk-level synchronization
* Compatibility with standard Linux file systems
* Detection of data corruption caused by media errors or software faults

## Architecture

The threat model, the guarantees to the layer above, the on-disk format and the planned cache are in
[ARCHITECTURE.md](docs/en/ARCHITECTURE.md). This section describes the driver as it is.

The lower device is a sequence of groups of one size, 1 GiB by default, each with a header of 1 MiB written by
`dcorrsetup format`: a copy of the superblock and the bitmaps of written chunks. The virtual device is divided
into chunks of 4 KiB, 8 sectors, and the slots of the chunks on the lower device into regions of 1024, 4 MiB,
as `dm-integrity` does. The metadata of a chunk is an entry of 8 CRC64 checksums, one per sector, 64 bytes; a
metadata sector holds the entries of 8 neighbouring chunks. The metadata of a region is kept in two copies: the
leading one next to its slots, the trailing one in the next region of the group.

### Layout

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

The header of a group holds the superblock, 4 KiB, with the version of the format, the number of the group, a
generation, a UUID, a random salt, the size of the lower device, all parameters of the layout and a CRC64; then
the leading copy of the bitmap of the group and the trailing copy of the one of the group before, 4 KiB blocks
of 32512 bits each, and room for the dirty stripes of the parity. The driver reads the superblocks of groups 0
and 1 when the target is created, takes the valid one with the larger generation, and refuses a device with
neither, or of another size than it was formatted for; with group 0 damaged it looks for group 1 at each size
of a group. The bitmap is written, but not read yet, and the parity columns are reserved, not written. The
layout is computed by `src/dcorr-format.h`, which the driver and `dcorrsetup` share.

The logical chunks of a group take the first 30/32 of its slots in order, so the leading copy of a region and its
data stay one contiguous range, aligned to 128 KiB. About 930 MiB of a group of 1 GiB hold data: the header
0.1%, the metadata 3%, the parity 6.25%.

The leading copy is written with each write back of a chunk, the trailing one after the lower device has
flushed that write back, so once everything is flushed both copies hold the same. A read takes the checksum of
a sector from either copy, so a metadata sector lost in one copy costs nothing; it is lost only when both are.

### Cache

Every write goes through a write back cache of 64 MiB per device, allocated when the target is created: one
entry per chunk of data, with a page, a mask of the sectors written into it, a place in a tree ordered by chunk
and a place in a list ordered by age. Device mapper splits requests at chunk boundaries, so each piece of a
write is copied into the entry of its chunk and completes at once. The code is in `src/cache.c`.

A worker writes the entries back: those older than 1 second, as many as keep at least 55% of the entries
free once more than half are in use, and all of them for a flush, a FUA write or a suspend. Writes to an
entry under write back, and writes that find no free entry, wait in `dm_map`. Reads of the clean sectors of an entry under write back wait there too,
so that a stream of them cannot hold the write back off. An entry whose write back
failed keeps its data and is tried again on the next flush, suspend or write to it. If every entry has failed,
new writes fail.

### Write Path

1. Splitting the request into chunks;
2. Copying each piece into the entry of its chunk in the cache, and completing it;
3. Writing back the entry later, once no read of the chunk is in flight. If the chunk was written back since
   the last flush of the lower device, the worker flushes first: its data could otherwise be any of three
   versions. If the two copies of its metadata differ in the sectors to be written, after a crash or a failed
   write back, the chunk is read, and a sector that matches the leading copy gets that checksum in the trailing
   copy, written with FUA.
4. One lower write per run of its dirty sectors, each of which calculates the checksums, puts them into the
   leading copy of the metadata of the region in RAM, writes the leading metadata sector of the chunk from
   there with FUA, and only then the data.
5. After the next flush of the lower device, writing the trailing copy of the metadata sectors of the chunks
   written back, and flushing again. Until then the trailing copy has the checksums of the old data and the
   leading one those of the new, so after a crash each sector reads its old or its new data.

### Read Path

1. Splitting the request into chunks;
2. Copying the sectors held in the cache, and completing them;
3. For the others: registering the read in the cache, copying both entries of the chunk from the metadata of
   its region in RAM, reading the data, unregistering it, calculating the checksums and accepting a sector that
   matches either entry, completing the request.

### Metadata in RAM

The driver keeps the metadata of the regions it used in RAM: 32 areas, each with both copies of 64 KiB, 4 MiB
per device, which cover 128 MiB of data. The first read or write back that needs a region reads both copies,
one request each, on a workqueue of its own; whoever needs it meanwhile waits, `dm_map` included. Then reads
and write backs of the region take the checksums from RAM, and a write back changes the leading copy there in
place before it writes the sector. The trailing copy in RAM changes only when it is written.

An area with chunks written back since the last flush is pinned until their trailing copy is written. When
another region needs a place, the area used longest ago that nobody holds is dropped. When half the areas are
held or pinned, the worker of the cache flushes the lower device and writes the trailing copies by itself,
before it writes back the next chunk. A suspend writes them and then drops every area, as the lower device may
change before the device is resumed; damage done to metadata on the lower device is not seen until then.

If the read of a copy fails, its sectors are read one at a time. A sector that failed in one copy is taken from
the other in RAM, and a rate-limited warning names each chunk read or written with one copy; the next write of
that sector puts it right. Only the chunks whose entries are in a sector failed in both copies fail, and an area
with such sectors is read again by the next request that finds it unused. A trailing sector that fails to write
is counted, and its chunks go on with the leading copy.

### Flushes

The device reports a write cache with FUA. An empty flush and a FUA write go to the worker of the cache, which
writes back everything dirty, waits for it, and flushes the lower device. The flush completes then, and fails
while any entry has failed to write back, as it would promise data that is not on the device. After that the
worker writes the trailing copies of the metadata and flushes the lower device again, so that both copies are
durable before the chunks are written back again. A suspend writes back everything
too, so a table reload or a removal loses nothing, except chunks that still fail to write: they are named
in the kernel log. Any other operation, such as discard, is refused.

### Synchronization

Only reads from the lower device and write backs of the cache reach the lower device, and the cache keeps
them apart, the way `dm-integrity` keeps its ranges in flight:

* A read from the lower device is put into a tree of reads in flight of the cache, ordered by chunk, before it
  is sent, and taken out when it completes. The node is in the per-bio data of the read, so this allocates
  nothing.
* A write back of an entry waits in the worker of the cache until no read of its chunk is in flight. A read
  that met it could get the data of one version of a sector and the checksum of another, and fail.
* New reads of the clean sectors of an entry under write back wait in `dm_map`, so the reads of a chunk end.
  Reads of its dirty sectors are copied from the cache.
* The lower writes of the chunks of one metadata sector go one at a time, those of one entry and of its
  neighbours alike, as each writes that sector from the same memory: a second one would change it under the
  first, which could then carry the checksums of data not yet written. The end of one starts the next,
  without a worker waiting.

The cache has one spinlock, held only for a lookup and a copy of at most one chunk, never across I/O. Every
read from the lower device takes it twice.

### Memory

Nothing on the I/O path allocates memory. The cache, with its pages and 256 write back jobs, and the metadata in RAM, with its 32 areas and a scratch area where the trailing sectors are built, are allocated when the target is created. A part lives in the per-bio data of its bio, or in a write back job, with its metadata structure and its metadata bio embedded in it: a read keeps a copy of both entries of its chunk, a write writes its leading metadata sector from the area in RAM. `dm_map` and the worker of the cache wait for an area to be read, or to be let go when all are in use; the workers of `transform_wq` never wait, as they run the completions that let areas go.

At most 4096 parts, reads and write back jobs, are in flight per device. A bio-based device has no request queue with tags, so `dm_map` and the worker wait for a place instead, which slows down the submitter as a full disk queue would. Ordinary load never reaches the limit: 4096 parts are 16 MiB of data, far more than the lower disk queues.

## Building

### Requirements

* Linux kernel headers
* GNU Make
* GCC or Clang

### Build

```bash
make
```

This builds the module and the utility:

```text
dm-dcorr.ko
tools/dcorrsetup
```

## Installation

Load the module:

```bash
sudo insmod dm-dcorr.ko
```

Verify that the module is loaded:

```bash
lsmod | grep dm_dcorr
```

## Device Mapper Setup

Format the underlying device, then create the target with the line `dcorrsetup table` prints, as its length
must be the capacity recorded in the superblock:

```bash
tools/dcorrsetup format <underlying_device>
tools/dcorrsetup table <underlying_device> | dmsetup create dcorr
```

`dcorrsetup format` refuses a device in use, one smaller than two groups, and one that already holds a valid
superblock unless given `--force`. `--group-size SIZE` chooses the size of a group, a power of two from `16M`
to `4G`, `1G` by default. `dcorrsetup dump <underlying_device>` prints the superblock and the layout. Until the bitmap is read,
the underlying device has to be zeroed before it is formatted: chunks never written are read and checked.

Verify device creation:

```bash
ls -l /dev/mapper/dcorr
```

Show the counters:

```bash
dmsetup status dcorr
```

After the usual `<start> <length> dcorr`, it prints thirteen counters: how many times a read waited in `dm_map` for a place among the parts in flight, how many times a write waited for a free entry of the cache, how many times a write waited for an entry under write back, how many reads waited for the write back of their chunk, the entries holding data not yet on the lower device, the entries whose write back failed, how many metadata areas were read from the lower device, how many times anything waited for a metadata area as all were in use, how many sectors of the trailing copy of the metadata failed to write, how many times the worker flushed and wrote the trailing copies by itself as too many metadata areas were busy, how many times it flushed before writing back a chunk written back since the last flush, how many chunks it read before a write back as their two copies of the metadata differed, and how many sectors so read matched neither copy or did not read.

## Usage

Create a filesystem:

```bash
mkfs.ext4 /dev/mapper/dcorr
```

Mount:

```bash
mount /dev/mapper/dcorr /mnt/test
```

Unmount:

```bash
umount /mnt/test
```

Remove Device Mapper target:

```bash
dmsetup remove dcorr
```

## Testing

The driver is built, loaded and tested only in a development VM with a debug kernel, never on the host:
see [deploy/README.md](deploy/README.md). The tests are described in
[tests/README.md](tests/README.md).

### Write and Read Benchmarks

Uncompetitive write benchmark:

```bash
fio --name=test                               \
    --filename=/dev/mapper/dcorr             \
    --rw=write                                \
    --bs=16k                                  \
    --direct=1                                \
    --ioengine=libaio                         \
    --iodepth=1                               \
    --numjobs=1                               \
    --time_based                              \
    --runtime=30
```

Competitive write benchmark:

```bash
fio --name=test                               \
    --filename=/dev/mapper/dcorr             \
    --rw=write                                \
    --bs=16k                                  \
    --direct=1                                \
    --ioengine=libaio                         \
    --iodepth=32                              \
    --numjobs=8                               \
    --time_based                              \
    --runtime=30
```

Uncompetitive read benchmark:

```bash
fio --name=test                               \
    --filename=/dev/mapper/dcorr             \
    --rw=read                                 \
    --bs=16k                                  \
    --direct=1                                \
    --ioengine=libaio                         \
    --iodepth=1                               \
    --numjobs=1                               \
    --time_based                              \
    --runtime=30
```

Competitive read benchmark:

```bash
fio --name=test                               \
    --filename=/dev/mapper/dcorr             \
    --rw=read                                 \
    --bs=16k                                  \
    --direct=1                                \
    --ioengine=libaio                         \
    --iodepth=32                              \
    --numjobs=8                               \
    --time_based                              \
    --runtime=30
```

## Performance Characteristics

See [docs](docs/ru/full_docs.pdf).

## Current Status

### Implemented

* CRC64 integrity verification
* Metadata storage subsystem
* Read path
* Write path
* Concurrent request synchronization
* Device Mapper integration
* Functional testing
* Performance evaluation

### Planned

* Error Correcting Codes (ECC)
* Automatic error recovery
* Metadata caching
* Improved synchronization mechanisms
* Reduced I/O amplification
* Architecture optimizations

## License

GPL-2.0

## Author

Alexey Smirnov

## Research Context

This project was developed as part of a research effort focused on block-level data integrity mechanisms for Linux storage subsystems.

The current implementation provides integrity verification and serves as a foundation for future ECC-based error correction capabilities.

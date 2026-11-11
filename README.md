# Automatic-Error-Correction-Driver

Linux Device Mapper target providing block-level data integrity verification using CRC64 checksums.

## Overview

Correction Driver is a Linux kernel module implemented as a Device Mapper target. The driver creates a virtual block device on top of an existing storage device and transparently intercepts read and write requests.

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
[ARCHITECTURE.md](ARCHITECTURE.md). This section describes the driver as it is.

The virtual device is divided into chunks of 4 KiB, 8 sectors, and the chunks into regions of 1024 chunks,
4 MiB of data, as `dm-integrity` does. The metadata of a chunk is an entry of 8 CRC64 checksums, one per
sector, 64 bytes; a metadata sector holds the entries of 8 neighbouring chunks.

### Layout

```text
region 0                                  region 1
+-----------+-----------+-------------+   +-----------+-----------+-------------+
| copy of   | metadata  | data        |   | copy of   | metadata  | data        |
| region N  | region 0  | 1024 chunks |   | region 0  | region 1  | 1024 chunks | ...
| 128 sect. | 128 sect. | 8192 sect.  |   | 128 sect. | 128 sect. | 8192 sect.  |
+-----------+-----------+-------------+   +-----------+-----------+-------------+
```

The metadata of a region and its data are one contiguous range, and the data stays aligned to 4 KiB. The
copy of the metadata is not written yet; its place is kept. The last region may be shorter: it keeps its whole
metadata area and as many whole chunks as fit.

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
3. Writing back the entry later, once no read of the chunk is in flight: one lower write per run of its dirty
   sectors, each of which calculates the checksums, writes the data, reads the metadata sector of the chunk,
   merges the new checksums into it and writes it back.

### Read Path

1. Splitting the request into chunks;
2. Copying the sectors held in the cache, and completing them;
3. For the others: registering the read in the cache, reading data and metadata, unregistering it,
   calculating and verifying the checksums, completing the request.

### Flushes

The device reports a write cache with FUA. An empty flush and a FUA write go to the worker of the cache, which
writes back everything dirty, waits for it, and flushes the lower device. The flush fails while any entry has
failed to write back, as it would promise data that is not on the device. A suspend writes back everything
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
  neighbours alike, as each merges its checksums into that sector: the end of one starts the next, without a
  worker waiting.

The cache has one spinlock, held only for a lookup and a copy of at most one chunk, never across I/O. Every
read from the lower device takes it twice.

### Memory

Nothing on the I/O path can fail to allocate. The cache, with its pages and 256 write back jobs, is allocated when the target is created. A part lives in the per-bio data of its bio, or in a write back job, with its metadata structure and its metadata bio embedded in it, and the page for the metadata sector comes from a mempool with a reserve of 128 pages. When memory is short, `dm_map` or the worker of the cache waits for a page that another part gives back; the workers of `transform_wq` never wait, as they run the completions that give it back.

At most 4096 parts, reads and write back jobs, are in flight per device. A bio-based device has no request queue with tags, so `dm_map` and the worker wait for a place instead, which slows down the submitter as a full disk queue would. Ordinary load never reaches the limit: 4096 parts are 16 MiB of data, far more than the lower disk queues.

## Building

### Requirements

* Linux kernel headers
* GNU Make
* GCC or Clang

### Build module

```bash
make
```

The resulting module:

```text
correction_driver.ko
```

## Installation

Load the module:

```bash
sudo insmod correction_driver.ko
```

Verify that the module is loaded:

```bash
lsmod | grep correction_driver
```

## Device Mapper Setup

Example target creation:

```bash
echo "0 <sectors> correction_driver <underlying_device>" | dmsetup create corrdm
```

Verify device creation:

```bash
ls -l /dev/mapper/corrdm
```

Show the counters:

```bash
dmsetup status corrdm
```

After the usual `<start> <length> corrdm`, it prints six counters: how many times a read waited in `dm_map` for a place among the parts in flight, how many times a write waited for a free entry of the cache, how many times a write waited for an entry under write back, how many reads waited for the write back of their chunk, the entries holding data not yet on the lower device, and the entries whose write back failed.

## Usage

Create a filesystem:

```bash
mkfs.ext4 /dev/mapper/corrdm
```

Mount:

```bash
mount /dev/mapper/corrdm /mnt/test
```

Unmount:

```bash
umount /mnt/test
```

Remove Device Mapper target:

```bash
dmsetup remove corrdm
```

## Testing

The driver is built, loaded and tested only in a development VM with a debug kernel, never on the host:
see [deploy/README.md](deploy/README.md). The tests are described in
[correction-driver/tests/README.md](correction-driver/tests/README.md).

### Write and Read Benchmarks

Uncompetitive write benchmark:

```bash
fio --name=test                               \
    --filename=/dev/mapper/corrdm             \
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
    --filename=/dev/mapper/corrdm             \
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
    --filename=/dev/mapper/corrdm             \
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
    --filename=/dev/mapper/corrdm             \
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

See [docs](/docs/full_docs.pdf).

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

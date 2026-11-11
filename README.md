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

The virtual device is divided into fixed-size chunks.

Each chunk contains:

* User data region
* Metadata region containing CRC64 checksums

### Layout

```text
+--------------------+
| Chunk 0 Data       |
+--------------------+
| Chunk 0 CRC64      |
+--------------------+
| Chunk 1 Data       |
+--------------------+
| Chunk 1 CRC64      |
+--------------------+
| Chunk 2 Data       |
+--------------------+
| Chunk 2 CRC64      |
+--------------------+
        ...
```

### Cache

Every write goes through a write back cache of 64 MiB per device, allocated when the target is created: one
entry per chunk of data, with a page, a mask of the sectors written into it, a place in a tree ordered by chunk
and a place in a list ordered by age. Device mapper splits requests at chunk boundaries, so each piece of a
write is copied into the entry of its chunk and completes at once. The code is in `src/cache.c`.

A worker writes the entries back: those older than 1 second, as many as keep at least 55% of the entries
free once more than half are in use, and all of them for a flush, a FUA write or a suspend. Writes to an
entry under write back, and writes that find no free entry, wait in `dm_map`. An entry whose write back
failed keeps its data and is tried again on the next flush, suspend or write to it. If every entry has failed,
new writes fail.

### Write Path

1. Splitting the request into chunks;
2. Copying each piece into the entry of its chunk in the cache, and completing it;
3. Writing back the entry later: one lower write per run of its dirty sectors, which takes the lock of the
   chunk, calculates the checksums, writes the data and the metadata, and for a partial chunk merges the old
   checksums of the other sectors.

### Read Path

1. Splitting the request into chunks;
2. Copying the sectors held in the cache, and completing them;
3. For the others: locking the chunk together with other readers, reading data and metadata, unlocking,
   calculating and verifying the checksums, completing the request.

### Flushes

The device reports a write cache with FUA. An empty flush and a FUA write go to the worker of the cache, which
writes back everything dirty, waits for it, and flushes the lower device. The flush fails while any entry has
failed to write back, as it would promise data that is not on the device. A suspend writes back everything
too, so a table reload or a removal loses nothing, except chunks that still fail to write: they are named
in the kernel log. Any other operation, such as discard, is refused.

### Synchronization

The driver uses chunk-level synchronization based on:

* A lock of its own: state under a spinlock and a list of waiting parts, in order of arrival
* A fixed table of 65536 such locks, allocated when the target is created: chunk n uses lock n modulo 65536

This approach allows concurrent reads while preventing conflicting write operations, and taking a lock never allocates memory. Chunks that share a lock sometimes wait for each other, which cannot deadlock, as a part holds one lock at a time. A part that has to wait does not hold a worker: the part that releases the lock queues the next one.

The lock of a chunk keeps reads from the lower device apart from write backs of the same chunk. The cache itself has one spinlock, held only for a lookup and a copy of at most one chunk, never across I/O.

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

After the usual `<start> <length> corrdm`, it prints five counters: how many times a read waited in `dm_map` for a place among the parts in flight, how many times a write waited for a free entry of the cache, how many times a write waited for an entry under write back, the entries holding data not yet on the lower device, and the entries whose write back failed.

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


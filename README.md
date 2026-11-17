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

How the driver works, with a glossary of its terms, is in [ARCHITECTURE.md](docs/en/ARCHITECTURE.md), and as
pictures in [DIAGRAMS.md](docs/en/DIAGRAMS.md); why it is
built this way in [DECISIONS.md](docs/en/DECISIONS.md), with the reading behind it in
[RESEARCH.md](docs/en/RESEARCH.md). What is not done yet is in [TODO.md](docs/en/TODO.md) and
[TODO_OPTIMIZATION.md](docs/en/TODO_OPTIMIZATION.md).

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
to `4G`, `1G` by default. `dcorrsetup dump <underlying_device>` prints the superblock and the layout. The
underlying device need not be zeroed: chunks never written read as zeros.

Verify device creation:

```bash
ls -l /dev/mapper/dcorr
```

Show the counters:

```bash
dmsetup status dcorr
```

It prints 26 counters after the usual `<start> <length> dcorr`, described in
[Interface](docs/en/ARCHITECTURE.md#interface).

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
see [DEPLOY.md](docs/en/DEPLOY.md). The tests are described in [TESTS.md](docs/en/TESTS.md).

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

See the [documentation of the first version](docs/ru/archive/full_docs.pdf), in Russian.

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

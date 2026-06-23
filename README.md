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

### Write Path

1. Splitting the request into chunks;
2. Initializing request structures;
3. Calculating checksums;
4. Generating device requests;
5. Exclusively locking affected chunks;
6. Writing data and metadata;
7. Unlocking affected chunks;
8. Completing the request.

### Read Path

1. Splitting the request into chunks;
2. Initializing request structures;
3. Generating requests to the device;
4. Locking affected chunks together;
5. Reading data and metadata;
6. Unlocking affected chunks;
7. Calculating and verifying checksums;
8. Completing the request.

### Synchronization

The driver uses chunk-level synchronization based on:

* `rw_semaphore`
* `xarray`
* Lazy lock allocation

This approach allows concurrent reads while preventing conflicting write operations and minimizing memory consumption.

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


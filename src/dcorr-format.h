/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The on-disk format of dm-dcorr, shared by the driver and by dcorrsetup in
 * userspace. Only <linux/types.h> is used, and every function is plain
 * arithmetic, so both compute the same layout from the same code; the tests
 * keep a copy of their own in tests/harness.py to check it.
 *
 * The lower device holds two areas of the superblock and the regions of data:
 *
 *   [area, copy 0 | regions 0 .. M - 1 | area, copy 1 | regions M .. R - 1]
 *
 * with M = R / 2, so that a range lost on the device rarely takes both copies.
 * An area is the header of the superblock and the blocks of the bitmap of
 * written chunks, rounded up to DCORR_AREA_ALIGN_SECTORS. A region is
 *
 *   [trailing copy of the metadata of region i - 1 | leading copy of region i | data of region i]
 *
 * The trailing copy of the last region goes into region 0. The last region
 * may be shorter: it keeps both of its metadata areas and as many whole
 * chunks as fit.
 *
 * Version 1 accepts only the values below; the superblock holds them all, so
 * that a later version can change them.
 */
#ifndef DCORR_FORMAT_H
#define DCORR_FORMAT_H

#include <linux/types.h>

#define DCORR_SECTOR_SIZE 512

/// @brief Data sectors of a chunk, the unit of the cache, of the metadata and of the bitmap
#define DCORR_CHUNK_SECTORS 8

/// @brief Bytes of metadata of one chunk: a CRC of each of its sectors
#define DCORR_METADATA_ENTRY_BYTES 64

/// @brief Chunks whose metadata shares one metadata sector
#define DCORR_CHUNKS_PER_METADATA_SECTOR (DCORR_SECTOR_SIZE / DCORR_METADATA_ENTRY_BYTES)

/// @brief Chunks of a region
#define DCORR_REGION_CHUNKS 1024

/// @brief Sectors of one copy of the metadata of a region
#define DCORR_REGION_METADATA_SECTORS (DCORR_REGION_CHUNKS / DCORR_CHUNKS_PER_METADATA_SECTOR)

/// @brief Data sectors of a region
#define DCORR_REGION_DATA_SECTORS (DCORR_REGION_CHUNKS * DCORR_CHUNK_SECTORS)

/// @brief Offset of the data in a region: the trailing copy of the region before, then its leading copy
#define DCORR_REGION_DATA_OFFSET (2 * DCORR_REGION_METADATA_SECTORS)

/// @brief Sectors of a whole region on the lower device
#define DCORR_REGION_SECTORS (DCORR_REGION_DATA_OFFSET + DCORR_REGION_DATA_SECTORS)

/// @brief Sectors of the header of the superblock, the first thing of an area
#define DCORR_HEADER_SECTORS 8
#define DCORR_HEADER_BYTES (DCORR_HEADER_SECTORS * DCORR_SECTOR_SIZE)

/// @brief Sectors of a block of the bitmap; the blocks follow the header
#define DCORR_BITMAP_BLOCK_SECTORS 8
#define DCORR_BITMAP_BLOCK_BYTES (DCORR_BITMAP_BLOCK_SECTORS * DCORR_SECTOR_SIZE)
#define DCORR_BITMAP_HEADER_BYTES 32

/// @brief Chunks one block of the bitmap covers, a bit each
#define DCORR_BITMAP_BLOCK_BITS ((DCORR_BITMAP_BLOCK_BYTES - DCORR_BITMAP_HEADER_BYTES) * 8)

/// @brief An area is rounded up to 1 MiB, so that region 0 starts at a boundary of 1 MiB
#define DCORR_AREA_ALIGN_SECTORS 2048

/// @brief Fewer regions would put copy 1 of the superblock next to copy 0
#define DCORR_MIN_REGIONS 2

#define DCORR_COPIES 2
#define DCORR_MAGIC "dm-dcorr"
#define DCORR_MAGIC_BYTES 8
#define DCORR_VERSION 1

/// @brief The header of the superblock, at the start of each area
/// @details
/// Little endian. The CRC is crc64_be with a zero seed over the whole header
/// with the field crc zeroed. Everything but copy and crc is the same in both
/// copies.
struct dcorr_superblock
{
    __u8 magic[DCORR_MAGIC_BYTES];
    __le32 version;
    /// @brief Which copy this is: 0 at the start, 1 in the middle
    __le32 copy;
    /// @brief The copy with the larger one wins; 1 after dcorrsetup format
    __le64 generation;
    /// @brief None defined yet, must be 0
    __le64 flags;
    __u8 uuid[16];
    /// @brief Random, mixed into the CRCs of the data
    __u8 salt[16];
    /// @brief The size of the lower device it was formatted for
    __le64 lower_sectors;
    /// @brief The size of the device on top, in logical sectors
    __le64 capacity;
    __le32 chunk_sectors;
    __le32 region_chunks;
    __le32 metadata_entry_bytes;
    __le32 bitmap_block_bits;
    __le64 area_sectors;
    __le64 regions;
    __le64 middle_region;
    __le64 bitmap_blocks;
    __le64 crc;
    __u8 reserved[DCORR_HEADER_BYTES - 136];
};

_Static_assert(sizeof(struct dcorr_superblock) == DCORR_HEADER_BYTES, "the header is one block of 4 KiB");

/// @brief A block of the bitmap of written chunks
/// @details
/// Little endian. Bit i of bits, bits[i / 8] >> (i % 8), is chunk
/// index * DCORR_BITMAP_BLOCK_BITS + i. The CRC is crc64_be with a zero seed
/// over the whole block with the field crc zeroed.
struct dcorr_bitmap_block
{
    __le64 crc;
    __le64 generation;
    /// @brief The number of the block in its area
    __le64 index;
    /// @brief The copy of the area it belongs to
    __le32 copy;
    __le32 reserved;
    __u8 bits[DCORR_BITMAP_BLOCK_BITS / 8];
};

_Static_assert(sizeof(struct dcorr_bitmap_block) == DCORR_BITMAP_BLOCK_BYTES, "a block of the bitmap is 4 KiB");

/// @brief Where everything lies on a lower device of a given size
struct dcorr_layout
{
    __u64 lower_sectors;
    /// @brief Sectors of one area of the superblock
    __u64 area_sectors;
    /// @brief Logical sectors of the device on top
    __u64 capacity;
    /// @brief Regions, the last of which may be short
    __u64 regions;
    /// @brief The first region after copy 1 of the superblock
    __u64 middle_region;
    /// @brief Blocks of the bitmap in each area
    __u64 bitmap_blocks;
};

/// @brief Logical sectors that regions laid out over a range of the lower device hold
/// @details Whole regions, plus the whole chunks that fit into the last one after its metadata areas.
static inline __u64 dcorr_regions_capacity(__u64 sectors)
{
    __u64 rest = sectors % DCORR_REGION_SECTORS;
    __u64 capacity = sectors / DCORR_REGION_SECTORS * DCORR_REGION_DATA_SECTORS;

    if (rest > DCORR_REGION_DATA_OFFSET)
        capacity += (rest - DCORR_REGION_DATA_OFFSET) / DCORR_CHUNK_SECTORS * DCORR_CHUNK_SECTORS;

    return capacity;
}

/// @brief Blocks of the bitmap for a device of this capacity
static inline __u64 dcorr_bitmap_blocks(__u64 capacity)
{
    __u64 chunks = capacity / DCORR_CHUNK_SECTORS;

    return (chunks + DCORR_BITMAP_BLOCK_BITS - 1) / DCORR_BITMAP_BLOCK_BITS;
}

/// @brief Sectors of an area of the superblock for a device of this capacity
static inline __u64 dcorr_area_sectors(__u64 capacity)
{
    __u64 sectors = DCORR_HEADER_SECTORS + dcorr_bitmap_blocks(capacity) * DCORR_BITMAP_BLOCK_SECTORS;

    return (sectors + DCORR_AREA_ALIGN_SECTORS - 1) / DCORR_AREA_ALIGN_SECTORS * DCORR_AREA_ALIGN_SECTORS;
}

/// @brief Computes the layout of a lower device
/// @details
/// The size of an area depends on the capacity, which depends on the size of
/// the areas, so the area grows from its smallest size until it holds the
/// bitmap of what is left. It only grows, so this ends.
/// @param lower_sectors Size of the lower device
/// @param layout        The layout, filled on success
/// @return 0, or -1 if the device is too small for DCORR_MIN_REGIONS
static inline int dcorr_layout_compute(__u64 lower_sectors, struct dcorr_layout *layout)
{
    __u64 area = dcorr_area_sectors(0);
    __u64 capacity;

    for (;;)
    {
        if (lower_sectors <= 2 * area)
            return -1;
        capacity = dcorr_regions_capacity(lower_sectors - 2 * area);
        if (dcorr_area_sectors(capacity) <= area)
            break;
        area = dcorr_area_sectors(capacity);
    }

    layout->lower_sectors = lower_sectors;
    layout->area_sectors = area;
    layout->capacity = capacity;
    layout->regions = (capacity + DCORR_REGION_DATA_SECTORS - 1) / DCORR_REGION_DATA_SECTORS;
    layout->middle_region = layout->regions / 2;
    layout->bitmap_blocks = dcorr_bitmap_blocks(capacity);

    return layout->regions < DCORR_MIN_REGIONS ? -1 : 0;
}

/// @brief First sector of an area of the superblock on the lower device
static inline __u64 dcorr_copy_start(const struct dcorr_layout *layout, unsigned int copy)
{
    return copy == 0 ? 0 : layout->area_sectors + layout->middle_region * DCORR_REGION_SECTORS;
}

/// @brief First sector of a region on the lower device
static inline __u64 dcorr_region_start(const struct dcorr_layout *layout, __u64 region)
{
    return layout->area_sectors + region * DCORR_REGION_SECTORS +
           (region >= layout->middle_region ? layout->area_sectors : 0);
}

#endif

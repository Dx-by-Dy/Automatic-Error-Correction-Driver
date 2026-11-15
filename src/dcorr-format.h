/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The on-disk format of dm-dcorr, shared by the driver and by dcorrsetup in
 * userspace. Only <linux/types.h> is used, and every function is plain
 * arithmetic, so both compute the same layout from the same code; the tests
 * keep a copy of their own in tests/harness.py to check it.
 *
 * The lower device is a sequence of groups of one size, a power of two from
 * DCORR_MIN_GROUP_SECTORS to DCORR_MAX_GROUP_SECTORS:
 *
 *   [group 0 | group 1 | ... | group G - 1 | unused]
 *   group: [header, 1 MiB | regions 0 .. Rg - 1 | unused]
 *
 * Every group holds as many whole regions as fit after its header; the rest of
 * it stays unused. The last group may be short: the same header and as many
 * whole regions as fit, at least DCORR_MIN_GROUP_REGIONS, or the tail of the
 * device is not used. There is no short region. A region is
 *
 *   [trailing copy of the metadata of region i - 1 | leading copy of region i | slots of region i]
 *
 * The trailing copy of the last region of a group goes into the first region
 * of the same group. A region holds DCORR_REGION_CHUNKS slots of a chunk each.
 *
 * The header of group g holds a full copy of the superblock with the number of
 * the group, the leading copy of the bitmap of written chunks of group g, the
 * trailing copy of the one of group g - 1 (the last group for group 0), and two
 * blocks of the bitmap of dirty stripes, zeroed by the format until the
 * correction stage defines them:
 *
 *   [superblock | leading bitmap of g | trailing bitmap of g - 1 | dirty stripes, leading, trailing | reserved]
 *
 * The slots of a group, numbered in order across its regions, are cut into
 * DCORR_COLUMNS columns of equal length. The first DCORR_DATA_COLUMNS hold the
 * data, in order; the last DCORR_PARITY_COLUMNS are kept for parity and are
 * not part of the capacity. As a group holds whole regions, a column is
 * DCORR_COLUMN_SLOTS_PER_REGION slots per region of its group. The logical
 * sectors of the device on top fill the data columns of group 0, then of group
 * 1, and so on.
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

/// @brief Slots of a chunk in a region
#define DCORR_REGION_CHUNKS 1024

/// @brief Sectors of one copy of the metadata of a region
#define DCORR_REGION_METADATA_SECTORS (DCORR_REGION_CHUNKS / DCORR_CHUNKS_PER_METADATA_SECTOR)

/// @brief Sectors of the slots of a region
#define DCORR_REGION_DATA_SECTORS (DCORR_REGION_CHUNKS * DCORR_CHUNK_SECTORS)

/// @brief Offset of the slots in a region: the trailing copy of the region before, then its leading copy
#define DCORR_REGION_DATA_OFFSET (2 * DCORR_REGION_METADATA_SECTORS)

/// @brief Sectors of a whole region on the lower device
#define DCORR_REGION_SECTORS (DCORR_REGION_DATA_OFFSET + DCORR_REGION_DATA_SECTORS)

/// @brief Columns of a group, and those of them kept for parity
#define DCORR_COLUMNS 32
#define DCORR_PARITY_COLUMNS 2
#define DCORR_DATA_COLUMNS (DCORR_COLUMNS - DCORR_PARITY_COLUMNS)

/// @brief Slots of a column for each region of its group
#define DCORR_COLUMN_SLOTS_PER_REGION (DCORR_REGION_CHUNKS / DCORR_COLUMNS)

/// @brief Logical sectors each region of a group adds to the capacity: its share of the data columns
#define DCORR_REGION_CAPACITY (DCORR_DATA_COLUMNS * DCORR_COLUMN_SLOTS_PER_REGION * DCORR_CHUNK_SECTORS)

/// @brief Sectors of the superblock, the first thing of the header of a group
#define DCORR_SUPERBLOCK_SECTORS 8
#define DCORR_SUPERBLOCK_BYTES (DCORR_SUPERBLOCK_SECTORS * DCORR_SECTOR_SIZE)

/// @brief Sectors of a block of a bitmap
#define DCORR_BITMAP_BLOCK_SECTORS 8
#define DCORR_BITMAP_BLOCK_BYTES (DCORR_BITMAP_BLOCK_SECTORS * DCORR_SECTOR_SIZE)
#define DCORR_BITMAP_HEADER_BYTES 32

/// @brief Slots one block of the bitmap of written chunks covers, a bit each
#define DCORR_BITMAP_BLOCK_BITS ((DCORR_BITMAP_BLOCK_BYTES - DCORR_BITMAP_HEADER_BYTES) * 8)

/// @brief Sectors of the header of a group, fixed: 1 MiB, so that it starts and ends at a boundary of 1 MiB,
/// with room for later versions
#define DCORR_GROUP_HEADER_SECTORS 2048

/// @brief The sizes of a group: powers of two from 16 MiB, the smallest with more than 2 regions, to 4 GiB
#define DCORR_MIN_GROUP_SECTORS (16ULL << 11)
#define DCORR_MAX_GROUP_SECTORS (4ULL << 21)
#define DCORR_DEFAULT_GROUP_SECTORS (1ULL << 21)

/// @brief Fewer groups would leave the superblock and the bitmap in one copy
#define DCORR_MIN_GROUPS 2

/// @brief Fewer regions would put the trailing copy of the metadata of a region into the region itself
#define DCORR_MIN_GROUP_REGIONS 2

#define DCORR_MAGIC "dm-dcorr"
#define DCORR_MAGIC_BYTES 8
#define DCORR_VERSION 1

/// @brief The roles of a block of a bitmap
enum dcorr_bitmap_role
{
    /// @brief In the header of the group it covers
    DCORR_BITMAP_LEAD,
    /// @brief In the header of the next group
    DCORR_BITMAP_TRAIL,
};

/// @brief The superblock, at the start of the header of each group
/// @details
/// Little endian. The CRC is crc64_be with a zero seed over the whole
/// superblock with the field crc zeroed. Everything but group and crc is the
/// same in every copy.
struct dcorr_superblock
{
    __u8 magic[DCORR_MAGIC_BYTES];
    __le32 version;
    /// @brief The number of the group whose header holds this copy
    __le32 group;
    /// @brief The copy with the larger one wins; 1 after dcorrsetup format
    __le64 generation;
    /// @brief None defined yet, must be 0
    __le64 flags;
    __u8 uuid[16];
    /// @brief Random, mixed into the CRCs of the data and of the bitmaps
    __u8 salt[16];
    /// @brief The size of the lower device it was formatted for
    __le64 lower_sectors;
    /// @brief The size of the device on top, in logical sectors
    __le64 capacity;
    __le32 chunk_sectors;
    __le32 region_chunks;
    __le32 metadata_entry_bytes;
    __le32 bitmap_block_bits;
    __le32 columns;
    __le32 parity_columns;
    __le64 header_sectors;
    __le64 group_sectors;
    __le64 groups;
    /// @brief Regions of a group, and of the last one, which may be short
    __le64 group_regions;
    __le64 last_group_regions;
    /// @brief Blocks of one copy of the bitmap of written chunks of a group
    __le64 bitmap_blocks;
    __le64 crc;
    __u8 reserved[DCORR_SUPERBLOCK_BYTES - 160];
};

_Static_assert(sizeof(struct dcorr_superblock) == DCORR_SUPERBLOCK_BYTES, "the superblock is one block of 4 KiB");

/// @brief A block of the bitmap of written chunks
/// @details
/// Little endian. Bit i of bits, bits[i / 8] >> (i % 8), is the slot
/// index * DCORR_BITMAP_BLOCK_BITS + i of the group. The CRC is crc64_be
/// started from zero over the salt of the device, then over the whole block
/// with the field crc zeroed, so that a block of another device does not pass.
struct dcorr_bitmap_block
{
    __le64 crc;
    __le64 generation;
    /// @brief The group whose slots it covers
    __le64 group;
    /// @brief The number of the block in its copy of the bitmap
    __le32 index;
    /// @brief enum dcorr_bitmap_role
    __le32 role;
    __u8 bits[DCORR_BITMAP_BLOCK_BITS / 8];
};

_Static_assert(sizeof(struct dcorr_bitmap_block) == DCORR_BITMAP_BLOCK_BYTES, "a block of the bitmap is 4 KiB");

/// @brief Regions of a group of the largest size
#define DCORR_MAX_GROUP_REGIONS ((DCORR_MAX_GROUP_SECTORS - DCORR_GROUP_HEADER_SECTORS) / DCORR_REGION_SECTORS)

/// @brief Blocks of one copy of the bitmap of written chunks of a group of this many regions
#define DCORR_BITMAP_BLOCKS(regions) \
    (((regions) * DCORR_REGION_CHUNKS + DCORR_BITMAP_BLOCK_BITS - 1) / DCORR_BITMAP_BLOCK_BITS)

/// @brief Sectors of the header in use: the superblock, two copies of the bitmap, two blocks of dirty stripes
#define DCORR_HEADER_USED_SECTORS(regions) \
    (DCORR_SUPERBLOCK_SECTORS + (2 * DCORR_BITMAP_BLOCKS(regions) + 2) * DCORR_BITMAP_BLOCK_SECTORS)

_Static_assert(DCORR_HEADER_USED_SECTORS(DCORR_MAX_GROUP_REGIONS) <= DCORR_GROUP_HEADER_SECTORS,
               "the header of the largest group must hold its bitmaps");
_Static_assert(DCORR_MAX_GROUP_REGIONS * DCORR_COLUMN_SLOTS_PER_REGION <= DCORR_BITMAP_BLOCK_BITS,
               "the dirty stripes of a group, one bit a row, must fit one block");
_Static_assert(DCORR_REGION_CHUNKS % DCORR_COLUMNS == 0, "a region must add whole slots to every column");

/// @brief Where everything lies on a lower device of a given size
struct dcorr_layout
{
    __u64 lower_sectors;
    __u64 group_sectors;
    /// @brief Groups, the last of which may be short
    __u64 groups;
    /// @brief Regions of a group that is not short
    __u64 group_regions;
    /// @brief Regions of the last group, group_regions if it is not short
    __u64 last_group_regions;
    /// @brief Logical sectors of a group that is not short
    __u64 group_capacity;
    /// @brief Logical sectors of the device on top
    __u64 capacity;
    /// @brief Blocks of one copy of the bitmap of written chunks of a group
    __u64 bitmap_blocks;
};

/// @brief Whether a size of a group is one of the list
static inline int dcorr_group_size_valid(__u64 sectors)
{
    return sectors >= DCORR_MIN_GROUP_SECTORS && sectors <= DCORR_MAX_GROUP_SECTORS && !(sectors & (sectors - 1));
}

/// @brief Whole regions that a group, or a short last one, of this many sectors holds after its header
static inline __u64 dcorr_group_regions(__u64 sectors)
{
    return sectors > DCORR_GROUP_HEADER_SECTORS ? (sectors - DCORR_GROUP_HEADER_SECTORS) / DCORR_REGION_SECTORS : 0;
}

/// @brief Computes the layout of a lower device
/// @param lower_sectors Size of the lower device
/// @param group_sectors Size of a group, one of the list
/// @param layout        The layout, filled on success
/// @return 0, or -1 if the size of the group is not one of the list, or the
/// device holds fewer than DCORR_MIN_GROUPS groups
static inline int dcorr_layout_compute(__u64 lower_sectors, __u64 group_sectors, struct dcorr_layout *layout)
{
    __u64 full, last;

    if (!dcorr_group_size_valid(group_sectors))
        return -1;

    full = lower_sectors / group_sectors;
    last = dcorr_group_regions(lower_sectors % group_sectors);

    layout->lower_sectors = lower_sectors;
    layout->group_sectors = group_sectors;
    layout->group_regions = dcorr_group_regions(group_sectors);
    layout->groups = full + (last >= DCORR_MIN_GROUP_REGIONS ? 1 : 0);
    layout->last_group_regions = last >= DCORR_MIN_GROUP_REGIONS ? last : layout->group_regions;
    layout->group_capacity = layout->group_regions * DCORR_REGION_CAPACITY;
    layout->capacity = layout->groups ? (layout->groups - 1) * layout->group_capacity +
                                            layout->last_group_regions * DCORR_REGION_CAPACITY
                                      : 0;
    layout->bitmap_blocks = DCORR_BITMAP_BLOCKS(layout->group_regions);

    return layout->groups < DCORR_MIN_GROUPS ? -1 : 0;
}

/// @brief First sector of a group on the lower device, where its header and its superblock start
static inline __u64 dcorr_group_start(const struct dcorr_layout *layout, __u64 group)
{
    return group * layout->group_sectors;
}

/// @brief Regions of a group
static inline __u64 dcorr_regions_of_group(const struct dcorr_layout *layout, __u64 group)
{
    return group + 1 == layout->groups ? layout->last_group_regions : layout->group_regions;
}

/// @brief Regions of the device, numbered across the groups
static inline __u64 dcorr_regions(const struct dcorr_layout *layout)
{
    return (layout->groups - 1) * layout->group_regions + layout->last_group_regions;
}

/// @brief First sector of a region on the lower device
static inline __u64 dcorr_region_start(const struct dcorr_layout *layout, __u64 region)
{
    return dcorr_group_start(layout, region / layout->group_regions) + DCORR_GROUP_HEADER_SECTORS +
           region % layout->group_regions * DCORR_REGION_SECTORS;
}

/// @brief The region whose leading area of metadata is followed by the trailing copy of this one
/// @details The next region of the same group; the first one for the last region of a group.
static inline __u64 dcorr_trail_region(const struct dcorr_layout *layout, __u64 region)
{
    __u64 group = region / layout->group_regions;
    __u64 next = region % layout->group_regions + 1;

    return group * layout->group_regions + (next == dcorr_regions_of_group(layout, group) ? 0 : next);
}

/// @brief The slot of the chunk of a logical sector, numbered across the regions of the device
/// @details The data columns of a group come first in it, so its logical chunks take its first slots in order.
static inline __u64 dcorr_chunk_slot(const struct dcorr_layout *layout, __u64 sector)
{
    return sector / layout->group_capacity * layout->group_regions * DCORR_REGION_CHUNKS +
           sector % layout->group_capacity / DCORR_CHUNK_SECTORS;
}

/// @brief Offset in the header of a group of the leading copy of its bitmap, right after the superblock
#define DCORR_LEAD_BITMAP_OFFSET DCORR_SUPERBLOCK_SECTORS

/// @brief Offset in the header of a group of the trailing copy of the bitmap of the group before
static inline __u64 dcorr_trail_bitmap_offset(const struct dcorr_layout *layout)
{
    return DCORR_SUPERBLOCK_SECTORS + layout->bitmap_blocks * DCORR_BITMAP_BLOCK_SECTORS;
}

/// @brief Offset in the header of a group of its two blocks of dirty stripes, the leading one first
static inline __u64 dcorr_dirty_offset(const struct dcorr_layout *layout)
{
    return DCORR_SUPERBLOCK_SECTORS + 2 * layout->bitmap_blocks * DCORR_BITMAP_BLOCK_SECTORS;
}

/// @brief Sectors at the start of the header of a group that the format writes
static inline __u64 dcorr_header_used_sectors(const struct dcorr_layout *layout)
{
    return dcorr_dirty_offset(layout) + 2 * DCORR_BITMAP_BLOCK_SECTORS;
}

#endif

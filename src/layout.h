#ifndef LAYOUT_H
#define LAYOUT_H

#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/types.h>

#include "dcorr-format.h"

/*
 * Where the data and the metadata of a logical sector lie on the lower device.
 * The layout is in dcorr-format.h; the sizes of a chunk and a region are the
 * constants of version 1 of the format, DCORR_*, and the rest comes from the
 * superblock as struct dcorr_layout.
 *
 * The metadata of a region is kept in two copies. The leading one, next to the
 * slots, is written with each write back of a chunk; the trailing one, in the
 * next region, after the lower device has flushed, so a lost sector of one
 * copy is read from the other. A metadata sector holds the entries of
 * DCORR_CHUNKS_PER_METADATA_SECTOR neighbouring chunks.
 *
 * A logical sector is found by the slot of its chunk, see dcorr_chunk_slot:
 * the slots of a group run across its regions, and the data columns of the
 * group take its first ones, so the region and the place in the region come
 * from the slot, not from the logical sector itself.
 */

static_assert(DCORR_SECTOR_SIZE == SECTOR_SIZE, "the format counts in sectors of 512 bytes");
static_assert(DCORR_REGION_CHUNKS % DCORR_CHUNKS_PER_METADATA_SECTOR == 0,
              "a metadata sector must not cover chunks of two regions");
static_assert(DCORR_REGION_DATA_OFFSET % DCORR_CHUNK_SECTORS == 0, "the slots must stay aligned to a chunk");
static_assert(DCORR_REGION_SECTORS % DCORR_CHUNK_SECTORS == 0, "every region must start aligned to a chunk");
static_assert(DCORR_GROUP_HEADER_SECTORS % DCORR_CHUNK_SECTORS == 0, "a header must keep the regions aligned");
static_assert(DCORR_MIN_GROUP_SECTORS % DCORR_CHUNK_SECTORS == 0, "a group must keep the regions aligned");

/// @brief The region of the chunk of a logical sector
static inline sector_t layout_region(const struct dcorr_layout *layout, sector_t sector)
{
    return dcorr_chunk_slot(layout, sector) / DCORR_REGION_CHUNKS;
}

/// @brief Index of the chunk of a logical sector in its region
static inline unsigned int layout_region_chunk(const struct dcorr_layout *layout, sector_t sector)
{
    return (unsigned int)(dcorr_chunk_slot(layout, sector) % DCORR_REGION_CHUNKS);
}

/// @brief The logical sector where the chunk in a slot of a region starts, if the slot holds data
/// @details The data columns of a group take its first slots, so a slot past its capacity is of parity.
/// @return Whether the slot holds data; sector is set then
static inline bool layout_slot_logical(const struct dcorr_layout *layout, sector_t region, unsigned int index,
                                       sector_t *sector)
{
    u64 group = region / layout->group_regions;
    u64 slot = region % layout->group_regions * DCORR_REGION_CHUNKS + index;

    if (slot >= dcorr_regions_of_group(layout, group) * DCORR_REGION_CAPACITY / DCORR_CHUNK_SECTORS)
        return false;
    *sector = group * layout->group_capacity + slot * DCORR_CHUNK_SECTORS;
    return true;
}

/// @brief The physical sector that holds the data of a logical sector
static inline sector_t layout_data_sector(const struct dcorr_layout *layout, sector_t sector)
{
    u64 slot = dcorr_chunk_slot(layout, sector);

    return dcorr_region_start(layout, slot / DCORR_REGION_CHUNKS) + DCORR_REGION_DATA_OFFSET +
           slot % DCORR_REGION_CHUNKS * DCORR_CHUNK_SECTORS + sector % DCORR_CHUNK_SECTORS;
}

/// @brief The first physical sector of the slot of the chunk of a logical sector
static inline sector_t layout_slot_start(const struct dcorr_layout *layout, sector_t sector)
{
    return layout_data_sector(layout, sector - sector % DCORR_CHUNK_SECTORS);
}

/// @brief The physical sector of the leading copy that holds the entry of the chunk of a logical sector
/// @details The metadata sector is shared with the neighbouring chunks.
static inline sector_t layout_lead_metadata_sector(const struct dcorr_layout *layout, sector_t sector)
{
    u64 slot = dcorr_chunk_slot(layout, sector);

    return dcorr_region_start(layout, slot / DCORR_REGION_CHUNKS) + DCORR_REGION_METADATA_SECTORS +
           slot % DCORR_REGION_CHUNKS / DCORR_CHUNKS_PER_METADATA_SECTOR;
}

/// @brief First sector of the leading copy of the metadata of a region on the lower device
static inline sector_t layout_lead_area_start(const struct dcorr_layout *layout, sector_t region)
{
    return dcorr_region_start(layout, region) + DCORR_REGION_METADATA_SECTORS;
}

/// @brief First sector of the trailing copy of the metadata of a region on the lower device
/// @details The copy of the last region of a group goes into the first region of the group.
static inline sector_t layout_trail_area_start(const struct dcorr_layout *layout, sector_t region)
{
    return dcorr_region_start(layout, dcorr_trail_region(layout, region));
}

#endif

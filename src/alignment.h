#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/types.h>

#include "dcorr-format.h"

/*
 * Where the data and the metadata of a logical sector lie on the device below.
 * The layout is in dcorr-format.h; the sizes of a chunk and a region are the
 * constants of version 1 of the format, and the rest comes from the superblock
 * as struct dcorr_layout.
 *
 * The metadata of a region is kept in two copies. The leading one, next to the
 * data, is written with each write back of a chunk; the trailing one, in the
 * next region, after the lower device has flushed, so a lost sector of one
 * copy is read from the other. A metadata sector holds the entries of
 * CHUNKS_PER_METADATA_SECTOR neighbouring chunks.
 *
 * A logical sector is found by the slot of its chunk, see dcorr_chunk_slot:
 * the slots of a group run across its regions, and the data columns of the
 * group take its first ones, so the region and the place in the region come
 * from the slot, not from the logical sector itself.
 */

/// @brief Data sectors of a chunk, the unit of the cache and of the metadata
#define DATA_SIZE_SECTORS DCORR_CHUNK_SECTORS

/// @brief Bytes of metadata of one chunk, struct chunk_metadata
#define METADATA_ENTRY_SIZE DCORR_METADATA_ENTRY_BYTES

/// @brief Chunks whose metadata shares one metadata sector
#define CHUNKS_PER_METADATA_SECTOR DCORR_CHUNKS_PER_METADATA_SECTOR

/// @brief Chunks of a region
#define REGION_CHUNKS DCORR_REGION_CHUNKS

/// @brief Sectors of one copy of the metadata of a region
#define REGION_METADATA_SECTORS DCORR_REGION_METADATA_SECTORS


/// @brief Offset of the data in a region: the trailing copy of the metadata of the region before, then
/// the leading copy of its own
#define REGION_DATA_OFFSET DCORR_REGION_DATA_OFFSET

/// @brief Sectors of a whole region on the lower device
#define REGION_SECTORS DCORR_REGION_SECTORS

static_assert(DCORR_SECTOR_SIZE == SECTOR_SIZE, "the format counts in sectors of 512 bytes");
static_assert(REGION_CHUNKS % CHUNKS_PER_METADATA_SECTOR == 0,
              "a metadata sector must not cover chunks of two regions");
static_assert(REGION_DATA_OFFSET % DATA_SIZE_SECTORS == 0, "the data must stay aligned to a chunk");
static_assert(REGION_SECTORS % DATA_SIZE_SECTORS == 0, "every region must start aligned to a chunk");
static_assert(DCORR_GROUP_HEADER_SECTORS % DATA_SIZE_SECTORS == 0, "a header must keep the regions aligned");
static_assert(DCORR_MIN_GROUP_SECTORS % DATA_SIZE_SECTORS == 0, "a group must keep the regions aligned");

/// @brief The slot of the chunk of a logical sector, numbered across the regions of the device
static inline u64 chunk_slot(const struct dcorr_layout *layout, sector_t sector)
{
    return dcorr_chunk_slot(layout, sector);
}

/// @brief The region of the chunk of a logical sector
static inline sector_t sector_region(const struct dcorr_layout *layout, sector_t sector)
{
    return chunk_slot(layout, sector) / REGION_CHUNKS;
}

/// @brief Index of the chunk of a logical sector in its region
static inline unsigned int region_chunk(const struct dcorr_layout *layout, sector_t sector)
{
    return (unsigned int)(chunk_slot(layout, sector) % REGION_CHUNKS);
}

/// @brief Converts a logical sector to the physical sector of its data
/// @param layout The layout of the device
/// @param sector Logical sector
/// @return Physical sector
static inline sector_t align_data_sector(const struct dcorr_layout *layout, sector_t sector)
{
    u64 slot = chunk_slot(layout, sector);

    return dcorr_region_start(layout, slot / REGION_CHUNKS) + REGION_DATA_OFFSET +
           slot % REGION_CHUNKS * DATA_SIZE_SECTORS + sector % DATA_SIZE_SECTORS;
}

/// @brief Calculates the physical sector where the data of the chunk of a logical sector starts
/// @param layout The layout of the device
/// @param sector Logical sector
/// @return Physical sector of the first data sector of the chunk
static inline sector_t start_data_sector(const struct dcorr_layout *layout, sector_t sector)
{
    return align_data_sector(layout, sector - sector % DATA_SIZE_SECTORS);
}

/// @brief Calculates the physical sector that holds the leading copy of the metadata of the chunk of a logical sector
/// @param layout The layout of the device
/// @param sector Logical sector
/// @return Physical metadata sector, shared with the neighbouring chunks
static inline sector_t metadata_sector(const struct dcorr_layout *layout, sector_t sector)
{
    u64 slot = chunk_slot(layout, sector);

    return dcorr_region_start(layout, slot / REGION_CHUNKS) + REGION_METADATA_SECTORS +
           slot % REGION_CHUNKS / CHUNKS_PER_METADATA_SECTOR;
}

/// @brief First sector of the leading copy of the metadata of a region on the device below
static inline sector_t lead_area_start(const struct dcorr_layout *layout, sector_t region)
{
    return dcorr_region_start(layout, region) + REGION_METADATA_SECTORS;
}

/// @brief First sector of the trailing copy of the metadata of a region on the device below
/// @details The copy of the last region of a group goes into the first region of the group.
static inline sector_t trail_area_start(const struct dcorr_layout *layout, sector_t region)
{
    return dcorr_region_start(layout, dcorr_trail_region(layout, region));
}

#endif

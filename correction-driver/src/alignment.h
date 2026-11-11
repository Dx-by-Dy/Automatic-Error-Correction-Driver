#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/types.h>

/// @brief Data sectors of a chunk, the unit of the cache and of the metadata
#define DATA_SIZE_SECTORS 8

/// @brief Bytes of metadata of one chunk, struct chunk_metadata
#define METADATA_ENTRY_SIZE 64

/// @brief Chunks whose metadata shares one metadata sector
#define CHUNKS_PER_METADATA_SECTOR (SECTOR_SIZE / METADATA_ENTRY_SIZE)

/// @brief Chunks of a region
#define REGION_CHUNKS 1024

/// @brief Sectors of the metadata of a region, and of its copy
#define REGION_METADATA_SECTORS (REGION_CHUNKS / CHUNKS_PER_METADATA_SECTOR)

/// @brief Data sectors of a region
#define REGION_DATA_SECTORS (REGION_CHUNKS * DATA_SIZE_SECTORS)

/// @brief Offset of the data in a region: the copy of the metadata of the region before, then its own
#define REGION_DATA_OFFSET (2 * REGION_METADATA_SECTORS)

/// @brief Sectors of a whole region on the lower device
#define REGION_SECTORS (REGION_DATA_OFFSET + REGION_DATA_SECTORS)

static_assert(REGION_CHUNKS % CHUNKS_PER_METADATA_SECTOR == 0,
              "a metadata sector must not cover chunks of two regions");
static_assert(REGION_DATA_OFFSET % DATA_SIZE_SECTORS == 0, "the data must stay aligned to a chunk");

/*
 * The lower device is a sequence of regions of REGION_CHUNKS chunks each:
 *
 *   [copy of the metadata of region i - 1 | metadata of region i | data of region i]
 *
 * The copy of the last region goes into region 0; it is not written yet. A
 * metadata sector holds the entries of CHUNKS_PER_METADATA_SECTOR neighbouring
 * chunks. The last region may be shorter: it keeps its whole metadata area
 * and as many whole chunks as fit.
 */

/// @brief Converts a logical sector to the physical sector of its data
/// @param sector Logical sector
/// @return Physical sector
static inline sector_t align_data_sector(sector_t sector)
{
    return (sector / REGION_DATA_SECTORS) * REGION_SECTORS + REGION_DATA_OFFSET +
           sector % REGION_DATA_SECTORS;
}

/// @brief Calculates the physical sector where the data of the chunk of a logical sector starts
/// @param sector Logical sector
/// @return Physical sector of the first data sector of the chunk
static inline sector_t start_data_sector(sector_t sector)
{
    return align_data_sector(sector - sector % DATA_SIZE_SECTORS);
}

/// @brief Calculates the physical sector that holds the metadata of the chunk of a logical sector
/// @param sector Logical sector
/// @return Physical metadata sector, shared with the neighbouring chunks
static inline sector_t metadata_sector(sector_t sector)
{
    return (sector / REGION_DATA_SECTORS) * REGION_SECTORS + REGION_METADATA_SECTORS +
           sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS / CHUNKS_PER_METADATA_SECTOR;
}

/// @brief Calculates where the metadata of the chunk of a logical sector is in its metadata sector
/// @param sector Logical sector
/// @return Offset in bytes of the entry of the chunk
static inline unsigned int metadata_offset(sector_t sector)
{
    return (unsigned int)(sector / DATA_SIZE_SECTORS % CHUNKS_PER_METADATA_SECTOR) * METADATA_ENTRY_SIZE;
}

/// @brief Calculates available device capacity
/// @details
/// Whole regions, plus the whole chunks that fit into the last one after its
/// metadata area.
/// @param sector Full capacity of the underlying device
/// @return Available logical device capacity
static inline sector_t device_new_capacity(sector_t sector)
{
    sector_t rest = sector % REGION_SECTORS;
    sector_t capacity = sector / REGION_SECTORS * REGION_DATA_SECTORS;

    if (rest > REGION_DATA_OFFSET)
        capacity += (rest - REGION_DATA_OFFSET) / DATA_SIZE_SECTORS * DATA_SIZE_SECTORS;

    return capacity;
}

#endif

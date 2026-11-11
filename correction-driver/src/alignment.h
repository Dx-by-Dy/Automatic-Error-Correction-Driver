#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include <linux/types.h>

#define DATA_SIZE_SECTORS 8
#define METADATA_SIZE_SECTORS 1
#define CHUNK_SIZE_SECTORS (DATA_SIZE_SECTORS + METADATA_SIZE_SECTORS)

/// @brief Converts logical device sector to physical sector
/// @details
/// After every DATA_SIZE_SECTORS data sectors,
/// METADATA_SIZE_SECTORS metadata sectors are placed on the device.
/// The function calculates the physical data sector
/// corresponding to a logical sector.
/// @param sector Logical sector
/// @return Physical sector
static inline sector_t align_data_sector(sector_t sector)
{
    return (sector / DATA_SIZE_SECTORS) * (CHUNK_SIZE_SECTORS) + (sector % DATA_SIZE_SECTORS);
}

/// @brief Calculates the start of the data area of a chunk
/// @details
/// For a given logical sector, determines the physical sector
/// from which the data area of the corresponding chunk starts.
/// @param sector Logical sector
/// @return Physical sector at the start of the chunk's data area
static inline sector_t start_data_sector(sector_t sector)
{
    sector_t align_sector = align_data_sector(sector);

    return align_sector - (align_sector % CHUNK_SIZE_SECTORS);
}

/// @brief Calculates the start of the metadata area of a chunk
/// @details
/// For a given logical sector, determines the physical sector
/// in which the metadata of the corresponding chunk is located.
/// @param sector Logical sector
/// @return Physical sector at the start of the chunk's metadata area
static inline sector_t start_metadata_sector(sector_t sector)
{
    return start_data_sector(sector) + DATA_SIZE_SECTORS;
}

/// @brief Calculates available device capacity
/// @details
/// Excludes metadata sectors from the calculation,
/// placed after each data chunk.
/// @param sector Full capacity of the underlying device
/// @return Available logical device capacity
static inline sector_t device_new_capacity(sector_t sector)
{
    return sector / CHUNK_SIZE_SECTORS * DATA_SIZE_SECTORS;
}

#endif

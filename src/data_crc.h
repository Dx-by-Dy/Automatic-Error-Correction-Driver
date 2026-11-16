#ifndef DATA_CRC_H
#define DATA_CRC_H

#include <linux/blkdev.h>
#include <linux/crc64.h>
#include <linux/types.h>

/*
 * The CRC of a data sector is crc64_be over the salt of the device, the
 * logical sector as le64, then the 512 bytes of the sector:
 *
 *   crc64_be(0, salt || le64(logical sector) || data)
 *
 * The CRC of the salt is computed once per table, see superblock_info, and
 * each sector continues it with its place, then its data. With a seed that
 * depends on the place and on the device, the same data gives a different CRC
 * in another sector or on another device: a chunk copied with its metadata, a
 * misdirected write, sectors swapped inside a chunk with their CRCs, or zeros
 * with zeroed metadata no longer pass. As a CRC is linear, this holds for
 * certain, not by chance, for sectors of one device.
 */

/// @brief The CRC every data sector of the device starts from: that of its salt
static inline u64 data_crc_salt(const u8 *salt, size_t len)
{
    return crc64_be(0, salt, len);
}

/// @brief The seed of the CRC of the data of a logical sector
/// @param salt_crc The CRC of the salt, see data_crc_salt
/// @param sector   The logical sector, relative to the start of the device on top
/// @return The CRC to continue over the data of the sector
static inline u64 data_crc_seed(u64 salt_crc, sector_t sector)
{
    __le64 place = cpu_to_le64(sector);

    return crc64_be(salt_crc, &place, sizeof(place));
}

#endif

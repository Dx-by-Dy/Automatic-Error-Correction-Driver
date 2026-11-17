#ifndef SUPERBLOCK_H
#define SUPERBLOCK_H

#include <linux/blkdev.h>
#include <linux/types.h>

#include "dcorr-format.h"

/// @brief What the driver takes from the superblock
struct superblock_info
{
    struct dcorr_layout layout;
    u8 uuid[16];
    u8 salt[16];
    /// @brief The CRC of the salt, where the CRC of every data sector starts, see data_crc.h
    u64 salt_crc;
    /// @brief The group whose copy it was taken from, 0 or 1
    unsigned int group;
    u64 generation;
};

struct dm_target;

int superblock_read(struct dm_target *ti, struct block_device *bdev, struct superblock_info *info);
const char *superblock_verify(const struct dcorr_superblock *sb, unsigned int group,
                              const struct superblock_info *info);

#endif

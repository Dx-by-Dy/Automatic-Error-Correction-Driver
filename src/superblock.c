#include <linux/bio.h>
#include <linux/crc64.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>

#include "superblock.h"
#include "macros.h"

#define SUPERBLOCK_CRC_END (offsetof(struct dcorr_superblock, crc) + sizeof_field(struct dcorr_superblock, crc))

/// @brief The CRC of a header, computed as if its field crc were zero
static u64 superblock_crc(const struct dcorr_superblock *sb)
{
    static const u8 zero[sizeof_field(struct dcorr_superblock, crc)];
    u64 crc;

    crc = crc64_be(0, sb, offsetof(struct dcorr_superblock, crc));
    crc = crc64_be(crc, zero, sizeof(zero));
    return crc64_be(crc, (const u8 *)sb + SUPERBLOCK_CRC_END, DCORR_HEADER_BYTES - SUPERBLOCK_CRC_END);
}

/// @brief Checks a copy of the header against version 1 and against the layout of the device below
/// @param sb     The header as read
/// @param copy   Which copy it was read as
/// @param layout The layout computed from the size of the device below
/// @return NULL if the copy is valid, or why it is not
static const char *superblock_check(const struct dcorr_superblock *sb, unsigned int copy,
                                    const struct dcorr_layout *layout)
{
    if (memcmp(sb->magic, DCORR_MAGIC, DCORR_MAGIC_BYTES))
        return "no magic";
    if (le64_to_cpu(sb->crc) != superblock_crc(sb))
        return "CRC mismatch";
    if (le32_to_cpu(sb->version) != DCORR_VERSION)
        return "unsupported version";
    if (le32_to_cpu(sb->copy) != copy)
        return "the number of another copy";
    if (le64_to_cpu(sb->flags))
        return "unknown flags";
    if (le32_to_cpu(sb->chunk_sectors) != DCORR_CHUNK_SECTORS ||
        le32_to_cpu(sb->region_chunks) != DCORR_REGION_CHUNKS ||
        le32_to_cpu(sb->metadata_entry_bytes) != DCORR_METADATA_ENTRY_BYTES ||
        le32_to_cpu(sb->bitmap_block_bits) != DCORR_BITMAP_BLOCK_BITS)
        return "parameters other than those of version 1";
    if (le64_to_cpu(sb->lower_sectors) != layout->lower_sectors)
        return "formatted for a device of another size";
    if (le64_to_cpu(sb->area_sectors) != layout->area_sectors ||
        le64_to_cpu(sb->capacity) != layout->capacity ||
        le64_to_cpu(sb->regions) != layout->regions ||
        le64_to_cpu(sb->middle_region) != layout->middle_region ||
        le64_to_cpu(sb->bitmap_blocks) != layout->bitmap_blocks)
        return "a layout other than the one computed";
    return NULL;
}

/// @brief Whether two valid copies agree in everything but their number and their CRC
static bool superblock_same(const struct dcorr_superblock *a, const struct dcorr_superblock *b)
{
    const size_t copy = offsetof(struct dcorr_superblock, copy);
    const size_t generation = offsetof(struct dcorr_superblock, generation);
    const size_t crc = offsetof(struct dcorr_superblock, crc);

    return !memcmp(a, b, copy) &&
           !memcmp((const u8 *)a + generation, (const u8 *)b + generation, crc - generation) &&
           !memcmp((const u8 *)a + SUPERBLOCK_CRC_END, (const u8 *)b + SUPERBLOCK_CRC_END,
                   DCORR_HEADER_BYTES - SUPERBLOCK_CRC_END);
}

/// @brief Reads both copies of the superblock and takes the valid one with the larger generation
/// @details
/// The layout is computed from the size of the device below, which tells
/// where copy 1 lies, and each copy is checked against it. A copy that is not
/// valid is named in the kernel log; with neither valid the device is refused.
/// Two valid copies of the same generation should be equal, as the driver
/// never writes the header; if they are not, copy 0 is taken, with a warning.
///
/// Expected execution context - the constructor of the target, may sleep.
/// @param bdev  The device below
/// @param info  What the driver takes from it, filled on success
/// @param error The reason for the table, set on failure
/// @return 0, or a negative error code
int superblock_read(struct block_device *bdev, struct superblock_info *info, char **error)
{
    struct dcorr_superblock *sb[DCORR_COPIES] = {};
    const char *reason[DCORR_COPIES];
    struct dcorr_layout layout;
    unsigned int copy, chosen;
    int r = 0;

    if (dcorr_layout_compute(bdev_nr_sectors(bdev), &layout))
    {
        *error = "The device below is too small";
        return -EINVAL;
    }

    for (copy = 0; copy < DCORR_COPIES; copy++)
    {
        sb[copy] = kmalloc(DCORR_HEADER_BYTES, GFP_KERNEL);
        if (!sb[copy])
        {
            *error = "Cannot allocate the superblock";
            r = -ENOMEM;
            goto out;
        }
        r = bdev_rw_virt(bdev, dcorr_copy_start(&layout, copy), sb[copy], DCORR_HEADER_BYTES, REQ_OP_READ);
        reason[copy] = r ? "read failed" : superblock_check(sb[copy], copy, &layout);
    }
    r = 0;

    if (reason[0] && reason[1])
    {
        DM_ERR("no valid superblock: copy 0: %s, copy 1: %s\n", reason[0], reason[1]);
        *error = "No valid superblock on the device below, format it with dcorrsetup";
        r = -EINVAL;
        goto out;
    }

    if (reason[0] || reason[1])
        chosen = reason[0] ? 1 : 0;
    else
        chosen = le64_to_cpu(sb[1]->generation) > le64_to_cpu(sb[0]->generation) ? 1 : 0;

    if (reason[1 - chosen])
        DM_WARN("copy %u of the superblock is not valid: %s\n", 1 - chosen, reason[1 - chosen]);
    else if (sb[0]->generation == sb[1]->generation && !superblock_same(sb[0], sb[1]))
        DM_WARN("the copies of the superblock differ in the same generation, taking copy 0\n");

    info->layout = layout;
    memcpy(info->salt, sb[chosen]->salt, sizeof(info->salt));
    info->copy = chosen;
    info->generation = le64_to_cpu(sb[chosen]->generation);
    DM_INFO("superblock copy %u, generation %llu\n", chosen, (unsigned long long)info->generation);

out:
    for (copy = 0; copy < DCORR_COPIES; copy++)
        kfree(sb[copy]);
    return r;
}

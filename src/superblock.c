#include <linux/bio.h>
#include <linux/crc64.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>

#include "superblock.h"
#include "macros.h"

#define SUPERBLOCK_CRC_END (offsetof(struct dcorr_superblock, crc) + sizeof_field(struct dcorr_superblock, crc))

/// @brief The copies the constructor reads: those in the headers of groups 0 and 1
#define SUPERBLOCK_COPIES 2

/// @brief The CRC of a superblock, computed as if its field crc were zero
static u64 superblock_crc(const struct dcorr_superblock *sb)
{
    static const u8 zero[sizeof_field(struct dcorr_superblock, crc)];
    u64 crc;

    crc = crc64_be(0, sb, offsetof(struct dcorr_superblock, crc));
    crc = crc64_be(crc, zero, sizeof(zero));
    return crc64_be(crc, (const u8 *)sb + SUPERBLOCK_CRC_END, DCORR_SUPERBLOCK_BYTES - SUPERBLOCK_CRC_END);
}

/// @brief Checks a copy of the superblock against version 1 and against the device below
/// @param sb            The copy as read
/// @param group         The group whose header it was read from
/// @param lower_sectors The size of the device below
/// @param group_sectors The size of a group that put the copy where it was read, 0 for group 0, where
///                      every size does
/// @param layout        Filled with the layout of the size of a group it records, if it is valid
/// @return NULL if the copy is valid, or why it is not
static const char *superblock_check(const struct dcorr_superblock *sb, unsigned int group, u64 lower_sectors,
                                    u64 group_sectors, struct dcorr_layout *layout)
{
    u64 size;

    if (memcmp(sb->magic, DCORR_MAGIC, DCORR_MAGIC_BYTES))
        return "no magic";
    if (le64_to_cpu(sb->crc) != superblock_crc(sb))
        return "CRC mismatch";
    if (le32_to_cpu(sb->version) != DCORR_VERSION)
        return "unsupported version";
    if (le32_to_cpu(sb->group) != group)
        return "the number of another group";
    if (le64_to_cpu(sb->flags))
        return "unknown flags";
    if (le32_to_cpu(sb->chunk_sectors) != DCORR_CHUNK_SECTORS ||
        le32_to_cpu(sb->region_chunks) != DCORR_REGION_CHUNKS ||
        le32_to_cpu(sb->metadata_entry_bytes) != DCORR_METADATA_ENTRY_BYTES ||
        le32_to_cpu(sb->bitmap_block_bits) != DCORR_BITMAP_BLOCK_BITS ||
        le32_to_cpu(sb->columns) != DCORR_COLUMNS ||
        le32_to_cpu(sb->parity_columns) != DCORR_PARITY_COLUMNS ||
        le64_to_cpu(sb->header_sectors) != DCORR_GROUP_HEADER_SECTORS)
        return "parameters other than those of version 1";
    size = le64_to_cpu(sb->group_sectors);
    if (!dcorr_group_size_valid(size))
        return "a size of a group not in the list";
    if (group_sectors && size != group_sectors)
        return "a size of a group other than the one of its place";
    if (le64_to_cpu(sb->lower_sectors) != lower_sectors)
        return "formatted for a device of another size";
    if (dcorr_layout_compute(lower_sectors, size, layout))
        return "too few groups for its size of a group";
    if (le64_to_cpu(sb->capacity) != layout->capacity ||
        le64_to_cpu(sb->groups) != layout->groups ||
        le64_to_cpu(sb->group_regions) != layout->group_regions ||
        le64_to_cpu(sb->last_group_regions) != layout->last_group_regions ||
        le64_to_cpu(sb->bitmap_blocks) != layout->bitmap_blocks)
        return "a layout other than the one computed";
    return NULL;
}

/// @brief Whether two valid copies agree in everything but the number of their group and their CRC
static bool superblock_same(const struct dcorr_superblock *a, const struct dcorr_superblock *b)
{
    const size_t group = offsetof(struct dcorr_superblock, group);
    const size_t generation = offsetof(struct dcorr_superblock, generation);
    const size_t crc = offsetof(struct dcorr_superblock, crc);

    return !memcmp(a, b, group) &&
           !memcmp((const u8 *)a + generation, (const u8 *)b + generation, crc - generation) &&
           !memcmp((const u8 *)a + SUPERBLOCK_CRC_END, (const u8 *)b + SUPERBLOCK_CRC_END,
                   DCORR_SUPERBLOCK_BYTES - SUPERBLOCK_CRC_END);
}

/// @brief Reads the copy of the superblock in the header of group 1 when the size of a group is not known
/// @details
/// Group 1 starts at the size of a group, so each size of the list is tried in
/// turn, from the smallest, and the first valid copy is taken: it records the
/// size that put it there.
/// @return NULL if a valid copy was found and read into sb, or why none was
static const char *superblock_probe(struct block_device *bdev, struct dcorr_superblock *sb,
                                    struct dcorr_layout *layout)
{
    u64 lower_sectors = bdev_nr_sectors(bdev);

    for (u64 size = DCORR_MIN_GROUP_SECTORS; size <= DCORR_MAX_GROUP_SECTORS; size <<= 1)
    {
        if (size + DCORR_SUPERBLOCK_SECTORS > lower_sectors)
            break;
        if (bdev_rw_virt(bdev, size, sb, DCORR_SUPERBLOCK_BYTES, REQ_OP_READ))
            continue;
        if (!superblock_check(sb, 1, lower_sectors, size, layout))
            return NULL;
    }
    return "no valid copy at the start of group 1 for any size of a group";
}

/// @brief Reads the copies of the superblock in groups 0 and 1 and takes the valid one with the larger generation
/// @details
/// The copy of group 0 gives the size of a group, and with it where group 1
/// starts. If it is not valid, the start of group 1 is probed for each size of
/// the list, see superblock_probe. Each copy is checked against the layout of
/// the size of a group it records. A copy that is not valid is named in the
/// kernel log; with neither valid the device is refused. Two valid copies of
/// the same generation should be equal, as the driver never writes the
/// superblock; if they are not, the one of group 0 is taken, with a warning.
///
/// The copies in the other groups are checked when the bitmap is read, see
/// superblock_verify.
///
/// Expected execution context - the constructor of the target, may sleep.
/// @param bdev  The device below
/// @param info  What the driver takes from it, filled on success
/// @param error The reason for the table, set on failure
/// @return 0, or a negative error code
int superblock_read(struct block_device *bdev, struct superblock_info *info, char **error)
{
    struct dcorr_superblock *sb[SUPERBLOCK_COPIES] = {};
    struct dcorr_layout layout[SUPERBLOCK_COPIES];
    const char *reason[SUPERBLOCK_COPIES];
    u64 lower_sectors = bdev_nr_sectors(bdev);
    unsigned int copy, chosen;
    int r = 0;

    for (copy = 0; copy < SUPERBLOCK_COPIES; copy++)
    {
        sb[copy] = kmalloc(DCORR_SUPERBLOCK_BYTES, GFP_KERNEL);
        if (!sb[copy])
        {
            *error = "Cannot allocate the superblock";
            r = -ENOMEM;
            goto out;
        }
    }

    if (bdev_rw_virt(bdev, 0, sb[0], DCORR_SUPERBLOCK_BYTES, REQ_OP_READ))
        reason[0] = "read failed";
    else
        reason[0] = superblock_check(sb[0], 0, lower_sectors, 0, &layout[0]);

    if (reason[0])
        reason[1] = superblock_probe(bdev, sb[1], &layout[1]);
    else if (bdev_rw_virt(bdev, layout[0].group_sectors, sb[1], DCORR_SUPERBLOCK_BYTES, REQ_OP_READ))
        reason[1] = "read failed";
    else
        reason[1] = superblock_check(sb[1], 1, lower_sectors, layout[0].group_sectors, &layout[1]);

    if (reason[0] && reason[1])
    {
        DM_ERR("no valid superblock: group 0: %s, group 1: %s\n", reason[0], reason[1]);
        *error = "No valid superblock on the device below, format it with dcorrsetup";
        r = -EINVAL;
        goto out;
    }

    if (reason[0] || reason[1])
        chosen = reason[0] ? 1 : 0;
    else
        chosen = le64_to_cpu(sb[1]->generation) > le64_to_cpu(sb[0]->generation) ? 1 : 0;

    if (reason[1 - chosen])
        DM_WARN("the superblock of group %u is not valid: %s\n", 1 - chosen, reason[1 - chosen]);
    else if (sb[0]->generation == sb[1]->generation && !superblock_same(sb[0], sb[1]))
        DM_WARN("the superblocks of groups 0 and 1 differ in the same generation, taking group 0\n");

    info->layout = layout[chosen];
    memcpy(info->uuid, sb[chosen]->uuid, sizeof(info->uuid));
    memcpy(info->salt, sb[chosen]->salt, sizeof(info->salt));
    info->group = chosen;
    info->generation = le64_to_cpu(sb[chosen]->generation);
    DM_INFO("superblock of group %u, generation %llu, groups of %llu sectors\n", chosen,
            (unsigned long long)info->generation, (unsigned long long)info->layout.group_sectors);

out:
    for (copy = 0; copy < SUPERBLOCK_COPIES; copy++)
        kfree(sb[copy]);
    return r;
}

/// @brief Checks the copy of the superblock of another group against the one the driver took
/// @details
/// The copy must be valid for its place and the size of the device below, and
/// belong to the same device and generation: the same UUID, salt and generation.
/// @param sb    The copy as read
/// @param group The group whose header it was read from
/// @param info  What superblock_read took
/// @return NULL if the copy is valid and the same, or why it is not
const char *superblock_verify(const struct dcorr_superblock *sb, unsigned int group,
                              const struct superblock_info *info)
{
    struct dcorr_layout layout;
    const char *reason;

    reason = superblock_check(sb, group, info->layout.lower_sectors, info->layout.group_sectors, &layout);
    if (reason)
        return reason;
    if (memcmp(sb->uuid, info->uuid, sizeof(info->uuid)) || memcmp(sb->salt, info->salt, sizeof(info->salt)))
        return "the copy of another device";
    if (le64_to_cpu(sb->generation) != info->generation)
        return "another generation";
    return NULL;
}

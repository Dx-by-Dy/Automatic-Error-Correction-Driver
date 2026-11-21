#include <linux/bitmap.h>
#include <linux/device-mapper.h>
#include <linux/crc64.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "written.h"
#include "log.h"

/// @brief The CRC of a block of a bitmap: over the salt, then over the block as if its field crc were zero
static u64 written_crc(const struct dcorr_bitmap_block *block, const u8 *salt)
{
    static const u8 zero[sizeof_field(struct dcorr_bitmap_block, crc)];
    u64 crc;

    crc = crc64_be(0, salt, sizeof_field(struct superblock_info, salt));
    crc = crc64_be(crc, zero, sizeof(zero));
    return crc64_be(crc, (const u8 *)block + sizeof(zero), DCORR_BITMAP_BLOCK_BYTES - sizeof(zero));
}

/// @brief Whether a copy of a block is valid for its place: its CRC, its group, its index and its role
static bool written_block_valid(const struct written_map *map, const struct dcorr_bitmap_block *block,
                                u64 group, unsigned int index, enum dcorr_bitmap_role role)
{
    return le64_to_cpu(block->crc) == written_crc(block, map->sb->salt) &&
           le64_to_cpu(block->group) == group && le32_to_cpu(block->index) == index &&
           le32_to_cpu(block->role) == role;
}

static struct dcorr_bitmap_block *written_block(const struct written_map *map, u64 idx)
{
    return page_address(map->pages[idx]);
}

/// @brief Where a copy of a block lies on the lower device
static sector_t written_block_sector(const struct written_map *map, u64 idx, enum dcorr_bitmap_role role)
{
    const struct dcorr_layout *layout = &map->sb->layout;
    u64 group = idx / layout->bitmap_blocks;
    u64 index = idx % layout->bitmap_blocks;

    if (role == DCORR_BITMAP_LEAD)
        return dcorr_group_start(layout, group) + DCORR_LEAD_BITMAP_OFFSET + index * DCORR_BITMAP_BLOCK_SECTORS;
    return dcorr_group_start(layout, (group + 1) % layout->groups) + dcorr_trail_bitmap_offset(layout) +
           index * DCORR_BITMAP_BLOCK_SECTORS;
}

/// @brief The block of the chunk of a logical sector, and its bit in the block
static u64 written_locate(const struct written_map *map, sector_t sector, unsigned int *bit)
{
    const struct dcorr_layout *layout = &map->sb->layout;
    u64 slot = sector % layout->group_capacity / DCORR_CHUNK_SECTORS;

    *bit = slot % DCORR_BITMAP_BLOCK_BITS;
    return sector / layout->group_capacity * layout->bitmap_blocks + slot / DCORR_BITMAP_BLOCK_BITS;
}

/// @brief Whether the chunk of a logical sector has been written back since the format
/// @details Expected execution context - any; the data cache calls it under its lock.
bool written_test(struct written_map *map, sector_t sector)
{
    unsigned int bit;
    u64 idx = written_locate(map, sector, &bit);

    return test_bit_le(bit, written_block(map, idx)->bits);
}

/// @brief Records that the chunk of a logical sector has been written back, for the next sync
/// @details Expected execution context - the completion of a write back, under the lock of the data cache.
void written_set(struct written_map *map, sector_t sector)
{
    unsigned int bit;
    u64 idx = written_locate(map, sector, &bit);
    struct dcorr_bitmap_block *block = written_block(map, idx);

    if (test_bit_le(bit, block->bits))
        return;
    set_bit_le(bit, block->bits);
    set_bit(idx, map->dirty);
}

/// @brief Clears the bits of whole chunks from a logical sector on, up to the end of its block of the bitmap
/// @details
/// The chunks of a group are consecutive slots of its data columns, so a run
/// of chunks within one block is a run of bits. Clears at most chunks bits;
/// the caller goes on from the sector after them.
///
/// Expected execution context - the worker of the data cache, under its lock,
/// so that no sync writes the block meanwhile.
/// @param map    The bitmap
/// @param sector The first logical sector of a chunk
/// @param chunks How many chunks are left to clear
/// @param done   Set to how many chunks this call covered, at least 1
/// @return Whether a bit was set before
bool written_clear(struct written_map *map, sector_t sector, u64 chunks, u64 *done)
{
    const struct dcorr_layout *layout = &map->sb->layout;
    unsigned int bit;
    u64 idx = written_locate(map, sector, &bit);
    struct dcorr_bitmap_block *block = written_block(map, idx);
    u64 group_left = (layout->group_capacity - sector % layout->group_capacity) / DCORR_CHUNK_SECTORS;
    bool cleared = false;

    *done = min3(chunks, (u64)(DCORR_BITMAP_BLOCK_BITS - bit), group_left);
    for (u64 i = 0; i < *done; i++)
    {
        if (test_and_clear_bit_le(bit + i, block->bits))
            cleared = true;
    }
    if (cleared)
        set_bit(idx, map->dirty);

    return cleared;
}

/// @brief Whether a range of logical sectors touches a block invalid in both copies
/// @details
/// The blocks of the range are numbered in order, so the blocks between its
/// first and its last are checked; one between them that covers only parity
/// slots is checked too, which errs on the side of refusing.
bool written_range_read_only(struct written_map *map, sector_t sector, sector_t sectors)
{
    unsigned int bit;
    u64 first = written_locate(map, sector, &bit);
    u64 last = written_locate(map, sector + sectors - 1, &bit);

    return find_next_bit(map->read_only, last + 1, first) <= last;
}

/// @brief Takes a copy of a block read from the trailing place into RAM
static void written_take(struct written_map *map, u64 idx, struct page *page)
{
    memcpy(written_block(map, idx), page_address(page), DCORR_BITMAP_BLOCK_BYTES);
}

/// @brief Chooses the copy of each block of a group, once both have been read
/// @details
/// The leading copy is in RAM already, valid or not, as lead_ok says; the
/// trailing one is in trail, valid or not, as trail_read says it read. Of two
/// valid copies the one with the larger generation is taken. A block with one
/// valid copy is marked dirty, the other copy to be written first, so that the
/// next sync repairs it; a block with none is read only, with every bit set.
static void written_choose(struct written_map *map, u64 group, const unsigned long *lead_ok,
                           struct page **trail, const unsigned long *trail_read)
{
    u64 blocks = map->sb->layout.bitmap_blocks;

    for (unsigned int i = 0; i < blocks; i++)
    {
        u64 idx = group * blocks + i;
        struct dcorr_bitmap_block *lead = written_block(map, idx);
        const struct dcorr_bitmap_block *other = page_address(trail[i]);
        bool lv = test_bit(idx, lead_ok);
        bool tv = test_bit(i, trail_read) && written_block_valid(map, other, group, i, DCORR_BITMAP_TRAIL);

        if (lv && tv)
        {
            if (le64_to_cpu(other->generation) > le64_to_cpu(lead->generation))
                written_take(map, idx, trail[i]);
            else if (other->generation == lead->generation && memcmp(other->bits, lead->bits, sizeof(lead->bits)))
                DCORR_DEV_WARN(map->ti, "block %u of the bitmap of group %llu: copies of one generation differ, taking the leading\n",
                               i, (unsigned long long)group);
            continue;
        }

        if (!lv && !tv)
        {
            memset(lead->bits, 0xff, sizeof(lead->bits));
            set_bit(idx, map->read_only);
            atomic64_inc(&map->stats->read_only_blocks);
            dcorr_error(map->ti);
            DCORR_DEV_ERR(map->ti, "block %u of the bitmap of group %llu is invalid in both copies, its chunks are read only\n",
                          i, (unsigned long long)group);
            continue;
        }

        if (tv)
            written_take(map, idx, trail[i]);
        else
            set_bit(idx, map->trail_first);
        if (map->writable)
            set_bit(idx, map->dirty);
        atomic64_inc(&map->stats->single_blocks);
        dcorr_error(map->ti);
        DCORR_DEV_WARN(map->ti, "block %u of the bitmap of group %llu has only its %s copy valid, the next sync writes the other\n",
                       i, (unsigned long long)group, tv ? "trailing" : "leading");
    }
}

/// @brief Reads the used part of the header of a group: its superblock, its leading bitmap, the trailing one
/// of the group before
/// @details
/// The leading blocks go straight into RAM, the rest into the pages given. One
/// request for all; if it fails, one for each block, and those that fail are
/// marked as not read.
/// @param read Set for each piece that read: bit 0 the superblock, 1 + i the leading block i,
///             1 + blocks + i the trailing block i
static void written_read_header(struct written_map *map, u64 group, struct page *sb_page, struct page **trail,
                                struct bio_vec *bvecs, unsigned long *read)
{
    const struct dcorr_layout *layout = &map->sb->layout;
    u64 blocks = layout->bitmap_blocks;
    unsigned int pieces = 1 + 2 * blocks;
    sector_t start = dcorr_group_start(layout, group);
    struct bio bio;
    int r;

    bio_init(&bio, map->bdev, bvecs, pieces, REQ_OP_READ);
    bio.bi_iter.bi_sector = start;
    for (unsigned int p = 0; p < pieces; p++)
    {
        struct page *page = !p ? sb_page : p <= blocks ? map->pages[group * blocks + p - 1] : trail[p - 1 - blocks];

        __bio_add_page(&bio, page, DCORR_BITMAP_BLOCK_BYTES, 0);
    }
    r = submit_bio_wait(&bio);
    bio_uninit(&bio);

    if (!r)
    {
        bitmap_fill(read, pieces);
        return;
    }

    bitmap_zero(read, pieces);
    for (unsigned int p = 0; p < pieces; p++)
    {
        struct page *page = !p ? sb_page : p <= blocks ? map->pages[group * blocks + p - 1] : trail[p - 1 - blocks];

        if (!bdev_rw_virt(map->bdev, start + p * DCORR_BITMAP_BLOCK_SECTORS, page_address(page),
                          DCORR_BITMAP_BLOCK_BYTES, REQ_OP_READ))
            __set_bit(p, read);
    }
    dcorr_error(map->ti);
    DCORR_DEV_ERR(map->ti, "the header of group %llu failed to read, err=%d, %u of its %u blocks fail\n",
                  (unsigned long long)group, r, pieces - bitmap_weight(read, pieces), pieces);
}

/// @brief Reads the bitmap of every group, and checks the superblock of every group but 0 and 1
/// @details
/// Expected execution context - preresume, may sleep.
/// @return 0, or -ENOMEM
static int written_load(struct written_map *map)
{
    const struct dcorr_layout *layout = &map->sb->layout;
    u64 blocks = layout->bitmap_blocks;
    unsigned int pieces = 1 + 2 * blocks;
    struct page **trail = kcalloc(2 * blocks, sizeof(*trail), GFP_KERNEL);
    struct page **first_trail;
    struct bio_vec *bvecs = kcalloc(pieces, sizeof(*bvecs), GFP_KERNEL);
    unsigned long *read = bitmap_zalloc(pieces, GFP_KERNEL);
    unsigned long *first_read = bitmap_zalloc(blocks, GFP_KERNEL);
    unsigned long *trail_read = bitmap_zalloc(blocks, GFP_KERNEL);
    unsigned long *lead_ok = bitmap_zalloc(map->nr_blocks, GFP_KERNEL);
    struct page *sb_page = alloc_page(GFP_KERNEL);
    ktime_t begin = ktime_get();
    int r = -ENOMEM;

    if (!trail || !bvecs || !read || !first_read || !trail_read || !lead_ok || !sb_page)
        goto out;
    first_trail = trail + blocks;
    for (unsigned int i = 0; i < 2 * blocks; i++)
    {
        trail[i] = alloc_page(GFP_KERNEL);
        if (!trail[i])
            goto out;
    }

    for (u64 group = 0; group < layout->groups; group++)
    {
        // The header of group 0 holds the trailing copy of the last group, chosen at the end.
        struct page **pages = group ? trail : first_trail;
        const char *reason;

        written_read_header(map, group, sb_page, pages, bvecs, read);

        if (group >= 2)
        {
            reason = test_bit(0, read) ? superblock_verify(page_address(sb_page), group, map->sb) : "read failed";
            if (reason)
            {
                atomic64_inc(&map->stats->bad_superblocks);
                dcorr_error(map->ti);
                DCORR_DEV_WARN(map->ti, "the superblock of group %llu is not valid: %s\n",
                               (unsigned long long)group,
                               reason);
            }
        }

        for (unsigned int i = 0; i < blocks; i++)
        {
            u64 idx = group * blocks + i;

            if (test_bit(1 + i, read) && written_block_valid(map, written_block(map, idx), group, i, DCORR_BITMAP_LEAD))
                __set_bit(idx, lead_ok);
            assign_bit(i, group ? trail_read : first_read, test_bit(1 + blocks + i, read));
        }

        if (group)
            written_choose(map, group - 1, lead_ok, trail, trail_read);
    }
    written_choose(map, layout->groups - 1, lead_ok, first_trail, first_read);

    DCORR_DEV_INFO(map->ti, "bitmap of %llu groups read in %lld ms\n",
                   (unsigned long long)layout->groups,
                   ktime_ms_delta(ktime_get(), begin));
    r = 0;

out:
    if (trail)
    {
        for (unsigned int i = 0; i < 2 * blocks; i++)
        {
            if (trail[i])
                __free_page(trail[i]);
        }
    }
    if (sb_page)
        __free_page(sb_page);
    bitmap_free(lead_ok);
    bitmap_free(trail_read);
    bitmap_free(first_read);
    bitmap_free(read);
    kfree(bvecs);
    kfree(trail);
    return r;
}

/// @brief Frees the bitmap
void written_destroy(struct written_map *map)
{
    if (map->pages)
    {
        for (u64 idx = 0; idx < map->nr_blocks; idx++)
        {
            if (map->pages[idx])
                __free_page(map->pages[idx]);
        }
    }
    kvfree(map->pages);
    kvfree(map->ios);
    bitmap_free(map->dirty);
    bitmap_free(map->pending);
    bitmap_free(map->trail_first);
    bitmap_free(map->read_only);
    kfree(map);
}

/// @brief Allocates the bitmap, to be read from the lower device by written_load_once
/// @details
/// Expected execution context - dcorr_ctr, may sleep.
/// @param ti       The target, for its name in the log; ti->error is set on failure
/// @param bdev     The lower device
/// @param sb       The superblock taken, which must outlive the bitmap
/// @param stats    The counters of the device
/// @param writable Whether the table may write, so that blocks with one valid copy may be repaired
/// @return The bitmap, or an ERR_PTR
struct written_map *written_create(struct dm_target *ti, struct block_device *bdev, const struct superblock_info *sb,
                                   struct dcorr_stats *stats, bool writable)
{
    struct written_map *map = kzalloc_obj(*map, GFP_KERNEL);

    if (!map)
        goto nomem;

    map->ti = ti;
    map->sb = sb;
    map->stats = stats;
    map->bdev = bdev;
    map->writable = writable;
    map->nr_blocks = sb->layout.groups * sb->layout.bitmap_blocks;
    atomic_set(&map->in_flight, 0);
    init_waitqueue_head(&map->wait);

    map->pages = kvcalloc(map->nr_blocks, sizeof(*map->pages), GFP_KERNEL);
    map->ios = kvcalloc(map->nr_blocks, sizeof(*map->ios), GFP_KERNEL);
    map->dirty = bitmap_zalloc(map->nr_blocks, GFP_KERNEL);
    map->pending = bitmap_zalloc(map->nr_blocks, GFP_KERNEL);
    map->trail_first = bitmap_zalloc(map->nr_blocks, GFP_KERNEL);
    map->read_only = bitmap_zalloc(map->nr_blocks, GFP_KERNEL);
    if (!map->pages || !map->ios || !map->dirty || !map->pending || !map->trail_first || !map->read_only)
        goto nomem_map;

    for (u64 idx = 0; idx < map->nr_blocks; idx++)
    {
        map->pages[idx] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!map->pages[idx])
            goto nomem_map;
        map->ios[idx].map = map;
    }

    return map;

nomem_map:
    written_destroy(map);
nomem:
    ti->error = "Cannot allocate the bitmap of written chunks";
    return ERR_PTR(-ENOMEM);
}

/// @brief Reads the bitmap from the lower device, on the first resume of the table only
/// @details
/// Reads the header of every group, see written_load: a block is taken from
/// its valid copy with the larger generation. Not in the constructor: on a
/// reload the constructor of the new table runs while the old one still
/// writes, and the bits it sets after that would be missed. By the first
/// resume of the new table the old one is suspended and its suspend has
/// written its bitmap. A later resume of the same table keeps the bitmap in
/// RAM, as the driver alone writes it.
///
/// Expected execution context - preresume, may sleep.
/// @return 0, or -ENOMEM, which fails the resume
int written_load_once(struct written_map *map)
{
    int r;

    if (map->loaded)
        return 0;
    r = written_load(map);
    if (r)
    {
        DCORR_DEV_ERR(map->ti, "the bitmap of written chunks cannot be read for want of memory, err=%d\n",
                      r);
        return r;
    }
    map->loaded = true;
    return 0;
}

static void written_end_io(struct bio *bio)
{
    struct written_io *io = container_of(bio, struct written_io, bio);
    struct written_map *map = io->map;

    io->error = blk_status_to_errno(bio->bi_status);
    bio_uninit(bio);
    if (atomic_dec_and_test(&map->in_flight))
        wake_up(&map->wait);
}

/// @brief Writes one copy of a block from RAM, its header rebuilt for the copy
static void written_submit(struct written_map *map, u64 idx, enum dcorr_bitmap_role role)
{
    struct dcorr_bitmap_block *block = written_block(map, idx);
    struct written_io *io = &map->ios[idx];

    block->group = cpu_to_le64(idx / map->sb->layout.bitmap_blocks);
    block->index = cpu_to_le32(idx % map->sb->layout.bitmap_blocks);
    block->role = cpu_to_le32(role);
    block->crc = cpu_to_le64(written_crc(block, map->sb->salt));

    io->error = 0;
    bio_init(&io->bio, map->bdev, &io->bvec, 1, REQ_OP_WRITE | REQ_SYNC);
    io->bio.bi_iter.bi_sector = written_block_sector(map, idx, role);
    io->bio.bi_end_io = written_end_io;
    __bio_add_page(&io->bio, map->pages[idx], DCORR_BITMAP_BLOCK_BYTES, 0);
    atomic_inc(&map->in_flight);
    submit_bio(&io->bio);
}

/// @brief The copy of a block written first: the leading one, unless the trailing one is not known to be valid
static enum dcorr_bitmap_role written_first_role(struct written_map *map, u64 idx)
{
    return test_bit(idx, map->trail_first) ? DCORR_BITMAP_TRAIL : DCORR_BITMAP_LEAD;
}

/// @brief Writes the first copy of every changed block, with the next generation, and waits for them
/// @details
/// Called by a sync of the data cache after the flush that made the data of the
/// new bits durable, with no write back in flight, so that no bit changes. The
/// caller flushes afterwards. The other copy keeps the generation before, so a
/// write torn by a crash leaves it. A block whose write failed is dirty again.
///
/// Expected execution context - the worker of the data cache, or postsuspend; may sleep.
/// @return The number of blocks written, or the error of the first write that failed
int written_write_first(struct written_map *map)
{
    unsigned long idx;
    int written = 0;
    int r = 0;

    for_each_set_bit(idx, map->dirty, map->nr_blocks)
    {
        struct dcorr_bitmap_block *block = written_block(map, idx);

        clear_bit(idx, map->dirty);
        set_bit(idx, map->pending);
        block->generation = cpu_to_le64(le64_to_cpu(block->generation) + 1);
        written_submit(map, idx, written_first_role(map, idx));
        written++;
    }
    wait_event(map->wait, !atomic_read(&map->in_flight));

    for_each_set_bit(idx, map->pending, map->nr_blocks)
    {
        if (!map->ios[idx].error)
            continue;
        if (!r)
            r = map->ios[idx].error;
        clear_bit(idx, map->pending);
        set_bit(idx, map->dirty);
        atomic64_inc(&map->stats->bitmap_write_errors);
        dcorr_error(map->ti);
        DCORR_DEV_ERR_LIMIT(map->ti, "block %llu of the bitmap of group %llu failed to write, err=%d\n",
                            (unsigned long long)(idx % map->sb->layout.bitmap_blocks),
                            (unsigned long long)(idx / map->sb->layout.bitmap_blocks), map->ios[idx].error);
    }

    return r ? r : written;
}

/// @brief Writes the other copy of every block written by written_write_first, and waits for them
/// @details
/// Called once the lower device has flushed the first copies. A copy that
/// fails is counted, and is written first with the next change of its block.
/// The caller flushes afterwards.
///
/// Expected execution context - the worker of the data cache, or postsuspend; may sleep.
void written_write_second(struct written_map *map)
{
    unsigned long idx;

    for_each_set_bit(idx, map->pending, map->nr_blocks)
    {
        enum dcorr_bitmap_role role = written_first_role(map, idx) == DCORR_BITMAP_LEAD ? DCORR_BITMAP_TRAIL
                                                                                         : DCORR_BITMAP_LEAD;

        written_submit(map, idx, role);
    }
    wait_event(map->wait, !atomic_read(&map->in_flight));

    for_each_set_bit(idx, map->pending, map->nr_blocks)
    {
        struct written_io *io = &map->ios[idx];
        bool trail = le32_to_cpu(written_block(map, idx)->role) == DCORR_BITMAP_TRAIL;

        clear_bit(idx, map->pending);
        assign_bit(idx, map->trail_first, io->error && trail);
        if (!io->error)
            continue;
        atomic64_inc(&map->stats->bitmap_write_errors);
        dcorr_error(map->ti);
        DCORR_DEV_ERR_LIMIT(map->ti, "%s copy of block %llu of the bitmap of group %llu failed to write, err=%d\n",
                            trail ? "trailing" : "leading", (unsigned long long)(idx % map->sb->layout.bitmap_blocks),
                            (unsigned long long)(idx / map->sb->layout.bitmap_blocks), io->error);
    }
}

/// @brief Makes the blocks written by written_write_first dirty again, when the flush after them failed
void written_abort(struct written_map *map)
{
    unsigned long idx;

    for_each_set_bit(idx, map->pending, map->nr_blocks)
    {
        clear_bit(idx, map->pending);
        set_bit(idx, map->dirty);
    }
}

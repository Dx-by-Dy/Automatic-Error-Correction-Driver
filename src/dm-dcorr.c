#include <linux/module.h>

#include "dm-dcorr.h"
#include "cache.h"
#include "layout.h"
#include "log.h"
#include "metadata.h"
#include "trn_p_rq.h"
#include "written.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("Device mapper target that detects damaged data with a CRC64 per sector");

/// @brief Refuses a write, a discard or a write zeroes that touches a read only range
/// @details
/// Such a range is a block of the bitmap invalid in both copies: whether its
/// chunks were ever written is not known, so nothing may change them.
/// @return Whether the bio is refused; it is counted and logged then
static bool dcorr_refused(struct dm_target *ti, struct bio *bio)
{
    struct dcorr_ctx *dc = ti->private;

    if (!written_range_read_only(dc->written, bio->bi_iter.bi_sector, bio_sectors(bio)))
        return false;

    atomic64_inc(&dc->stats.refused_writes);
    DCORR_DEV_ERR_LIMIT(ti, "%s at sector %llu refused: it touches a block of the bitmap invalid in both copies\n",
                        bio_op(bio) == REQ_OP_WRITE ? "write" : bio_op(bio) == REQ_OP_DISCARD ? "discard" : "write zeroes",
                        (unsigned long long)bio->bi_iter.bi_sector);
    return true;
}

/// @brief Sends a read that the cache does not serve to the lower device
/// @details
/// The read is in the tree of reads of the cache by now, see cache_read. It
/// takes a place among the parts in flight, waiting if MAX_PARTS_IN_FLIGHT are
/// in flight, and the part in its per-bio data is submitted from transform_wq.
static void dcorr_map_read(struct dcorr_ctx *dc, struct trn_p_rq *part, struct bio *bio)
{
    if (down_trylock(&dc->parts_in_flight))
    {
        atomic64_inc(&dc->stats.map_waits);
        down(&dc->parts_in_flight);
    }

    trn_p_rq_init(part, bio, dc, TRANSFORM_READ, NULL);
    queue_work(dc->transform_wq, &part->submit_work);
}

/// @brief Handles incoming bio requests
/// @details
/// Called by the DM subsystem for each incoming bio. DM splits requests at chunk
/// boundaries, so the bio stays within one chunk.
///
/// An empty flush goes to the cache, which writes back everything dirty and
/// flushes the lower device before completing it. Device mapper sends one for
/// each REQ_PREFLUSH, and the data of such a bio comes afterwards without the flag.
///
/// A write goes into the cache, see cache_write, unless its chunk lies in a
/// block of the bitmap invalid in both copies: such a range is read only, and
/// the write fails. A read takes from the cache what it holds, and gives zeros
/// for a chunk never written, see cache_read; the rest is put into the tree of
/// reads of the cache and goes to the lower device, see dcorr_map_read.
/// It waits if MAX_PARTS_IN_FLIGHT parts are in flight, which blocks the
/// submitter as a full request queue of a disk would, and while the metadata
/// area of its region is read, see metadata_get. Waiting belongs here and in
/// the worker of the cache, never in transform_wq: its workers run the
/// complete_work that gives places back. dcorr_map never waits for a lower bio of
/// its own, which stays on current->bio_list until it returns: the metadata
/// area is read by a worker of the metadata cache.
///
/// A discard is not split at chunks, only by the limits of the queue, see
/// dcorr_io_hints. Its whole chunks go to the cache, which clears their bits in
/// the bitmap of written chunks, so they read as zeros; the partial chunks at
/// its ends are left as they are, and one with no whole chunk completes at
/// once. It is refused if it touches a read only range, and never passed down.
///
/// A write zeroes is not split at chunks either: its partial chunks are
/// written as zeros through the cache, its whole chunks cleared as by a
/// discard, see cache_write_zeroes. Device mapper sends it only while the
/// lower device has write zeroes, see dcorr_io_hints. It is refused if it
/// touches a read only range.
///
/// Other operations are refused: device mapper sends none of them, as the
/// target does not offer them, and remapping one would bypass the CRC.
/// @param ti  DM target
/// @param bio Incoming bio request
/// @return DM_MAPIO_SUBMITTED for READ, WRITE, DISCARD, WRITE_ZEROES and an empty flush.
///         DM_MAPIO_KILL for anything else.
static int dcorr_map(struct dm_target *ti, struct bio *bio)
{
    struct dcorr_ctx *dc = ti->private;
    struct trn_p_rq *part = dm_per_bio_data(bio, ti->per_io_data_size);

    DCORR_DEBUG("bio=%p op=%u sector=%llu size=%u\n", bio, bio_op(bio),
                (unsigned long long)bio->bi_iter.bi_sector, bio->bi_iter.bi_size);

    if (bio->bi_opf & REQ_PREFLUSH)
    {
        if (WARN_ON_ONCE(bio_has_data(bio)))
            return DM_MAPIO_KILL;
        cache_flush(dc->cache, bio);
        return DM_MAPIO_SUBMITTED;
    }

    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        if (!cache_read(dc->cache, bio, &part->lower_read))
            dcorr_map_read(dc, part, bio);
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_WRITE:
        if (dcorr_refused(ti, bio))
            return DM_MAPIO_KILL;
        cache_write(dc->cache, bio);
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_DISCARD:
        atomic64_inc(&dc->stats.discards);
        if (DIV_ROUND_UP(bio->bi_iter.bi_sector, DCORR_CHUNK_SECTORS) >= bio_end_sector(bio) / DCORR_CHUNK_SECTORS)
        {
            bio_endio(bio);
            return DM_MAPIO_SUBMITTED;
        }
        if (dcorr_refused(ti, bio))
            return DM_MAPIO_KILL;
        cache_discard(dc->cache, bio);
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_WRITE_ZEROES:
        if (dcorr_refused(ti, bio))
            return DM_MAPIO_KILL;
        cache_write_zeroes(dc->cache, bio);
        return DM_MAPIO_SUBMITTED;

    default:
        DCORR_DEV_ERR_LIMIT(ti, "unsupported bio op=%u\n", bio_op(bio));
        return DM_MAPIO_KILL;
    }
}

/// @brief Creates the target
/// @details
/// Expects a single argument argv[0] — path to the lower device, formatted
/// by dcorrsetup. The superblock gives the layout, and the length of the target
/// must be the capacity it records, as dcorrsetup table prints it.
///
/// Sequentially allocates and initializes all resources: work queue,
/// lower device, the superblock, the bitmap of written chunks, which
/// reads the header of every group, the metadata cache and the data cache.
///
/// On error at any stage, frees all previously allocated resources
/// in reverse order of allocation.
/// @param ti   DM target
/// @param argc Argument count
/// @param argv Arguments: argv[0] — path to lower device
/// @return 0 on success, negative error code on failure
static int dcorr_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dcorr_ctx *dc;
    int r;

    if (argc != 1)
    {
        ti->error = "Invalid argument count: expected <device>";
        DCORR_DEV_ERR(ti, "expected 1 argument, got %u\n", argc);
        return -EINVAL;
    }

    DCORR_DEBUG("argc=%u, argv[0]=%s\n", argc, argv[0]);

    dc = kzalloc_obj(*dc, GFP_KERNEL);
    if (!dc)
    {
        ti->error = "Cannot allocate the context of the target";
        DCORR_DEV_ERR(ti, "kzalloc of the context failed\n");
        return -ENOMEM;
    }

    dc->transform_wq = alloc_workqueue("transformation_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!dc->transform_wq)
    {
        ti->error = "alloc_workqueue failed";
        DCORR_DEV_ERR(ti, "alloc_workqueue failed\n");
        r = -ENOMEM;
        goto err_free;
    }

    sema_init(&dc->parts_in_flight, MAX_PARTS_IN_FLIGHT);
    dc->ti = ti;
    INIT_WORK(&dc->event_work, dcorr_event_work);

    r = dm_set_target_max_io_len(ti, DCORR_CHUNK_SECTORS);
    if (r)
    {
        ti->error = "dm_set_target_max_io_len failed";
        DCORR_DEV_ERR(ti, "dm_set_target_max_io_len failed, err=%d\n", r);
        goto err_destroy_wq;
    }
    ti->per_io_data_size = sizeof(struct trn_p_rq);
    ti->num_flush_bios = 1;
    ti->flush_supported = true;
    ti->num_discard_bios = 1;
    ti->discards_supported = true;
    ti->num_write_zeroes_bios = 1;

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dc->lower);
    if (r)
    {
        ti->error = "dm_get_device failed";
        DCORR_DEV_ERR(ti, "dm_get_device failed, dev=%s err=%d\n", argv[0], r);
        goto err_destroy_wq;
    }

    if (bdev_logical_block_size(dc->lower->bdev) != SECTOR_SIZE)
    {
        ti->error = "The lower device must have logical blocks of 512 bytes";
        DCORR_DEV_ERR(ti, "the lower device has logical blocks of %u bytes, the metadata is written in sectors of 512\n",
                      bdev_logical_block_size(dc->lower->bdev));
        r = -EINVAL;
        goto err_put_device;
    }

    r = superblock_read(ti, dc->lower->bdev, &dc->sb);
    if (r)
        goto err_put_device;

    if (ti->len != dc->sb.layout.capacity)
    {
        ti->error = "The length must be the capacity in the superblock, see dcorrsetup table";
        DCORR_DEV_ERR(ti, "length %llu, the superblock gives %llu\n", (unsigned long long)ti->len,
                      (unsigned long long)dc->sb.layout.capacity);
        r = -EINVAL;
        goto err_put_device;
    }

    dc->written = written_create(ti, dc->lower->bdev, &dc->sb, &dc->stats,
                                 dm_table_get_mode(ti->table) & BLK_OPEN_WRITE);
    if (IS_ERR(dc->written))
    {
        r = PTR_ERR(dc->written);
        DCORR_DEV_ERR(ti, "written_create failed, err=%d\n", r);
        goto err_put_device;
    }

    dc->metadata = metadata_cache_create(ti, dc->lower->bdev, &dc->sb, &dc->stats, dc->written);
    if (IS_ERR(dc->metadata))
    {
        ti->error = "metadata cache alloc failed";
        r = PTR_ERR(dc->metadata);
        DCORR_DEV_ERR(ti, "metadata_cache_create failed, err=%d\n", r);
        goto err_destroy_written;
    }

    dc->cache = cache_create(dc);
    if (IS_ERR(dc->cache))
    {
        ti->error = "cache alloc failed";
        r = PTR_ERR(dc->cache);
        DCORR_DEV_ERR(ti, "cache_create failed, err=%d\n", r);
        goto err_destroy_metadata;
    }

    ti->private = dc;

    DCORR_DEV_INFO(ti, "mapped on dev=%s, disk capacity=%llu sec, available capacity=%llu sec\n",
                   argv[0],
                   (unsigned long long)get_capacity(dc->lower->bdev->bd_disk),
                   (unsigned long long)ti->len);

    return 0;

err_destroy_metadata:
    metadata_cache_destroy(dc->metadata);
err_destroy_written:
    written_destroy(dc->written);
err_put_device:
    dm_put_device(ti, dc->lower);
err_destroy_wq:
    destroy_workqueue(dc->transform_wq);
err_free:
    kfree(dc);
    return r;
}

/// @brief Destroys the target and frees all resources
/// @details
/// Before destroying the work queue, waits for completion of all
/// current work via flush_workqueue to ensure no resource access
/// after their release.
/// @param ti DM target
static void dcorr_dtr(struct dm_target *ti)
{
    struct dcorr_ctx *dc = ti->private;

    DCORR_DEBUG("dc=%p\n", dc);

    cancel_work_sync(&dc->event_work);
    cache_destroy(dc->cache);
    flush_workqueue(dc->transform_wq);
    destroy_workqueue(dc->transform_wq);
    metadata_cache_destroy(dc->metadata);
    written_destroy(dc->written);
    dm_put_device(ti, dc->lower);
    kfree(dc);
}

/// @brief Writes back the cache once device mapper has no bio of the device in flight
/// @details
/// Device mapper calls it before a table is replaced or destroyed, so nothing
/// written is left behind in the cache, but chunks whose write back fails.
/// Then forgets the metadata in RAM, as the lower device may change before
/// the device is resumed. The bitmap stays: the driver alone writes it, and
/// the suspend has written it out.
/// @param ti DM target
static void dcorr_postsuspend(struct dm_target *ti)
{
    struct dcorr_ctx *dc = ti->private;

    cache_suspend(dc->cache);
    metadata_drop(dc->metadata);
}

/// @brief Reads the bitmap of written chunks on the first resume of the table
/// @details
/// See written_load_once: on a reload the old table is suspended by now.
/// @param ti DM target
/// @return 0, or an error that fails the resume
static int dcorr_preresume(struct dm_target *ti)
{
    struct dcorr_ctx *dc = ti->private;

    return written_load_once(dc->written);
}

/// @brief Lets the cache write back by age again
/// @param ti DM target
static void dcorr_resume(struct dm_target *ti)
{
    struct dcorr_ctx *dc = ti->private;

    cache_resume(dc->cache);
}

/// @brief Reports the state of the target to dmsetup
/// @details
/// STATUSTYPE_INFO (dmsetup status) gives the counters of struct dcorr_stats
/// and the numbers of dirty and failed entries of the cache, positional, in
/// the order and with the meaning that "Interface" in docs/en/ARCHITECTURE.md
/// lists; a new counter is added at the end. STATUSTYPE_TABLE (dmsetup table)
/// gives the lower device as major:minor, so that the line loads again.
/// STATUSTYPE_IMA gives nothing yet.
/// @param ti           DM target
/// @param type         What to report
/// @param status_flags Flags of the request, unused
/// @param result       Buffer for the text
/// @param maxlen       Size of the buffer
static void dcorr_status(struct dm_target *ti, status_type_t type,
                         unsigned int status_flags, char *result, unsigned int maxlen)
{
    struct dcorr_ctx *dc = ti->private;
    struct dcorr_stats *stats = &dc->stats;
    unsigned long dirty, failed;
    unsigned int sz = 0;

    switch (type)
    {
    case STATUSTYPE_INFO:
        cache_counters(dc->cache, &dirty, &failed);
        DMEMIT("%llu %llu %llu %llu %lu %lu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
               (unsigned long long)atomic64_read(&stats->map_waits),
               (unsigned long long)atomic64_read(&stats->free_waits),
               (unsigned long long)atomic64_read(&stats->busy_waits),
               (unsigned long long)atomic64_read(&stats->read_waits),
               dirty, failed,
               (unsigned long long)atomic64_read(&stats->metadata_loads),
               (unsigned long long)atomic64_read(&stats->metadata_waits),
               (unsigned long long)atomic64_read(&stats->trail_errors),
               (unsigned long long)atomic64_read(&stats->crowded_flushes),
               (unsigned long long)atomic64_read(&stats->barriers),
               (unsigned long long)atomic64_read(&stats->settle_reads),
               (unsigned long long)atomic64_read(&stats->settle_mismatches),
               (unsigned long long)atomic64_read(&stats->unwritten_reads),
               (unsigned long long)atomic64_read(&stats->read_only_blocks),
               (unsigned long long)atomic64_read(&stats->single_blocks),
               (unsigned long long)atomic64_read(&stats->bad_superblocks),
               (unsigned long long)atomic64_read(&stats->bitmap_write_errors),
               (unsigned long long)atomic64_read(&stats->refused_writes),
               (unsigned long long)atomic64_read(&stats->discards),
               (unsigned long long)atomic64_read(&stats->discarded_chunks),
               (unsigned long long)atomic64_read(&stats->read_errors),
               (unsigned long long)atomic64_read(&stats->crc_mismatches),
               (unsigned long long)atomic64_read(&stats->write_errors),
               (unsigned long long)atomic64_read(&stats->metadata_read_errors),
               (unsigned long long)atomic64_read(&stats->flush_errors));
        break;
    case STATUSTYPE_TABLE:
        DMEMIT("%s", dc->lower->name);
        break;
    case STATUSTYPE_IMA:
        result[0] = '\0';
        break;
    }
}

/// @brief Gives device mapper the lower device, the part of it the layout uses
/// @details
/// Device mapper stacks the limits of the lower device into those of the
/// target through it, before dcorr_io_hints, checks that the area lies on the
/// device, and offers write zeroes only if the lower device has it.
static int dcorr_iterate_devices(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
    struct dcorr_ctx *dc = ti->private;

    return fn(ti, dc->lower, 0, dc->sb.layout.lower_sectors, data);
}

/// @brief Sets the limits of the queue the target needs, over those of the lower device
/// @details
/// What the target does itself replaces what it took from the lower device:
/// - a chunk of 4 KiB is the smallest write that does not make the cache
///   merge, and the unit of the CRC work, so it is the physical block and the
///   minimal I/O, unless the lower device has larger ones; the optimal I/O and
///   the alignment of the lower device say nothing of the layout on top;
/// - discards in whole chunks, of any length: device mapper does not split
///   them at max_io_len, only the block layer by these limits; they are not
///   passed down, so whatever the lower device allows does not matter;
/// - write zeroes of any length, carried out in the cache, see
///   cache_write_zeroes; device mapper turns it off when the lower device has
///   none, as then nothing says that zeroing is cheap there;
/// - no polling, as every request completes from a workqueue, and no stable
///   pages, as a write is copied into the cache.
///
/// A lower device with logical blocks other than 512 bytes is refused by the
/// constructor; a zoned one by device mapper, as the target is not zoned.
static void dcorr_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
    limits->physical_block_size = max_t(unsigned int, limits->physical_block_size, DCORR_CHUNK_SECTORS << SECTOR_SHIFT);
    limits->io_min = max_t(unsigned int, limits->io_min, DCORR_CHUNK_SECTORS << SECTOR_SHIFT);
    limits->io_opt = 0;
    limits->alignment_offset = 0;

    limits->discard_granularity = DCORR_CHUNK_SECTORS << SECTOR_SHIFT;
    limits->discard_alignment = 0;
    limits->max_hw_discard_sectors = UINT_MAX >> SECTOR_SHIFT;

    limits->max_write_zeroes_sectors = UINT_MAX >> SECTOR_SHIFT;
    limits->max_hw_wzeroes_unmap_sectors = 0;

    limits->features &= ~(BLK_FEAT_POLL | BLK_FEAT_STABLE_WRITES);
}

static struct target_type dcorr_target_type = {
    .name = "dcorr",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dcorr_ctr,
    .dtr = dcorr_dtr,
    .map = dcorr_map,
    .postsuspend = dcorr_postsuspend,
    .preresume = dcorr_preresume,
    .resume = dcorr_resume,
    .status = dcorr_status,
    .iterate_devices = dcorr_iterate_devices,
    .io_hints = dcorr_io_hints,
};

/// @brief Registers the DM target on module load
/// @return 0 on success, negative error code on failure
static int __init dcorr_init(void)
{
    int r;

    DCORR_DEBUG("loading\n");
    r = dm_register_target(&dcorr_target_type);

    if (r)
        DCORR_ERR("dm_register_target failed, err=%d\n", r);
    else
        DCORR_INFO("module loaded\n");

    return r;
}

/// @brief Exit point for the DM target on module unload
static void __exit dcorr_exit(void)
{
    DCORR_DEBUG("unloading\n");
    dm_unregister_target(&dcorr_target_type);
    DCORR_INFO("module unloaded\n");
}

module_init(dcorr_init);
module_exit(dcorr_exit);

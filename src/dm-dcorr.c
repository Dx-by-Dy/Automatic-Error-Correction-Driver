#include "dm-dcorr.h"
#include "cache.h"
#include "metadata.h"
#include "written.h"
#include "macros.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("Device mapper target that detects damaged data with a CRC64 per sector");

/// @brief Prints a message of the device, named as dmsetup names it
/// @details
/// The name is looked up for each message, so a rename shows at once; if the
/// device has none, major:minor stands for it. Called through the DM_DEV_
/// macros of macros.h, from process context with no spinlock held, as the
/// lookup takes a mutex of device mapper. That mutex guards only the name, so
/// it never waits for I/O.
void dcorr_log(struct dm_target *ti, enum dcorr_level level, const char *func, const char *fmt, ...)
{
    char name[DM_NAME_LEN];
    struct va_format vaf;
    va_list args;

    if (dm_copy_name_and_uuid(dm_table_get_md(ti->table), name, NULL))
        strscpy(name, dm_table_device_name(ti->table));

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;
    switch (level)
    {
    case DCORR_LEVEL_ERR:
        pr_err("[ERROR] " DM_MSG_PREFIX " %s [%s]: %pV", name, func, &vaf);
        break;
    case DCORR_LEVEL_WARN:
        pr_warn("[WARN] " DM_MSG_PREFIX " %s [%s]: %pV", name, func, &vaf);
        break;
    case DCORR_LEVEL_INFO:
        pr_info("[INFO] " DM_MSG_PREFIX " %s [%s]: %pV", name, func, &vaf);
        break;
    }
    va_end(args);
}

/// @brief Raises the device mapper event of the first error
static void dm_event_work(struct work_struct *work)
{
    struct dm_context *dm_ctx = container_of(work, struct dm_context, event_work);

    dm_table_event(dm_ctx->ti->table);
}

/// @brief Records that the device met an error: of the lower device, or damaged data or metadata
/// @details
/// The first one since the table was created raises a device mapper event,
/// which dmsetup wait and dmeventd see; the counters of dmsetup status tell
/// what it was. Later errors raise none, so that a failing device does not
/// keep the waiters busy. Any context: the event is raised from a work item,
/// as dm_table_event takes a mutex. Before the constructor returns there is
/// no context yet, and nothing to raise.
/// @param ti The target of the device
void dcorr_error(struct dm_target *ti)
{
    struct dm_context *dm_ctx = READ_ONCE(ti->private);

    if (dm_ctx && !test_and_set_bit(0, &dm_ctx->errors_seen))
        schedule_work(&dm_ctx->event_work);
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
/// for a chunk never written, see cache_read; for the rest it is put into the tree of reads
/// of the cache, takes a place among the parts in flight, initializes the
/// trn_p_rq in the per-bio data of the bio and processes it asynchronously.
/// It waits if MAX_PARTS_IN_FLIGHT parts are in flight, which blocks the
/// submitter as a full request queue of a disk would, and while the metadata
/// area of its region is read, see metadata_get. Waiting belongs here and in
/// the worker of the cache, never in transform_wq: its workers run the
/// complete_work that gives places back. dm_map never waits for a lower bio of
/// its own, which stays on current->bio_list until it returns: the metadata
/// area is read by a worker of the metadata cache.
///
/// A discard is not split at chunks, only by the limits of the queue, see
/// dm_io_hints. Its whole chunks go to the cache, which clears their bits in
/// the bitmap of written chunks, so they read as zeros; the partial chunks at
/// its ends are left as they are, and one with no whole chunk completes at
/// once. It is refused if it touches a read only range, and never passed down.
///
/// A write zeroes is not split at chunks either: its partial chunks are
/// written as zeros through the cache, its whole chunks cleared as by a
/// discard, see cache_write_zeroes. Device mapper sends it only while the
/// device below has write zeroes, see dm_io_hints. It is refused if it
/// touches a read only range.
///
/// Other operations are refused: device mapper sends none of them, as the
/// target does not offer them, and remapping one would bypass the CRC.
/// @param ti  DM target
/// @param bio Incoming bio request
/// @return DM_MAPIO_SUBMITTED for READ, WRITE, DISCARD, WRITE_ZEROES and an empty flush.
///         DM_MAPIO_KILL for anything else.
static int dm_map(struct dm_target *ti, struct bio *bio)
{
    DM_DEBUG("bio=%p op=%u sector=%llu size=%u\n",
             bio,
             bio_op(bio),
             (unsigned long long)bio->bi_iter.bi_sector,
             bio->bi_iter.bi_size);

    struct dm_context *dm_ctx = ti->private;
    struct trn_p_rq *part = dm_per_bio_data(bio, ti->per_io_data_size);

    if (bio->bi_opf & REQ_PREFLUSH)
    {
        if (WARN_ON_ONCE(bio_has_data(bio)))
            return DM_MAPIO_KILL;
        cache_flush(dm_ctx->cache, bio);
        return DM_MAPIO_SUBMITTED;
    }

    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        if (cache_read(dm_ctx->cache, bio, &part->range))
            return DM_MAPIO_SUBMITTED;
        break;

    case REQ_OP_WRITE:
        if (written_read_only(dm_ctx->written, bio->bi_iter.bi_sector))
        {
            atomic64_inc(&dm_ctx->written->refused_writes);
            DM_DEV_ERR_LIMIT(ti, "write at sector %llu refused: its block of the bitmap is invalid in both copies\n",
                             (unsigned long long)bio->bi_iter.bi_sector);
            return DM_MAPIO_KILL;
        }
        cache_write(dm_ctx->cache, bio);
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_DISCARD:
        atomic64_inc(&dm_ctx->cache->nr_discards);
        if (DIV_ROUND_UP(bio->bi_iter.bi_sector, DATA_SIZE_SECTORS) >= bio_end_sector(bio) / DATA_SIZE_SECTORS)
        {
            bio_endio(bio);
            return DM_MAPIO_SUBMITTED;
        }
        if (written_range_read_only(dm_ctx->written, bio->bi_iter.bi_sector, bio_sectors(bio)))
        {
            atomic64_inc(&dm_ctx->written->refused_writes);
            DM_DEV_ERR_LIMIT(ti, "discard at sector %llu refused: it touches a block of the bitmap invalid in both copies\n",
                             (unsigned long long)bio->bi_iter.bi_sector);
            return DM_MAPIO_KILL;
        }
        cache_discard(dm_ctx->cache, bio);
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_WRITE_ZEROES:
        if (written_range_read_only(dm_ctx->written, bio->bi_iter.bi_sector, bio_sectors(bio)))
        {
            atomic64_inc(&dm_ctx->written->refused_writes);
            DM_DEV_ERR_LIMIT(ti, "write zeroes at sector %llu refused: it touches a block of the bitmap invalid in both copies\n",
                             (unsigned long long)bio->bi_iter.bi_sector);
            return DM_MAPIO_KILL;
        }
        cache_write_zeroes(dm_ctx->cache, bio);
        return DM_MAPIO_SUBMITTED;

    default:
        DM_DEV_ERR_LIMIT(ti, "unsupported bio op=%u\n", bio_op(bio));
        return DM_MAPIO_KILL;
    }

    if (down_trylock(&dm_ctx->parts_in_flight))
    {
        atomic64_inc(&dm_ctx->map_waits);
        down(&dm_ctx->parts_in_flight);
    }

    trn_p_rq_init(part, bio, dm_ctx, TRANSFORM_READ, NULL);
    queue_work(dm_ctx->transform_wq, &part->submit_work);
    return DM_MAPIO_SUBMITTED;
}

/// @brief Initializes the DM target on creation
/// @details
/// Expects a single argument argv[0] — path to the lower-level device, formatted
/// by dcorrsetup. The superblock gives the layout, and the length of the target
/// must be the capacity it records, as dcorrsetup table prints it.
///
/// Sequentially allocates and initializes all resources: work queue,
/// lower-level device, the superblock, the bitmap of written chunks, which
/// reads the header of every group, the metadata cache and the data cache.
///
/// On error at any stage, frees all previously allocated resources
/// in reverse order of allocation.
/// @param ti   DM target
/// @param argc Argument count
/// @param argv Arguments: argv[0] — path to lower-level device
/// @return 0 on success, negative error code on failure
static int dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    if (argc != 1)
    {
        ti->error = "Invalid argument count: expected <device>";
        DM_DEV_ERR(ti, "expected 1 argument, got %u\n", argc);
        return -EINVAL;
    }

    DM_DEBUG("argc=%u, argv[0]=%s\n", argc, argv[0]);

    struct dm_context *dm_ctx;
    int r;

    dm_ctx = kzalloc_obj(*dm_ctx, GFP_KERNEL);
    if (!dm_ctx)
    {
        ti->error = "dm_context alloc failed";
        DM_DEV_ERR(ti, "kzalloc dm_context failed\n");
        return -ENOMEM;
    }

    dm_ctx->transform_wq = alloc_workqueue("transformation_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!dm_ctx->transform_wq)
    {
        ti->error = "alloc_workqueue failed";
        DM_DEV_ERR(ti, "alloc_workqueue failed\n");
        r = -ENOMEM;
        goto error_alloc_workqueue;
    }

    sema_init(&dm_ctx->parts_in_flight, MAX_PARTS_IN_FLIGHT);
    atomic64_set(&dm_ctx->map_waits, 0);
    atomic64_set(&dm_ctx->read_errors, 0);
    atomic64_set(&dm_ctx->crc_mismatches, 0);
    dm_ctx->ti = ti;
    INIT_WORK(&dm_ctx->event_work, dm_event_work);

    r = dm_set_target_max_io_len(ti, DATA_SIZE_SECTORS);
    if (r)
    {
        DM_DEV_ERR(ti, "dm_set_target_max_io_len failed, err=%d\n", r);
        goto error_dm_get_device;
    }
    ti->per_io_data_size = sizeof(struct trn_p_rq);
    ti->num_flush_bios = 1;
    ti->flush_supported = true;
    ti->num_discard_bios = 1;
    ti->discards_supported = true;
    ti->num_write_zeroes_bios = 1;

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        DM_DEV_ERR(ti, "dm_get_device failed, dev=%s err=%d\n", argv[0], r);
        goto error_dm_get_device;
    }

    if (bdev_logical_block_size(dm_ctx->dev->bdev) != SECTOR_SIZE)
    {
        ti->error = "The device below must have logical blocks of 512 bytes";
        DM_DEV_ERR(ti, "the device below has logical blocks of %u bytes, the metadata is written in sectors of 512\n",
                   bdev_logical_block_size(dm_ctx->dev->bdev));
        r = -EINVAL;
        goto error_metadata;
    }

    r = superblock_read(ti, dm_ctx->dev->bdev, &dm_ctx->sb);
    if (r)
        goto error_metadata;

    if (ti->len != dm_ctx->sb.layout.capacity)
    {
        ti->error = "The length must be the capacity in the superblock, see dcorrsetup table";
        DM_DEV_ERR(ti, "length %llu, the superblock gives %llu\n", (unsigned long long)ti->len,
               (unsigned long long)dm_ctx->sb.layout.capacity);
        r = -EINVAL;
        goto error_metadata;
    }

    dm_ctx->written = written_create(ti, dm_ctx->dev->bdev, &dm_ctx->sb,
                                     dm_table_get_mode(ti->table) & BLK_OPEN_WRITE);
    if (IS_ERR(dm_ctx->written))
    {
        r = PTR_ERR(dm_ctx->written);
        DM_DEV_ERR(ti, "written_create failed, err=%d\n", r);
        goto error_metadata;
    }

    dm_ctx->metadata = metadata_cache_create(ti, dm_ctx->dev->bdev, &dm_ctx->sb.layout, dm_ctx->sb.salt_crc);
    if (IS_ERR(dm_ctx->metadata))
    {
        ti->error = "metadata cache alloc failed";
        r = PTR_ERR(dm_ctx->metadata);
        DM_DEV_ERR(ti, "metadata_cache_create failed, err=%d\n", r);
        goto error_written;
    }

    dm_ctx->cache = cache_create(dm_ctx);
    if (IS_ERR(dm_ctx->cache))
    {
        ti->error = "cache alloc failed";
        r = PTR_ERR(dm_ctx->cache);
        DM_DEV_ERR(ti, "cache_create failed, err=%d\n", r);
        goto error_cache;
    }

    ti->private = dm_ctx;

    DM_DEV_INFO(ti, "mapped on dev=%s, disk capacity=%llu sec, available capacity=%llu sec\n",
            argv[0],
            (unsigned long long)get_capacity(dm_ctx->dev->bdev->bd_disk),
            (unsigned long long)ti->len);

    return 0;

error_cache:
    metadata_cache_destroy(dm_ctx->metadata);
error_written:
    written_destroy(dm_ctx->written);
error_metadata:
    dm_put_device(ti, dm_ctx->dev);
error_dm_get_device:
    destroy_workqueue(dm_ctx->transform_wq);
error_alloc_workqueue:
    kfree(dm_ctx);
    return r;
}

/// @brief Destroys the DM target and frees all resources
/// @details
/// Before destroying the work queue, waits for completion of all
/// current work via flush_workqueue to ensure no resource access
/// after their release.
/// @param ti DM target
static void dm_dtr(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    DM_DEBUG("dm_ctx=%p\n", dm_ctx);

    cancel_work_sync(&dm_ctx->event_work);
    cache_destroy(dm_ctx->cache);
    flush_workqueue(dm_ctx->transform_wq);
    destroy_workqueue(dm_ctx->transform_wq);
    metadata_cache_destroy(dm_ctx->metadata);
    written_destroy(dm_ctx->written);
    dm_put_device(ti, dm_ctx->dev);
    kfree(dm_ctx);
}

/// @brief Writes back the cache once device mapper has no bio of the device in flight
/// @details
/// Device mapper calls it before a table is replaced or destroyed, so nothing
/// written is left behind in the cache, but chunks whose write back fails.
/// Then forgets the metadata in RAM, as the device below may change before
/// the device is resumed. The bitmap stays: the driver alone writes it, and
/// the suspend has written it out.
/// @param ti DM target
static void dm_target_postsuspend(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    cache_suspend(dm_ctx->cache);
    metadata_drop(dm_ctx->metadata);
}

/// @brief Reads the bitmap of written chunks on the first resume of the table
/// @details
/// See written_load_once: on a reload the old table is suspended by now.
/// @param ti DM target
/// @return 0, or an error that fails the resume
static int dm_target_preresume(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    return written_load_once(dm_ctx->written);
}

/// @brief Lets the cache write back by age again
/// @param ti DM target
static void dm_target_resume(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    cache_resume(dm_ctx->cache);
}

/// @brief Reports the state of the target to dmsetup
/// @details
/// STATUSTYPE_INFO (dmsetup status) gives the counters, positional, in the
/// order and with the meaning that "Interface" in docs/en/ARCHITECTURE.md
/// lists; a new counter is added at the end. STATUSTYPE_TABLE (dmsetup table)
/// gives the lower device as major:minor, so that the line loads again.
/// STATUSTYPE_IMA gives nothing yet.
/// @param ti           DM target
/// @param type         What to report
/// @param status_flags Flags of the request, unused
/// @param result       Buffer for the text
/// @param maxlen       Size of the buffer
static void dm_status(struct dm_target *ti, status_type_t type,
                      unsigned int status_flags, char *result, unsigned int maxlen)
{
    struct dm_context *dm_ctx = ti->private;
    unsigned long dirty, failed;
    unsigned int sz = 0;

    switch (type)
    {
    case STATUSTYPE_INFO:
        cache_counters(dm_ctx->cache, &dirty, &failed);
        DMEMIT("%llu %llu %llu %llu %lu %lu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
               (unsigned long long)atomic64_read(&dm_ctx->map_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->free_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->busy_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->read_waits),
               dirty, failed,
               (unsigned long long)atomic64_read(&dm_ctx->metadata->loads),
               (unsigned long long)atomic64_read(&dm_ctx->metadata->waits),
               (unsigned long long)atomic64_read(&dm_ctx->metadata->trail_errors),
               (unsigned long long)atomic64_read(&dm_ctx->cache->crowded_flushes),
               (unsigned long long)atomic64_read(&dm_ctx->cache->barriers),
               (unsigned long long)atomic64_read(&dm_ctx->metadata->settle_reads),
               (unsigned long long)atomic64_read(&dm_ctx->metadata->settle_mismatches),
               (unsigned long long)atomic64_read(&dm_ctx->written->unwritten_reads),
               (unsigned long long)atomic64_read(&dm_ctx->written->read_only_blocks),
               (unsigned long long)atomic64_read(&dm_ctx->written->single_blocks),
               (unsigned long long)atomic64_read(&dm_ctx->written->bad_superblocks),
               (unsigned long long)atomic64_read(&dm_ctx->written->write_errors),
               (unsigned long long)atomic64_read(&dm_ctx->written->refused_writes),
               (unsigned long long)atomic64_read(&dm_ctx->cache->nr_discards),
               (unsigned long long)atomic64_read(&dm_ctx->cache->discarded_chunks),
               (unsigned long long)atomic64_read(&dm_ctx->read_errors),
               (unsigned long long)atomic64_read(&dm_ctx->crc_mismatches),
               (unsigned long long)atomic64_read(&dm_ctx->cache->write_errors),
               (unsigned long long)atomic64_read(&dm_ctx->metadata->read_errors),
               (unsigned long long)atomic64_read(&dm_ctx->cache->flush_errors));
        break;
    case STATUSTYPE_TABLE:
        DMEMIT("%s", dm_ctx->dev->name);
        break;
    case STATUSTYPE_IMA:
        result[0] = '\0';
        break;
    }
}

/// @brief Gives device mapper the device below, the part of it the layout uses
/// @details
/// Device mapper stacks the limits of the device below into those of the
/// target through it, before dm_io_hints, checks that the area lies on the
/// device, and offers write zeroes only if the device below has it.
static int dm_iterate_devices(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
    struct dm_context *dm_ctx = ti->private;

    return fn(ti, dm_ctx->dev, 0, dm_ctx->sb.layout.lower_sectors, data);
}

/// @brief Sets the limits of the queue the target needs, over those of the device below
/// @details
/// What the target does itself replaces what it took from the device below:
/// - a chunk of 4 KiB is the smallest write that does not make the cache
///   merge, and the unit of the CRC work, so it is the physical block and the
///   minimal I/O, unless the device below has larger ones; the optimal I/O and
///   the alignment of the device below say nothing of the layout on top;
/// - discards in whole chunks, of any length: device mapper does not split
///   them at max_io_len, only the block layer by these limits; they are not
///   passed down, so whatever the device below allows does not matter;
/// - write zeroes of any length, carried out in the cache, see
///   cache_write_zeroes; device mapper turns it off when the device below has
///   none, as then nothing says that zeroing is cheap there;
/// - no polling, as every request completes from a workqueue, and no stable
///   pages, as a write is copied into the cache.
///
/// A device below with logical blocks other than 512 bytes is refused by the
/// constructor; a zoned one by device mapper, as the target is not zoned.
static void dm_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
    limits->physical_block_size = max_t(unsigned int, limits->physical_block_size, DATA_SIZE_SECTORS << SECTOR_SHIFT);
    limits->io_min = max_t(unsigned int, limits->io_min, DATA_SIZE_SECTORS << SECTOR_SHIFT);
    limits->io_opt = 0;
    limits->alignment_offset = 0;

    limits->discard_granularity = DATA_SIZE_SECTORS << SECTOR_SHIFT;
    limits->discard_alignment = 0;
    limits->max_hw_discard_sectors = UINT_MAX >> SECTOR_SHIFT;

    limits->max_write_zeroes_sectors = UINT_MAX >> SECTOR_SHIFT;
    limits->max_hw_wzeroes_unmap_sectors = 0;

    limits->features &= ~(BLK_FEAT_POLL | BLK_FEAT_STABLE_WRITES);
}

static struct target_type target = {
    .name = "dcorr",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dm_ctr,
    .dtr = dm_dtr,
    .map = dm_map,
    .postsuspend = dm_target_postsuspend,
    .preresume = dm_target_preresume,
    .resume = dm_target_resume,
    .status = dm_status,
    .iterate_devices = dm_iterate_devices,
    .io_hints = dm_io_hints,
};

/// @brief Registers the DM target on module load
/// @return 0 on success, negative error code on failure
static int __init dm_init(void)
{
    DM_DEBUG("loading\n");

    int r = dm_register_target(&target);

    if (r)
        DM_ERR("dm_register_target failed, err=%d\n", r);
    else
        DM_INFO("module loaded\n");

    return r;
}

/// @brief Exit point for the DM target on module unload
static void __exit dm_exit(void)
{
    DM_DEBUG("unloading\n");
    dm_unregister_target(&target);
    DM_INFO("module unloaded\n");
}

module_init(dm_init);
module_exit(dm_exit);

#include "corrdm.h"
#include "cache.h"
#include "macros.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

/// @brief Handles incoming bio requests
/// @details
/// Called by the DM subsystem for each incoming bio. DM splits requests at chunk
/// boundaries, so the bio stays within one chunk.
///
/// An empty flush goes to the cache, which writes back everything dirty and
/// flushes the lower device before completing it. Device mapper sends one for
/// each REQ_PREFLUSH, and the data of such a bio comes afterwards without the flag.
///
/// A write goes into the cache, see cache_write. A read takes from the cache
/// what it holds, see cache_read; for the rest it is put into the tree of reads
/// of the cache, takes a place among the parts in flight, initializes the
/// trn_p_rq in the per-bio data of the bio and processes it asynchronously. It waits if MAX_PARTS_IN_FLIGHT parts are in
/// flight, or for memory, which blocks the submitter as a full request queue of
/// a disk would. Waiting belongs here and in the worker of the cache, never in
/// transform_wq: its workers run the complete_work that gives places and
/// memory back. dm_map never waits for a lower bio of its own, which stays on
/// current->bio_list until it returns.
///
/// Other operations are refused: device mapper sends none of them, as the
/// target does not offer them, and remapping one would bypass the CRC.
/// @param ti  DM target
/// @param bio Incoming bio request
/// @return DM_MAPIO_SUBMITTED for READ, WRITE and an empty flush.
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
        cache_write(dm_ctx->cache, bio);
        return DM_MAPIO_SUBMITTED;

    default:
        DM_ERR("unsupported bio op=%u\n", bio_op(bio));
        return DM_MAPIO_KILL;
    }

    if (down_trylock(&dm_ctx->parts_in_flight))
    {
        atomic64_inc(&dm_ctx->map_waits);
        down(&dm_ctx->parts_in_flight);
    }

    trn_p_rq_init(part, bio, dm_ctx, TRANSFORM_READ);
    queue_work(dm_ctx->transform_wq, &part->submit_work);
    return DM_MAPIO_SUBMITTED;
}

/// @brief Initializes the DM target on creation
/// @details
/// Expects a single argument argv[0] — path to the lower-level device.
///
/// Sequentially allocates and initializes all resources:
/// work queue, metadata page pool, lower-level device and the cache.
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
        DM_ERR("expected 1 argument, got %u\n", argc);
        return -EINVAL;
    }

    DM_DEBUG("argc=%u, argv[0]=%s\n", argc, argv[0]);

    struct dm_context *dm_ctx;
    int r;

    dm_ctx = kzalloc_obj(*dm_ctx, GFP_KERNEL);
    if (!dm_ctx)
    {
        ti->error = "dm_context alloc failed";
        DM_ERR("kzalloc dm_context failed\n");
        return -ENOMEM;
    }

    dm_ctx->transform_wq = alloc_workqueue("transformation_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!dm_ctx->transform_wq)
    {
        ti->error = "alloc_workqueue failed";
        DM_ERR("alloc_workqueue failed\n");
        r = -ENOMEM;
        goto error_alloc_workqueue;
    }

    dm_ctx->page_pool = mempool_create_page_pool(PAGE_POOL_RESERVE, 0);
    if (!dm_ctx->page_pool)
    {
        ti->error = "page pool alloc failed";
        DM_ERR("mempool_create_page_pool failed\n");
        r = -ENOMEM;
        goto error_page_pool;
    }

    sema_init(&dm_ctx->parts_in_flight, MAX_PARTS_IN_FLIGHT);
    atomic64_set(&dm_ctx->map_waits, 0);

    r = dm_set_target_max_io_len(ti, DATA_SIZE_SECTORS);
    if (r)
    {
        DM_ERR("dm_set_target_max_io_len failed, err=%d\n", r);
        goto error_dm_get_device;
    }
    ti->per_io_data_size = sizeof(struct trn_p_rq);
    ti->num_flush_bios = 1;
    ti->flush_supported = true;

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        DM_ERR("dm_get_device failed, dev=%s err=%d\n", argv[0], r);
        goto error_dm_get_device;
    }

    dm_ctx->cache = cache_create(dm_ctx);
    if (IS_ERR(dm_ctx->cache))
    {
        ti->error = "cache alloc failed";
        r = PTR_ERR(dm_ctx->cache);
        DM_ERR("cache_create failed, err=%d\n", r);
        dm_put_device(ti, dm_ctx->dev);
        goto error_dm_get_device;
    }

    ti->private = dm_ctx;
    ti->len = device_new_capacity(get_capacity(dm_ctx->dev->bdev->bd_disk));

    DM_INFO("mapped on dev=%s, disk capacity=%llu sec, available capacity=%llu sec\n",
            argv[0],
            (unsigned long long)get_capacity(dm_ctx->dev->bdev->bd_disk),
            (unsigned long long)ti->len);

    return 0;

error_dm_get_device:
    mempool_destroy(dm_ctx->page_pool);
error_page_pool:
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

    cache_destroy(dm_ctx->cache);
    flush_workqueue(dm_ctx->transform_wq);
    destroy_workqueue(dm_ctx->transform_wq);
    dm_put_device(ti, dm_ctx->dev);
    mempool_destroy(dm_ctx->page_pool);
    kfree(dm_ctx);
}

/// @brief Writes back the cache once device mapper has no bio of the device in flight
/// @details
/// Device mapper calls it before a table is replaced or destroyed, so nothing
/// written is left behind in the cache, but chunks whose write back fails.
/// @param ti DM target
static void dm_target_postsuspend(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    cache_suspend(dm_ctx->cache);
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
/// STATUSTYPE_INFO (dmsetup status) gives the counters, in this order: waits of
/// reads in dm_map for a place among the parts in flight, waits of writes for a
/// free entry of the cache, waits of writes for an entry under write back,
/// reads that waited for the write back of their chunk, entries holding data
/// not yet on the lower device, entries whose write back failed.
/// STATUSTYPE_TABLE (dmsetup table) gives nothing yet.
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
        DMEMIT("%llu %llu %llu %llu %lu %lu",
               (unsigned long long)atomic64_read(&dm_ctx->map_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->free_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->busy_waits),
               (unsigned long long)atomic64_read(&dm_ctx->cache->read_waits),
               dirty, failed);
        break;
    case STATUSTYPE_TABLE:
    case STATUSTYPE_IMA:
        result[0] = '\0';
        break;
    }
}

static struct target_type target = {
    .name = "corrdm",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dm_ctr,
    .dtr = dm_dtr,
    .map = dm_map,
    .postsuspend = dm_target_postsuspend,
    .resume = dm_target_resume,
    .status = dm_status,
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

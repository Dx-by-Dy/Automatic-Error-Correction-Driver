#include "corrdm.h"
#include "macros.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

/// @brief Handles incoming bio requests
/// @details
/// Called by the DM subsystem for each incoming bio. DM splits requests at chunk
/// boundaries, so the bio stays within one chunk.
///
/// An empty flush goes to the lower device as it is. Device mapper sends one
/// for each REQ_PREFLUSH, and the data of such a bio comes afterwards without
/// the flag. A write completes only once its data and metadata have, so the
/// flush covers every write completed before it.
///
/// For read and write operations, takes a place among the parts in flight,
/// initializes the trn_p_rq in the per-bio data of the bio and processes it
/// asynchronously. It waits if MAX_PARTS_IN_FLIGHT parts are in flight, or for
/// memory, which blocks the submitter as a full request queue of a disk would.
/// The waiting belongs here and never in a worker: workers run the complete_work
/// that gives places and memory back.
///
/// Other operations are refused: device mapper sends none of them, as the
/// target does not offer them, and remapping one would bypass the CRC.
/// @param ti  DM target
/// @param bio Incoming bio request
/// @return DM_MAPIO_SUBMITTED for READ, WRITE.
///         DM_MAPIO_REMAPPED for an empty flush.
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
    sector_t sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    enum trn_p_type type;

    if (bio->bi_opf & REQ_PREFLUSH)
    {
        if (WARN_ON_ONCE(bio_has_data(bio)))
            return DM_MAPIO_KILL;
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;
    }

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        type = TRANSFORM_READ;
        break;

    case REQ_OP_WRITE:
        type = TRANSFORM_WRITE;
        break;

    default:
        DM_ERR("unsupported bio op=%u\n", bio_op(bio));
        return DM_MAPIO_KILL;
    }

    if (down_trylock(&dm_ctx->parts_in_flight))
    {
        atomic64_inc(&dm_ctx->map_waits);
        down(&dm_ctx->parts_in_flight);
    }

    bio->bi_iter.bi_sector = sector;
    trn_p_rq_init(part, bio, dm_ctx, type);
    queue_work(dm_ctx->transform_wq, &part->submit_work);
    return DM_MAPIO_SUBMITTED;
}

/// @brief Initializes the DM target on creation
/// @details
/// Expects a single argument argv[0] — path to the lower-level device.
///
/// Sequentially allocates and initializes all resources:
/// lock table, work queue, metadata page pool, and lower-level device.
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

    r = locker_init(&dm_ctx->locker);
    if (r)
    {
        ti->error = "locker alloc failed";
        DM_ERR("locker_init failed, err=%d\n", r);
        goto error_locker_init;
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
    locker_exit(&dm_ctx->locker);
error_locker_init:
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

    flush_workqueue(dm_ctx->transform_wq);
    destroy_workqueue(dm_ctx->transform_wq);
    locker_exit(&dm_ctx->locker);
    dm_put_device(ti, dm_ctx->dev);
    mempool_destroy(dm_ctx->page_pool);
    kfree(dm_ctx);
}

/// @brief Reports the state of the target to dmsetup
/// @details
/// STATUSTYPE_INFO (dmsetup status) gives the counters: for now the number of
/// times dm_map waited for a place among the parts in flight.
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
    unsigned int sz = 0;

    switch (type)
    {
    case STATUSTYPE_INFO:
        DMEMIT("%llu", (unsigned long long)atomic64_read(&dm_ctx->map_waits));
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

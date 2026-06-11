#include "correction-driver.h"
#include "macros.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

static int dm_map(struct dm_target *ti, struct bio *bio)
{
    struct trn_rq *req;
    struct dm_context *dm_ctx = ti->private;

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        req = trn_rq_init(bio, dm_ctx, TRANSFORM_READ);

        if (req)
        {
            trn_rq_submit(req);
            return DM_MAPIO_SUBMITTED;
        }

        pr_err("Failed to initialize read request\n");
        return DM_MAPIO_SUBMITTED;

    case REQ_OP_WRITE:
        req = trn_rq_init(bio, dm_ctx, TRANSFORM_WRITE);

        if (req)
        {
            trn_rq_submit(req);
            return DM_MAPIO_SUBMITTED;
        }

        pr_err("Failed to initialize read request\n");
        return DM_MAPIO_SUBMITTED;

    default:
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_SUBMITTED;
    }
}

static int dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dm_context *dm_ctx;
    int r;

    dm_ctx = kzalloc(sizeof(*dm_ctx), GFP_KERNEL);
    if (!dm_ctx)
        return -ENOMEM;

    dm_ctx->locker = kzalloc(sizeof(*dm_ctx->locker), GFP_KERNEL);
    if (!dm_ctx->locker)
    {
        ti->error = "locker_alloc failed";
        r = -ENOMEM;
        goto error_locker_alloc;
    }

    locker_init(dm_ctx->locker);

    dm_ctx->transform_wq = alloc_workqueue("transformation_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1024);
    if (!dm_ctx->transform_wq)
    {
        ti->error = "alloc_workqueue failed";
        r = -ENOMEM;
        goto error_alloc_workqueue;
    }

    dm_ctx->transform_bs = kzalloc(sizeof(struct bio_set), GFP_KERNEL);
    if (!dm_ctx->transform_bs)
    {
        ti->error = "alloc_bioset failed";
        r = -ENOMEM;
        goto error_alloc_bioset;
    }

    r = bioset_init(dm_ctx->transform_bs, 128, 0, BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r)
    {
        ti->error = "bioset_init failed";
        goto error_bioset_init;
    }

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        goto error_dm_get_device;
    }

    ti->private = dm_ctx;
    ti->len = device_new_capacity(get_capacity(dm_ctx->dev->bdev->bd_disk));

    r = dm_set_target_max_io_len(ti, 8);
    if (r)
    {
        ti->error = "dm_set_target_max_io_len failed";
        goto error_set_target_max_io_len;
    }

    pr_info(DM_MSG_PREFIX ": loaded dev=%s", argv[0]);

    return 0;

error_set_target_max_io_len:
    dm_put_device(ti, dm_ctx->dev);
error_dm_get_device:
    bioset_exit(dm_ctx->transform_bs);
error_bioset_init:
    kfree(dm_ctx->transform_bs);
error_alloc_bioset:
    destroy_workqueue(dm_ctx->transform_wq);
error_alloc_workqueue:
    locker_exit(dm_ctx->locker);
    kfree(dm_ctx->locker);
error_locker_alloc:
    kfree(dm_ctx);
    return r;
}

static void dm_dtr(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;
    if (!dm_ctx)
        return;

    flush_workqueue(dm_ctx->transform_wq);
    destroy_workqueue(dm_ctx->transform_wq);
    locker_exit(dm_ctx->locker);
    kfree(dm_ctx->locker);
    dm_put_device(ti, dm_ctx->dev);
    bioset_exit(dm_ctx->transform_bs);
    kfree(dm_ctx->transform_bs);
    kfree(dm_ctx);
}

static struct target_type target = {
    .name = "correction_dm",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dm_ctr,
    .dtr = dm_dtr,
    .map = dm_map,
};

static int __init dm_init(void)
{
    return dm_register_target(&target);
}

static void __exit dm_exit(void)
{
    dm_unregister_target(&target);
}

module_init(dm_init);
module_exit(dm_exit);

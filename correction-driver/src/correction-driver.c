#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/bvec.h>
#include <linux/crc64.h>
#include <linux/workqueue.h>

#include "bio_helper.h"
#include "write_worker.h"
#include "correction-driver.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

static int dm_map(struct dm_target *ti, struct bio *bio)
{

    struct dm_context *dm_ctx = ti->private;

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;

    case REQ_OP_WRITE:
        print_bio(bio);
        struct write_request *req = write_request_init(bio, dm_ctx);
        if (!req)
        {
            pr_err("Failed to initialize write request\n");
            return DM_MAPIO_KILL;
        }
        queue_work(dm_ctx->write_wq, &req->work);
        return DM_MAPIO_SUBMITTED;

    default:
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;
    }
}

static int dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dm_context *dm_ctx;
    int r;

    dm_ctx = kzalloc(sizeof(*dm_ctx), GFP_KERNEL);
    if (!dm_ctx)
        return -ENOMEM;

    dm_ctx->write_wq = alloc_workqueue("write_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1024);
    if (!dm_ctx->write_wq)
    {
        kfree(dm_ctx);
        return -ENOMEM;
    }

    dm_ctx->write_rq_bs = kzalloc(sizeof(struct bio_set), GFP_KERNEL);
    if (!dm_ctx->write_rq_bs)
    {
        destroy_workqueue(dm_ctx->write_wq);
        kfree(dm_ctx);
        return -ENOMEM;
    }

    r = bioset_init(dm_ctx->write_rq_bs, 128, 0, BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r)
    {
        destroy_workqueue(dm_ctx->write_wq);
        kfree(dm_ctx);
        return r;
    }

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        bioset_exit(dm_ctx->write_rq_bs);
        kfree(dm_ctx->write_rq_bs);
        destroy_workqueue(dm_ctx->write_wq);
        kfree(dm_ctx);
        return r;
    }
    ti->private = dm_ctx;

    pr_info(DM_MSG_PREFIX ": loaded dev=%s", argv[0]);

    return 0;
}

static void dm_dtr(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;
    if (!dm_ctx)
        return;

    flush_workqueue(dm_ctx->write_wq);
    destroy_workqueue(dm_ctx->write_wq);
    dm_put_device(ti, dm_ctx->dev);
    bioset_exit(dm_ctx->write_rq_bs);
    kfree(dm_ctx->write_rq_bs);
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

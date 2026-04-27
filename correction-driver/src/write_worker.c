#include "write_worker.h"
#include "alignment.h"
#include "bio_helper.h"
#include <linux/slab.h>

static void write_handler(struct work_struct *work);
static int create_orig_bio_parts(struct write_request *req);
static void init_orig_bio_parts(struct write_request *req);
static void submit_orig_bio_parts(struct write_request *req);

struct write_request *write_request_init(struct bio *orig_bio, struct dm_context *ctx)
{
    struct write_request *req = kmalloc(sizeof(struct write_request), GFP_KERNEL);
    if (!req)
        return NULL;

    bio_get(orig_bio);
    INIT_WORK(&req->work, write_handler);
    req->orig_bio = orig_bio;
    req->dm_ctx = ctx;
    req->num_parts = 0;
    atomic_set(&req->pending, 0);

    pr_info("write_request_init");

    return req;
}

static void write_handler(struct work_struct *work)
{
    struct write_request *req = container_of(work, struct write_request, work);
    int ret;

    ret = create_orig_bio_parts(req);
    pr_info("create_orig_bio_parts");
    if (ret)
    {
        // TODO: что делать?
        pr_err("Failed to create orig bio parts\n");
        return;
    }

    init_orig_bio_parts(req);
    pr_info("init_orig_bio_parts");
    for (unsigned int i = 0; i < req->num_parts; i++)
    {
        print_bio(req->orig_bio_parts[i]);
    }
    submit_orig_bio_parts(req);
    pr_info("submit_orig_bio_parts");
}

static int create_orig_bio_parts(struct write_request *req)
{
    struct bio *orig_bio = req->orig_bio;
    unsigned int misalign;

    while (bio_sectors(orig_bio) > 0)
    {
        misalign = min(misalign_data_sector(orig_bio->bi_iter.bi_sector), bio_sectors(orig_bio));
        if (misalign == bio_sectors(orig_bio))
        {
            struct bio *orig_bio_part = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, req->dm_ctx->write_rq_bs);
            if (!orig_bio_part)
            {
                pr_err("Failed to allocate bio clone\n");
                goto error;
            }
            // bio_chain(orig_bio_part, orig_bio);
            req->orig_bio_parts[req->num_parts++] = orig_bio_part;
            return 0;
        }
        struct bio *orig_bio_part = bio_split(orig_bio, misalign, GFP_NOIO, req->dm_ctx->write_rq_bs);
        if (IS_ERR(orig_bio_part))
        {
            pr_err("Failed to split bio\n");
            goto error;
        }
        // bio_chain(orig_bio_part, orig_bio);
        req->orig_bio_parts[req->num_parts++] = orig_bio_part;
    }

error:
    pr_err("Failed to create orig bio parts\n");
    for (unsigned int i = 0; i < req->num_parts; i++)
    {
        bio_put(req->orig_bio_parts[i]);
    }
    return -ENOMEM;
}

static void init_orig_bio_parts(struct write_request *req)
{
    for (unsigned int i = 0; i < req->num_parts; i++)
    {
        struct bio *part = req->orig_bio_parts[i];
        bio_set_dev(part, req->dm_ctx->dev->bdev);
        part->bi_end_io = write_orig_bio_part_end_io;
        atomic_inc(&req->pending);
        part->bi_private = req;
        part->bi_iter.bi_sector = align_data_sector(part->bi_iter.bi_sector);
    }
}

static void submit_orig_bio_parts(struct write_request *req)
{
    for (unsigned int i = 0; i < req->num_parts; i++)
    {
        submit_bio(req->orig_bio_parts[i]);
    }
}
#include "read_worker.h"
#include "bio_helper.h"
#include <linux/slab.h>

static void read_handler(struct work_struct *work);
static int create_orig_bio_parts(struct read_request *req);
static int init_orig_bio_parts(struct read_request *req);
static void submit_orig_bio_parts(struct read_request *req);

struct read_request *read_request_init(struct bio *orig_bio, struct dm_context *ctx)
{
    struct read_request *req = kmalloc(sizeof(struct read_request), GFP_NOIO);
    if (!req)
        return NULL;

    bio_get(orig_bio);
    INIT_WORK(&req->work, read_handler);
    req->orig_bio = orig_bio;
    req->dm_ctx = ctx;
    req->num_parts = 0;
    atomic_set(&req->pending, 0);

    // pr_info("read_request_init");

    return req;
}

static void read_handler(struct work_struct *work)
{
    struct read_request *req = container_of(work, struct read_request, work);
    int ret;

    ret = create_orig_bio_parts(req);
    // pr_info("create_orig_bio_parts");
    if (ret)
    {
        pr_err("Failed to create orig bio parts\n");
        bio_endio(req->orig_bio);
        bio_put(req->orig_bio);
        kfree(req);
        return;
    }

    ret = init_orig_bio_parts(req);
    if (ret)
    {
        pr_err("Failed to init orig bio parts\n");
        bio_endio(req->orig_bio);
        bio_put(req->orig_bio);
        kfree(req);
        return;
    }
    // pr_info("init_orig_bio_parts");
    // for (unsigned int i = 0; i < req->num_parts; i++)
    // {
    //     print_bio(req->orig_bio_parts[i]);
    // }
    submit_orig_bio_parts(req);
    // pr_info("submit_orig_bio_parts");
}

static int create_orig_bio_parts(struct read_request *req)
{
    struct bio *orig_bio = req->orig_bio;
    unsigned int misalign;

    while (bio_sectors(orig_bio) > 0)
    {
        if (req->num_parts >= MAX_ORIG_BIO_PARTS)
        {
            pr_err("Too many orig bio parts\n");
            goto error;
        }

        misalign = min(misalign_data_sector(orig_bio->bi_iter.bi_sector), bio_sectors(orig_bio));
        if (misalign == bio_sectors(orig_bio))
        {
            // TODO: добавить read_bio_part_private в bio_set
            // TODO: добавить read_rq_bs
            struct bio *orig_bio_part = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, req->dm_ctx->write_rq_bs);
            if (!orig_bio_part)
                goto error;
            req->orig_bio_parts[req->num_parts++] = orig_bio_part;

            // pr_info("orig_bio_parts before:");
            // print_bio(orig_bio_part);

            return 0;
        }

        struct bio *orig_bio_part = bio_split(orig_bio, misalign, GFP_NOIO, req->dm_ctx->write_rq_bs);
        if (IS_ERR(orig_bio_part))
            goto error;
        req->orig_bio_parts[req->num_parts++] = orig_bio_part;
    }

error:
    pr_err("Failed to create orig bio parts\n");
    for (unsigned int i = 0; i < req->num_parts; i++)
    {
        kfree(req->orig_bio_parts[i]->bi_private);
        bio_put(req->orig_bio_parts[i]);
    }
    return -ENOMEM;
}

static int init_orig_bio_parts(struct read_request *req)
{
    unsigned int i;

    for (i = 0; i < req->num_parts; i++)
    {
        struct bio *part = req->orig_bio_parts[i];
        struct read_bio_part_private *priv = kzalloc(sizeof(struct read_bio_part_private), GFP_NOIO);
        if (!priv)
        {
            bio_put(part);
            goto error;
        }
        priv->req = req;

        part->bi_iter.bi_sector = align_data_sector(part->bi_iter.bi_sector);

        priv->index = start_data_sector(part->bi_iter.bi_sector);
        priv->lock = locker_get_lock(req->dm_ctx->locker, priv->index);
        if (!priv->lock)
        {
            kfree(priv);
            bio_put(part);
            goto error;
        }
        part->bi_private = priv;

        bio_set_dev(part, req->dm_ctx->dev->bdev);
        part->bi_end_io = read_orig_bio_part_end_io;
        atomic_inc(&req->pending);

        // pr_info("orig_bio_parts after:");
        // print_bio(part);
    }

    return 0;

error:
    pr_err("Failed to init orig bio parts\n");
    for (unsigned int j = 0; j < i; j++)
    {
        struct bio *part = req->orig_bio_parts[j];
        struct read_bio_part_private *priv = part->bi_private;
        locker_put_lock(req->dm_ctx->locker, priv->index, priv->lock);
        kfree(priv);
        bio_put(part);
    }
    return -ENOMEM;
}

static void submit_orig_bio_parts(struct read_request *req)
{
    int submitted_parts[MAX_ORIG_BIO_PARTS] = {0};
    int all_submitted = 1;
    unsigned int i;

    // TODO: сделать очередь ожидания, а не loop
    while (1)
    {
        all_submitted = 1;
        for (i = 0; i < req->num_parts; i++)
        {
            if (submitted_parts[i] == 0)
            {
                all_submitted = 0;
                struct bio *part = req->orig_bio_parts[i];
                struct read_bio_part_private *priv = part->bi_private;
                if (down_read_trylock(&priv->lock->sem))
                {
                    submitted_parts[i] = 1;
                    submit_bio(part);
                }
            }
        }

        if (all_submitted)
            break;
    }
}
#include "write_worker.h"
#include "alignment.h"
#include "bio_helper.h"
#include <linux/slab.h>

static void write_handler(struct work_struct *work);
static int create_orig_bio_parts(struct write_request *req);
static int init_orig_bio_parts(struct write_request *req);
static void submit_orig_bio_parts(struct write_request *req);

struct write_request *write_request_init(struct bio *orig_bio, struct dm_context *ctx)
{
    struct write_request *req = kmalloc(sizeof(struct write_request), GFP_NOIO);
    if (!req)
        return NULL;

    bio_get(orig_bio);
    INIT_WORK(&req->work, write_handler);
    req->orig_bio = orig_bio;
    req->dm_ctx = ctx;
    req->num_parts = 0;
    atomic_set(&req->pending, 0);

    // pr_info("write_request_init");

    return req;
}

static void write_handler(struct work_struct *work)
{
    struct write_request *req = container_of(work, struct write_request, work);
    int ret;

    ret = create_orig_bio_parts(req);
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

static int create_orig_bio_parts(struct write_request *req)
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
            // TODO: добавить write_bio_part_private в bio_set
            struct bio *orig_bio_part = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, req->dm_ctx->write_rq_bs);
            if (!orig_bio_part)
                goto error;
            req->orig_bio_parts[req->num_parts++] = orig_bio_part;
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

static int init_orig_bio_parts(struct write_request *req)
{
    unsigned int i;

    for (i = 0; i < req->num_parts; i++)
    {
        struct bio *part = req->orig_bio_parts[i];
        struct write_bio_part_private *priv = kzalloc(sizeof(struct write_bio_part_private), GFP_NOIO);
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
        part->bi_end_io = write_orig_bio_part_end_io;
        atomic_inc(&req->pending);
    }

    return 0;

error:
    pr_err("Failed to init orig bio parts\n");
    for (unsigned int j = 0; j < i; j++)
    {
        struct bio *part = req->orig_bio_parts[j];
        struct write_bio_part_private *priv = part->bi_private;
        locker_put_lock(req->dm_ctx->locker, priv->index, priv->lock);
        kfree(priv);
        bio_put(part);
    }
    return -ENOMEM;
}

static void submit_orig_bio_parts(struct write_request *req)
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
                struct write_bio_part_private *priv = part->bi_private;
                if (down_write_trylock(&priv->lock->sem))
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
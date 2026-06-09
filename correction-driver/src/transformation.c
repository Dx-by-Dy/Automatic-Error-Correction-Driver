#include "transformation.h"

static void transformation_part_worker(struct work_struct *work);

static void transformation_request_destroy(struct transformation_request *req)
{
    req->orig_bio->bi_status = req->status;
    bio_endio(req->orig_bio);
    bio_put(req->orig_bio);
    kfree(req);
}

struct transformation_request *
transformation_create(struct bio *orig_bio,
                      struct dm_context *dm_ctx,
                      enum transformation_type type)
{
    struct transformation_request *req;

    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req)
        return NULL;

    bio_get(orig_bio);

    req->dm_ctx = dm_ctx;
    req->orig_bio = orig_bio;
    atomic_set(&req->pending, 0);
    atomic_set(&req->failed, 0);
    req->status = BLK_STS_OK;
    INIT_LIST_HEAD(&req->parts);

    int splitting = 1;
    while (splitting)
    {
        struct bio *part_bio;
        struct transformation_part *part;
        unsigned int len;

        len = min(misalign_data_sector(orig_bio->bi_iter.bi_sector), bio_sectors(orig_bio));
        if (len == bio_sectors(orig_bio))
        {
            splitting = 0;
            part_bio = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, dm_ctx->transform_bs);
        }
        else
        {
            part_bio = bio_split(orig_bio, len, GFP_NOIO, dm_ctx->transform_bs);
        }

        if (IS_ERR_OR_NULL(part_bio))
            goto error;

        part = kzalloc(sizeof(*part), GFP_NOIO);
        if (!part)
        {
            bio_put(part_bio);
            goto error;
        }

        part->req = req;
        part->bio = part_bio;
        part->type = type;

        part_bio->bi_private = part;
        part_bio->bi_iter.bi_sector = align_data_sector(part_bio->bi_iter.bi_sector);

        part->index = start_data_sector(part_bio->bi_iter.bi_sector);

        part->lock = locker_get_lock(dm_ctx->locker, part->index);
        if (!part->lock)
        {
            bio_put(part_bio);
            kfree(part);
            goto error;
        }

        part_bio->bi_end_io = transformation_end_io;
        bio_set_dev(part_bio, dm_ctx->dev->bdev);
        INIT_WORK(&part->work, transformation_part_worker);
        list_add_tail(&part->list, &req->parts);
        atomic_inc(&req->pending);
    }

    return req;

error:
    pr_info("transformation_create: error\n");

    struct transformation_part *p;
    struct transformation_part *tmp;

    list_for_each_entry_safe(p, tmp, &req->parts, list)
    {
        locker_put_lock(dm_ctx->locker, p->index, p->lock);
        bio_put(p->bio);
        list_del(&p->list);
        kfree(p);
    }

    req->status = BLK_STS_IOERR;
    transformation_request_destroy(req);

    return NULL;
}

static void transformation_part_worker(struct work_struct *work)
{
    struct transformation_part *part = container_of(work, struct transformation_part, work);
    struct transformation_request *req = part->req;

    if (atomic_read(&req->failed))
        goto fail;

    switch (part->type)
    {
    case TRANSFORM_READ:
        down_read(&part->lock->sem);
        break;
    case TRANSFORM_WRITE:
        down_write(&part->lock->sem);
        break;
    }

    if (atomic_read(&req->failed))
    {
        switch (part->type)
        {
        case TRANSFORM_READ:
            up_read(&part->lock->sem);
            break;
        case TRANSFORM_WRITE:
            up_write(&part->lock->sem);
            break;
        }

        goto fail;
    }

    submit_bio(part->bio);
    return;

fail:
    pr_info("transformation_part_worker: error\n");

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        transformation_request_destroy(req);
}

void transformation_submit(struct transformation_request *req)
{
    struct transformation_part *part;
    struct transformation_part *tmp;

    list_for_each_entry_safe(part, tmp, &req->parts, list)
    {
        list_del(&part->list);
        queue_work(req->dm_ctx->transform_wq, &part->work);
    }
}

void transformation_end_io(struct bio *bio)
{
    struct transformation_part *part = bio->bi_private;
    struct transformation_request *req = part->req;

    if (bio->bi_status)
    {
        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;
    }

    switch (part->type)
    {
    case TRANSFORM_READ:
        up_read(&part->lock->sem);
        break;
    case TRANSFORM_WRITE:
        up_write(&part->lock->sem);
        break;
    }

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        transformation_request_destroy(req);
}
#include "transformation.h"

void complete_request(struct transformation_request *req)
{
    req->orig_bio->bi_status = req->status;
    bio_endio(req->orig_bio);
    bio_put(req->orig_bio);
    kfree(req);
}

struct transformation_request *
transformation_request_init(struct bio *orig_bio,
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

        struct transformation_part *part = transformation_part_init(part_bio, req, dm_ctx, type);
        if (!part)
            goto error;

        part_bio->bi_iter.bi_sector = align_data_sector(part_bio->bi_iter.bi_sector);
        part_bio->bi_private = part;
        part_bio->bi_end_io = transformation_end_io;
        bio_set_dev(part_bio, dm_ctx->dev->bdev);

        list_add_tail(&part->list, &req->parts);

        // прибавляем 2, так как 2 bio - один для данных и один для метаданных
        switch (part->type)
        {
        case TRANSFORM_READ:
            atomic_inc(&req->pending);
            break;
        case TRANSFORM_WRITE:
            atomic_inc(&req->pending);
            atomic_inc(&req->pending);
            break;
        }
    }

    return req;

error:
    pr_info("transformation_create: error\n");

    struct transformation_part *p;
    struct transformation_part *tmp;

    list_for_each_entry_safe(p, tmp, &req->parts, list)
    {
        list_del(&p->list);
        complete_part(p);
    }

    req->status = BLK_STS_IOERR;
    complete_request(req);

    return NULL;
}

void transformation_request_submit(struct transformation_request *req)
{
    struct transformation_part *part;
    struct transformation_part *tmp;

    list_for_each_entry_safe(part, tmp, &req->parts, list)
    {
        list_del(&part->list);
        queue_work(req->dm_ctx->transform_wq, &part->submit_work);
    }
}

void transformation_end_io(struct bio *bio)
{
    struct transformation_part *part = bio->bi_private;
    struct transformation_request *req = part->req;

    if (bio->bi_status != BLK_STS_OK)
    {
        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;
    }

    if (atomic_dec_and_test(&part->pending))
        complete_part(part);

    if (atomic_dec_and_test(&req->pending))
        complete_request(req);
}
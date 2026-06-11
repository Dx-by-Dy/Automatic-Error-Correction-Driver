#include "trn_rq.h"

void complete_trn_rq(struct trn_rq *req)
{
    req->orig_bio->bi_status = req->status;
    bio_endio(req->orig_bio);
    bio_put(req->orig_bio);
    kfree(req);
}

struct trn_rq *
trn_rq_init(struct bio *orig_bio,
                            struct dm_context *dm_ctx,
                            enum trn_p_type type)
{
    struct trn_rq *req;

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

        struct trn_p_rq *part = trn_p_rq_init(part_bio, req, dm_ctx, type);
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

    struct trn_p_rq *p;
    struct trn_p_rq *tmp;

    list_for_each_entry_safe(p, tmp, &req->parts, list)
    {
        list_del(&p->list);
        complete_trn_p_rq(p);
    }

    req->status = BLK_STS_IOERR;
    complete_trn_rq(req);

    return NULL;
}

void trn_rq_submit(struct trn_rq *req)
{
    struct trn_p_rq *part;
    struct trn_p_rq*tmp;

    list_for_each_entry_safe(part, tmp, &req->parts, list)
    {
        list_del(&part->list);
        queue_work(req->dm_ctx->transform_wq, &part->submit_work);
    }
}

void transformation_end_io(struct bio *bio)
{
    struct trn_p_rq *part = bio->bi_private;
    struct trn_rq *req = part->req;

    if (bio->bi_status != BLK_STS_OK)
    {
        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;
    }

    if (atomic_dec_and_test(&part->pending))
        complete_trn_p_rq(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
}
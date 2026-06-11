#include "trn_p_rq.h"

static void locked(struct trn_p_rq *part)
{
    switch (part->type)
    {
    case TRANSFORM_READ:
        down_read(&part->lock->sem);
        break;
    case TRANSFORM_WRITE:
        down_write(&part->lock->sem);
        break;
    }

    part->state = LOCKED;
}

static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);
    struct trn_rq *req = part->req;

    if (atomic_read(&req->failed))
        goto fail;

    locked(part);

    if (atomic_read(&req->failed))
        goto fail;

    switch (part->type)
    {
    case TRANSFORM_READ:
        submit_bio(part->meta.read->read_bio);
        break;
    case TRANSFORM_WRITE:
        if (part->meta.write->chunk_full)
            submit_bio(part->meta.write->write_bio);
        else
            submit_bio(part->meta.write->read_bio);
        break;
    }

    submit_bio(part->bio);

    return;

fail:
    pr_info("trn_p_rq_worker: error\n");

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    complete_trn_p_rq(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
}

struct trn_p_rq *
trn_p_rq_init(struct bio *part_bio,
              struct trn_rq *req,
              struct dm_context *dm_ctx,
              enum trn_p_type type)
{
    struct trn_p_rq *part;

    part = kzalloc(sizeof(*part), GFP_NOIO);
    if (!part)
    {
        return NULL;
    }

    part->index = start_data_sector(part_bio->bi_iter.bi_sector);
    part->req = req;
    part->bio = part_bio;
    part->type = type;
    atomic_set(&part->pending, 2);

    switch (part->type)
    {
    case TRANSFORM_READ:
        part->meta.read = trn_mr_rq_init(part, dm_ctx);
        if (!part->meta.read)
        {
            kfree(part);
            return NULL;
        }
        break;
    case TRANSFORM_WRITE:
        part->meta.write = trn_mw_rq_init(part, dm_ctx);
        if (!part->meta.write)
        {
            kfree(part);
            return NULL;
        }
        break;
    }

    part->lock = locker_get_lock(dm_ctx->locker, part->index);
    if (!part->lock)
    {
        switch (part->type)
        {
        case TRANSFORM_READ:
            complete_trn_mr_rq(part->meta.read);
            break;
        case TRANSFORM_WRITE:
            complete_trn_mw_rq(part->meta.write);
            break;
        }
        kfree(part);
        return NULL;
    }

    INIT_WORK(&part->submit_work, submit_work);
    switch (part->type)
    {
    case TRANSFORM_READ:
        INIT_WORK(&part->metadata_work, trn_mr_rq_work);
        break;
    case TRANSFORM_WRITE:
        INIT_WORK(&part->metadata_work, trn_mw_rq_work);
        break;
    }
    part->state = INITIALIZED;

    return part;
}

void complete_trn_p_rq(struct trn_p_rq *part)
{
    struct trn_rq *req = part->req;

    if (part->state == LOCKED)
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
    }

    switch (part->type)
    {
    case TRANSFORM_READ:
        if (part->state == LOCKED)
        {
            part->state = CHECK_CRC;
            queue_work(req->dm_ctx->transform_wq, &part->metadata_work);
            return;
        }
        complete_trn_mr_rq(part->meta.read);
        break;
    case TRANSFORM_WRITE:
        complete_trn_mw_rq(part->meta.write);
        break;
    }

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
}

void trn_p_rq_end_io(struct bio *bio)
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
}
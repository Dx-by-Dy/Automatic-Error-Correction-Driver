#include "trn_p_rq.h"
#include "trn_mw_rq.h"

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
    {
        complete_trn_p_rq(part);
        goto fail;
    }

    switch (part->type)
    {
    case TRANSFORM_READ:
        break;
    case TRANSFORM_WRITE:
        if (part->meta->chunk_full)
            submit_bio(part->meta->write_bio);
        else
            submit_bio(part->meta->read_bio);
        break;
    }

    submit_bio(part->bio);
    return;

fail:
    pr_info("trn_p_rq_worker: error\n");

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

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

    switch (part->type)
    {
    case TRANSFORM_READ:
        atomic_set(&part->pending, 1);
        break;
    case TRANSFORM_WRITE:
        atomic_set(&part->pending, 2);
        break;
    }

    part->meta = trn_mw_rq_init(part, req, dm_ctx);
    if (!part->meta)
    {
        switch (part->type)
        {
        case TRANSFORM_READ:
            break;
        case TRANSFORM_WRITE:
            kfree(part);
            return NULL;
        }
    }

    part->lock = locker_get_lock(dm_ctx->locker, part->index);
    if (!part->lock)
    {
        complete_trn_mw_rq(part->meta);
        kfree(part);
        return NULL;
    }

    INIT_WORK(&part->submit_work, submit_work);
    INIT_WORK(&part->metadata_work, trn_mw_rq_work);
    part->state = INITIALIZED;

    return part;
}

void complete_trn_p_rq(struct trn_p_rq *part)
{
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

    locker_put_lock(part->req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    complete_trn_mw_rq(part->meta);
    kfree(part);
}
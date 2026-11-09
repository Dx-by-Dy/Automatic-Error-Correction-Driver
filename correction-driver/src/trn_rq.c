#include "trn_rq.h"
#include "macros.h"

/// @brief Completes request processing and frees all resources
/// @details
/// Sets the final status to the original bio, signals
/// completion via bio_endio, and releases the captured reference
/// via bio_put.
///
/// Called when req->pending reaches 0.
///
/// Expected execution context - process.
/// @param req Request structure
void complete_trn_rq(struct trn_rq *req)
{
    DM_DEBUG("req=%p status=%d\n", req, req->status);

    req->orig_bio->bi_status = req->status;
    bio_endio(req->orig_bio);
    bio_put(req->orig_bio);
    kfree(req);
}

/// @brief Initializes struct trn_rq
/// @details
/// Captures reference to orig_bio via bio_get. Iteratively splits
/// bio by chunk boundaries: if the remainder of bio fits in the current chunk —
/// clones it, otherwise splits a part via bio_split.
///
/// For each part creates trn_p_rq, configures part_bio (physical
/// sector, bi_private, bi_end_io, device) and adds to parts list.
///
/// On error at any stage:
///   - sets the failed flag
///   - completes all already created parts via complete_work
///   - if no part was created (pending == 0) —
///     frees req directly via complete_trn_rq
///
/// Expected execution context - process.
/// @param orig_bio Original request bio
/// @param dm_ctx   Driver context
/// @param type     Transformation type (TRANSFORM_READ or TRANSFORM_WRITE)
/// @return Pointer to trn_rq on success, NULL on error
struct trn_rq *
trn_rq_init(struct bio *orig_bio,
            struct dm_context *dm_ctx,
            enum trn_p_type type)
{
    DM_DEBUG("orig_bio=%p sector=%llu size=%u type=%d\n",
             orig_bio,
             (unsigned long long)orig_bio->bi_iter.bi_sector,
             orig_bio->bi_iter.bi_size,
             type);

    struct trn_rq *req;

    req = kzalloc_obj(*req, GFP_NOIO);
    if (!req)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    bio_get(orig_bio);
    req->dm_ctx = dm_ctx;
    req->orig_bio = orig_bio;
    atomic_set(&req->pending, 0);
    atomic_set(&req->failed, 0);
    req->status = BLK_STS_OK;
    INIT_LIST_HEAD(&req->parts);

    bool last;

    do
    {
        struct bio *part_bio;
        unsigned int len;

        len = min(sectors_until_datachunk_end(orig_bio->bi_iter.bi_sector), bio_sectors(orig_bio));
        last = (len == bio_sectors(orig_bio));

        if (last)
            part_bio = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, dm_ctx->transform_bs);
        else
            part_bio = bio_split(orig_bio, len, GFP_NOIO, dm_ctx->transform_bs);

        if (IS_ERR_OR_NULL(part_bio))
        {
            DM_ERR("bio_alloc_clone/bio_split failed\n");
            goto error;
        }

        struct trn_p_rq *part = trn_p_rq_init(part_bio, req, dm_ctx, type);

        if (!part)
        {
            DM_ERR("trn_p_rq_init failed\n");
            bio_put(part_bio);
            goto error;
        }

        part_bio->bi_iter.bi_sector = align_data_sector(part_bio->bi_iter.bi_sector);
        part_bio->bi_private = part;
        part_bio->bi_end_io = trn_p_rq_end_io;
        bio_set_dev(part_bio, dm_ctx->dev->bdev);

        DM_DEBUG("part=%p\n", part);
        DM_DEBUG_BIO(part_bio);

        list_add_tail(&part->list, &req->parts);
        atomic_inc(&req->pending);

    } while (!last);

    DM_DEBUG("req=%p parts=%d\n",
             req, atomic_read(&req->pending));

    return req;

error:
    DM_ERR("failed, cleaning up\n");

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    if (!atomic_read(&req->pending))
        complete_trn_rq(req);
    else
    {
        struct trn_p_rq *p;
        struct trn_p_rq *tmp;
        LIST_HEAD(parts);

        // req may be freed once the last part is queued, so the list head must not be in it
        list_splice_init(&req->parts, &parts);

        list_for_each_entry_safe(p, tmp, &parts, list)
        {
            list_del(&p->list);
            queue_work(dm_ctx->transform_wq, &p->complete_work);
        }
    }

    return NULL;
}

/// @brief Queues all trn_p_rq in transform_wq for processing
/// @details
/// Moves the parts to a local list, removes each element and queues
/// its submit_work in transform_wq.
///
/// req may be freed as soon as the last part is queued, so it must not be
/// accessed after the first queue_work, including by the caller.
///
/// Expected execution context - process.
/// @param req Request structure
void trn_rq_submit(struct trn_rq *req)
{
    DM_DEBUG("req=%p, parts=%d\n", req, atomic_read(&req->pending));

    struct workqueue_struct *wq = req->dm_ctx->transform_wq;
    struct trn_p_rq *part;
    struct trn_p_rq *tmp;
    LIST_HEAD(parts);

    list_splice_init(&req->parts, &parts);

    list_for_each_entry_safe(part, tmp, &parts, list)
    {
        list_del(&part->list);
        queue_work(wq, &part->submit_work);
    }
}

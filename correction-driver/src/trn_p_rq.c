#include "trn_p_rq.h"
#include "macros.h"

/// @brief Function completing the structure lifecycle
/// @details
/// Called when part->pending reaches 0, or at once by submit_work when the
/// part failed before any I/O.
///
/// TRANSFORM_READ: leaves the tree of reads of the cache and on a successful
/// read verifies the CRCs with check_crc.
///
/// TRANSFORM_WRITE: releases the metadata bio.
///
/// Finally gives back the place of the part among the parts in flight, and
/// hands bio back to device mapper with the status of the part.
/// This frees the part, as it lives in the per-bio data of bio.
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->complete_work
static void complete_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, complete_work);
    struct bio *bio = part->bio;

    DM_DEBUG("part=%p, type=%d, index=%lu\n", part, part->type, part->index);

    switch (part->type)
    {
    case TRANSFORM_READ:
        cache_read_done(part->dm_ctx->cache, &part->range);
        if (!part->status)
            check_crc(&part->meta.read);
        break;
    case TRANSFORM_WRITE:
        bio_uninit(&part->meta_bio);
        break;
    }

    up(&part->dm_ctx->parts_in_flight);

    bio->bi_end_io = part->orig_end_io;
    bio->bi_status = part->status;
    bio_endio(bio);
}

/// @brief Work handler: submits bio to device
/// @details
/// Runs from transform_wq once for each trn_p_rq.
///
/// A part whose metadata sector did not read completes at once, without I/O.
/// Otherwise submits the data bio, and for TRANSFORM_WRITE first puts the new
/// CRCs into the metadata area in RAM and submits meta_bio, which writes the
/// metadata sector from there.
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->submit_work
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (part->status)
    {
        complete_work(&part->complete_work);
        return;
    }

    if (part->type == TRANSFORM_WRITE)
    {
        update_crc_local(&part->meta.write);
        submit_bio(&part->meta_bio);
    }
    submit_bio_noacct(part->bio);
}

/// @brief Initializes struct trn_p_rq and prepares bio for the lower device
/// @details
/// Initializes fields and the metadata structure (trn_mr_rq or trn_mw_rq)
/// depending on transformation type. A read copies the entry of its chunk
/// from the metadata cache here; a write keeps the area it is given.
///
/// Initializes save_iter field of meta for TRANSFORM_READ.
///
/// Redirects bio to the physical sector on the lower device, and its
/// completion to trn_p_rq_end_io.
///
/// Expected execution context - process. A read may sleep while the metadata
/// area of its region is read, see metadata_get. Never fails to allocate.
/// @param part   Structure to initialize, the per-bio data of bio
/// @param bio    Bio with chunk data, bi_sector relative to the start of the target
/// @param dm_ctx Driver context
/// @param type   Transformation type (TRANSFORM_READ or TRANSFORM_WRITE)
/// @param area   For TRANSFORM_WRITE, the metadata area of the region of the chunk,
///               held by the caller until the part completes; NULL for TRANSFORM_READ
void trn_p_rq_init(struct trn_p_rq *part,
                   struct bio *bio,
                   struct dm_context *dm_ctx,
                   enum trn_p_type type,
                   struct metadata_area *area)
{
    DM_DEBUG("part=%p, bio=%p, type=%d\n", part, bio, type);

    part->sector = bio->bi_iter.bi_sector;
    part->index = start_data_sector(bio->bi_iter.bi_sector);
    part->metadata_sector = metadata_sector(bio->bi_iter.bi_sector);
    part->dm_ctx = dm_ctx;
    part->bio = bio;
    part->type = type;

    switch (part->type)
    {
    case TRANSFORM_READ:
        part->status = trn_mr_rq_init(&part->meta.read, part, dm_ctx);
        part->meta.read.saved_iter = bio->bi_iter;
        atomic_set(&part->pending, 1);
        break;
    case TRANSFORM_WRITE:
        part->status = trn_mw_rq_init(&part->meta.write, part, area);
        atomic_set(&part->pending, 2);
        break;
    }

    INIT_WORK(&part->submit_work, submit_work);
    INIT_WORK(&part->complete_work, complete_work);

    part->orig_end_io = bio->bi_end_io;
    bio->bi_end_io = trn_p_rq_end_io;
    bio->bi_private = part;
    bio->bi_iter.bi_sector = align_data_sector(bio->bi_iter.bi_sector);
    bio_set_dev(bio, dm_ctx->dev->bdev);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);
    DM_DEBUG_BIO(bio);
}

/// @brief Handler for completion of data and metadata bios
/// @details
/// Called upon completion of any data bio or metadata bio.
///
/// On bio error, captures status in the part.
///
/// Decrements part->pending counter of the chunk transformation request.
/// When pending == 0, starts complete_work to finish the part.
///
/// Expected execution context - softirq.
/// @param bio Completed bio
void trn_p_rq_end_io(struct bio *bio)
{
    struct trn_p_rq *part = bio->bi_private;

    DM_DEBUG("bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

    if (bio->bi_status != BLK_STS_OK)
    {
        DM_ERR_LIMIT("bio failed, bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

        WRITE_ONCE(part->status, bio->bi_status);
    }

    if (atomic_dec_and_test(&part->pending))
        queue_work(part->dm_ctx->transform_wq, &part->complete_work);
}

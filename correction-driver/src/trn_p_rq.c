#include "trn_p_rq.h"
#include "macros.h"

/// @brief Work handler: submits bio to device
/// @details
/// Runs from transform_wq once for each trn_p_rq.
///
/// Submits data bio and meta_bio, which trn_mr_rq_init or trn_mw_rq_init set up:
///   - TRANSFORM_READ:  reads the metadata
///   - TRANSFORM_WRITE: reads the old metadata sector, shared with the neighbouring chunks
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->submit_work
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    submit_bio(&part->meta_bio);
    submit_bio_noacct(part->bio);
}

/// @brief Function advancing state machine and completing structure lifecycle
/// @details
/// Called when part->pending reaches 0.
///
/// Completion logic depends on type:
///
/// TRANSFORM_READ:
///   Leaves the tree of reads of the cache and on successful read launches
///   check_crc with subsequent resource cleanup.
///
/// TRANSFORM_WRITE:
///   If the data was written and the old metadata sector read, merges the new
///   CRCs into it and submits meta_bio again to write it.
///   Transitions state to CRC_UPDATE.
///
///   After CRC_UPDATE, or on an error — frees metadata.
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

    DM_DEBUG("part=%p, state=%d, type=%d, index=%lu\n", part, part->state, part->type, part->index);

    switch (part->type)
    {
    case TRANSFORM_READ:
        cache_read_done(part->dm_ctx->cache, &part->range);
        if (!part->status)
            check_crc(&part->meta.read);
        complete_trn_mr_rq(&part->meta.read);
        break;
    case TRANSFORM_WRITE:
        if (part->state == SUBMITTED && !part->status)
        {
            part->state = CRC_UPDATE;
            update_crc_local(&part->meta.write);
            bio_uninit(&part->meta_bio);
            metadata_bio_init(part, part->meta.write.page, 0, metadata_write_opf(bio));
            atomic_inc(&part->pending);
            submit_bio(&part->meta_bio);
            return;
        }
        complete_trn_mw_rq(&part->meta.write);
        break;
    }

    up(&part->dm_ctx->parts_in_flight);

    bio->bi_end_io = part->orig_end_io;
    bio->bi_status = part->status;
    bio_endio(bio);
}

/// @brief Initializes struct trn_p_rq and prepares bio for the lower device
/// @details
/// Initializes fields and the metadata structure (trn_mr_rq or trn_mw_rq)
/// depending on transformation type.
///
/// Initializes save_iter field of meta for TRANSFORM_READ.
///
/// Pending counter is initialized to 2: data bio + metadata bio.
///
/// Redirects bio to the physical sector on the lower device, and its
/// completion to trn_p_rq_end_io.
///
/// Expected execution context - process, may sleep: waits for a metadata page
/// if memory is short, and never fails.
/// @param part   Structure to initialize, the per-bio data of bio
/// @param bio    Bio with chunk data, bi_sector relative to the start of the target
/// @param dm_ctx Driver context
/// @param type   Transformation type (TRANSFORM_READ or TRANSFORM_WRITE)
void trn_p_rq_init(struct trn_p_rq *part,
                   struct bio *bio,
                   struct dm_context *dm_ctx,
                   enum trn_p_type type)
{
    DM_DEBUG("part=%p, bio=%p, type=%d\n", part, bio, type);

    part->index = start_data_sector(bio->bi_iter.bi_sector);
    part->metadata_sector = metadata_sector(bio->bi_iter.bi_sector);
    part->metadata_offset = metadata_offset(bio->bi_iter.bi_sector);
    part->dm_ctx = dm_ctx;
    part->bio = bio;
    part->type = type;
    part->status = BLK_STS_OK;
    part->state = SUBMITTED;
    atomic_set(&part->pending, 2);

    switch (part->type)
    {
    case TRANSFORM_READ:
        trn_mr_rq_init(&part->meta.read, part, dm_ctx);
        part->meta.read.saved_iter = bio->bi_iter;
        break;
    case TRANSFORM_WRITE:
        trn_mw_rq_init(&part->meta.write, part, dm_ctx);
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
/// When pending == 0, starts complete_work to advance the state machine.
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

#include "trn_p_rq.h"
#include "macros.h"

/// @brief Function completing the structure lifecycle
/// @details
/// Called when the data bio completes, when the metadata bio of a write
/// fails, as the data is then not sent, or at once by submit_work when the
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
/// Runs from transform_wq once for a read and twice for a write.
///
/// A part whose metadata sector did not read completes at once, without I/O.
/// A read submits its data bio. A write first puts the new CRCs into the
/// leading copy in the metadata area in RAM and submits meta_bio, which writes
/// that sector from there with FUA; trn_p_rq_meta_end_io runs this again once
/// it is durable, and the data bio goes then. So after a crash the trailing
/// copy still has the CRC of the old data, and the leading one of the new.
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

    if (part->type == TRANSFORM_WRITE && !part->meta_written)
    {
        update_crc_local(&part->meta.write);
        submit_bio(&part->meta_bio);
        return;
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
    part->index = start_data_sector(&dm_ctx->sb.layout, bio->bi_iter.bi_sector);
    part->metadata_sector = metadata_sector(&dm_ctx->sb.layout, bio->bi_iter.bi_sector);
    part->dm_ctx = dm_ctx;
    part->bio = bio;
    part->type = type;

    switch (part->type)
    {
    case TRANSFORM_READ:
        part->status = trn_mr_rq_init(&part->meta.read, part, dm_ctx);
        part->meta.read.saved_iter = bio->bi_iter;
        break;
    case TRANSFORM_WRITE:
        part->meta_written = false;
        part->status = trn_mw_rq_init(&part->meta.write, part, area);
        break;
    }

    INIT_WORK(&part->submit_work, submit_work);
    INIT_WORK(&part->complete_work, complete_work);

    part->orig_end_io = bio->bi_end_io;
    bio->bi_end_io = trn_p_rq_end_io;
    bio->bi_private = part;
    bio->bi_iter.bi_sector = align_data_sector(&dm_ctx->sb.layout, bio->bi_iter.bi_sector);
    bio_set_dev(bio, dm_ctx->dev->bdev);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);
    DM_DEBUG_BIO(bio);
}

/// @brief Handler for completion of the data bio
/// @details
/// On bio error, captures status in the part, then starts complete_work.
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

    queue_work(part->dm_ctx->transform_wq, &part->complete_work);
}

/// @brief Handler for completion of the metadata bio of a write
/// @details
/// On success the leading sector is durable, so submit_work runs again to
/// send the data. On error the data is not sent and the part completes with
/// the error: the device keeps the old data, which the trailing copy matches.
///
/// Expected execution context - softirq.
/// @param bio Completed metadata bio
void trn_p_rq_meta_end_io(struct bio *bio)
{
    struct trn_p_rq *part = bio->bi_private;

    if (bio->bi_status != BLK_STS_OK)
    {
        DM_ERR_LIMIT("metadata write failed, status=%d, sector=%llu\n", bio->bi_status,
                     (unsigned long long)part->metadata_sector);
        WRITE_ONCE(part->status, bio->bi_status);
        queue_work(part->dm_ctx->transform_wq, &part->complete_work);
        return;
    }

    part->meta_written = true;
    queue_work(part->dm_ctx->transform_wq, &part->submit_work);
}

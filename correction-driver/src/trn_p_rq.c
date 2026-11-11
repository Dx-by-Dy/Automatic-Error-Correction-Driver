#include "trn_p_rq.h"
#include "macros.h"

/// @brief Checks whether the chunk lock is compatible with its current holders
/// @details
/// Readers share the lock, a writer needs it alone.
///
/// Expected to be called with chunk->wait_lock held.
/// @param chunk The lock of the chunk
/// @param type  Transformation type of the part asking for the lock
/// @return true if the part can hold the lock along with the current holders
static bool chunk_lock_available(const struct lock *chunk, enum trn_p_type type)
{
    if (chunk->writer)
        return false;

    return type == TRANSFORM_READ || !chunk->readers;
}

/// @brief Makes a part a holder of the chunk lock
/// @details
/// Sets part->state = LOCKED, which submit_work relies on when the part
/// was waiting and is queued again.
///
/// Expected to be called with chunk->wait_lock held.
/// @param chunk The lock of the chunk
/// @param part  Chunk transformation structure
static void chunk_lock_grant(struct lock *chunk, struct trn_p_rq *part)
{
    if (part->type == TRANSFORM_READ)
        chunk->readers++;
    else
        chunk->writer = true;

    part->state = LOCKED;
}

/// @brief Takes the chunk lock, or joins the list of waiting parts
/// @details
/// Never sleeps on the chunk, so a worker is never held by a chunk, and the
/// complete_work that releases the lock can always run.
///
/// The list is strictly in order of arrival: a part does not overtake the
/// waiting ones even if it is compatible with the holders, so a stream of
/// reads cannot starve a write.
///
/// If this returns false, the part may be running elsewhere and may even be
/// freed already, so the caller must not touch it. The chunk_unlock that
/// grants the lock queues its submit_work again.
///
/// Expected execution context - process.
/// @param part Chunk transformation structure
/// @return true if the lock is taken, false if the part is waiting
static bool chunk_lock(struct trn_p_rq *part)
{
    struct lock *chunk = part->lock;
    bool locked;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    spin_lock(&chunk->wait_lock);
    locked = list_empty(&chunk->waiters) && chunk_lock_available(chunk, part->type);
    if (locked)
        chunk_lock_grant(chunk, part);
    else
        list_add_tail(&part->list, &chunk->waiters);
    spin_unlock(&chunk->wait_lock);

    return locked;
}

/// @brief Releases the chunk lock and starts the parts that can take it now
/// @details
/// Grants the lock from the head of the list until a part is not compatible:
/// one writer, or all readers up to the next writer. The parts are queued
/// after wait_lock is dropped, and queueing one may free it at once, so the
/// list they are on is local.
///
/// Expected execution context - process.
/// @param part Chunk transformation structure
static void chunk_unlock(struct trn_p_rq *part)
{
    struct workqueue_struct *wq = part->dm_ctx->transform_wq;
    struct lock *chunk = part->lock;
    struct trn_p_rq *next;
    struct trn_p_rq *tmp;
    LIST_HEAD(granted);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    spin_lock(&chunk->wait_lock);

    if (part->type == TRANSFORM_READ)
        chunk->readers--;
    else
        chunk->writer = false;

    list_for_each_entry_safe(next, tmp, &chunk->waiters, list)
    {
        if (!chunk_lock_available(chunk, next->type))
            break;

        chunk_lock_grant(chunk, next);
        list_move_tail(&next->list, &granted);
    }

    spin_unlock(&chunk->wait_lock);

    list_for_each_entry_safe(next, tmp, &granted, list)
    {
        list_del(&next->list);
        queue_work(wq, &next->submit_work);
    }
}

/// @brief Work handler: acquires chunk lock and submits bio to device
/// @details
/// Runs from transform_wq for each trn_p_rq, and once more if the part had to
/// wait for the lock: then part->state is already LOCKED.
///
/// Submits data bio and meta_bio, which trn_mr_rq_init or trn_mw_rq_init set up:
///   - TRANSFORM_READ:  reads the metadata
///   - TRANSFORM_WRITE: writes the metadata (chunk_full) or reads the old one (partial write)
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->submit_work
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (part->state == INITIALIZED && !chunk_lock(part))
        return;

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
///   Releases read lock and on successful read launches check_crc
///   with subsequent resource cleanup.
///
/// TRANSFORM_WRITE:
///   If chunk_full == false — updates CRC locally and
///   submits meta_bio again to update CRC on disk.
///   Transitions state to CRC_UPDATE.
///
///   If chunk_full == true — releases write lock and frees metadata.
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
        chunk_unlock(part);
        if (!part->status)
            check_crc(&part->meta.read);
        complete_trn_mr_rq(&part->meta.read);
        break;
    case TRANSFORM_WRITE:
        if (part->state == LOCKED && !part->meta.write.chunk_full && !part->status)
        {
            part->state = CRC_UPDATE;
            update_crc_local(&part->meta.write);
            bio_uninit(&part->meta_bio);
            metadata_bio_init(part, part->meta.write.page, 0, metadata_write_opf(bio));
            atomic_inc(&part->pending);
            submit_bio(&part->meta_bio);
            return;
        }
        chunk_unlock(part);
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
/// Finds the chunk lock in the lock table by the index of
/// the start of the chunk's data area.
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
    part->dm_ctx = dm_ctx;
    part->bio = bio;
    part->type = type;
    part->status = BLK_STS_OK;
    part->state = INITIALIZED;
    part->lock = locker_lock_of(&dm_ctx->locker, part->index);
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
        DM_ERR("bio failed, bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

        WRITE_ONCE(part->status, bio->bi_status);
    }

    if (atomic_dec_and_test(&part->pending))
        queue_work(part->dm_ctx->transform_wq, &part->complete_work);
}

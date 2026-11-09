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
/// Does nothing unless part->state == LOCKED or part->state == CRC_UPDATE.
///
/// Grants the lock from the head of the list until a part is not compatible:
/// one writer, or all readers up to the next writer. The parts are queued
/// after wait_lock is dropped, and queueing one may free it at once, so the
/// list they are on is local.
///
/// Expected execution context - process.
/// @param part Chunk transformation structure
static void chunk_unlock(struct trn_p_rq *part)
{
    struct workqueue_struct *wq = part->req->dm_ctx->transform_wq;
    struct lock *chunk = part->lock;
    struct trn_p_rq *next;
    struct trn_p_rq *tmp;
    LIST_HEAD(granted);

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (part->state != LOCKED && part->state != CRC_UPDATE)
        return;

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
/// First checks the failed flag of parent trn_rq — if another chunk has
/// already completed with error, immediately transitions to completion
/// without sending bio. complete_work releases the lock if the part holds it.
///
/// On success, submits data bio and chunk metadata depending on transformation type:
///   - TRANSFORM_READ:  metadata reading bio
///   - TRANSFORM_WRITE: write_bio (chunk_full) or read_bio (partial write)
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->submit_wor
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);
    struct trn_rq *req = part->req;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (atomic_read(&req->failed))
        goto fail;

    if (part->state == INITIALIZED && !chunk_lock(part))
        return;

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
    DM_ERR("req failed before submission, part=%p, index=%lu, status=%d\n", part, part->index, req->status);

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    queue_work(req->dm_ctx->transform_wq, &part->complete_work);
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
///   submits write_bio to update CRC on disk.
///   Transitions state to CRC_UPDATE.
///
///   If chunk_full == true — releases write lock and frees
///   metadata, bio, structure, and decrements req->pending.
///
/// If req->pending reaches 0 — calls complete_trn_rq.
///
/// Expected execution context - process.
/// @param work Pointer to work_struct embedded in part->complete_work
static void complete_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, complete_work);
    struct trn_rq *req = part->req;

    DM_DEBUG("part=%p, state=%d, type=%d, index=%lu\n", part, part->state, part->type, part->index);

    switch (part->type)
    {
    case TRANSFORM_READ:
        chunk_unlock(part);
        if (part->state == LOCKED && !atomic_read(&req->failed))
            check_crc(part->meta.read);
        complete_trn_mr_rq(part->meta.read);
        break;
    case TRANSFORM_WRITE:
        if (part->state == LOCKED && !part->meta.write->chunk_full && !atomic_read(&req->failed))
        {
            part->state = CRC_UPDATE;
            update_crc_local(part->meta.write);
            atomic_inc(&part->pending);
            submit_bio(part->meta.write->write_bio);
            return;
        }
        chunk_unlock(part);
        complete_trn_mw_rq(part->meta.write);
        break;
    }

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
}

/// @brief Initializes struct trn_p_rq
/// @details
/// Allocates memory for trn_p_rq, initializes fields, and creates
/// metadata structure (trn_mr_rq or trn_mw_rq) depending
/// on transformation type.
///
/// Obtains chunk lock via locker_get_lock by the index of
/// the start of the chunk's data area.
///
/// Initializes save_iter field of meta for TRANSFORM_READ.
///
/// Pending counter is initialized to 2: data bio + metadata bio.
///
/// Expected execution context - process.
///
/// On error, frees all resources.
/// @param part_bio Bio with chunk data
/// @param req      Parent struct trn_rq
/// @param dm_ctx   Driver context
/// @param type     Transformation type (TRANSFORM_READ or TRANSFORM_WRITE)
/// @return Pointer to trn_p_rq on success, NULL on error
struct trn_p_rq *
trn_p_rq_init(struct bio *part_bio,
              struct trn_rq *req,
              struct dm_context *dm_ctx,
              enum trn_p_type type)
{
    DM_DEBUG("part_bio=%p, req=%p, type=%d\n", part_bio, req, type);

    struct trn_p_rq *part;

    part = kzalloc_obj(*part, GFP_NOIO);
    if (!part)
    {
        DM_ERR("kzalloc failed\n");
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
            DM_ERR("trn_mr_rq_init failed\n");
            kfree(part);
            return NULL;
        }
        part->meta.read->saved_iter = part_bio->bi_iter;
        break;
    case TRANSFORM_WRITE:
        part->meta.write = trn_mw_rq_init(part, dm_ctx);
        if (!part->meta.write)
        {
            DM_ERR("trn_mw_rq_init failed\n");
            kfree(part);
            return NULL;
        }
        break;
    }

    part->lock = locker_get_lock(dm_ctx->locker, part->index);
    if (!part->lock)
    {
        DM_ERR("locker_get_lock failed\n");
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
    INIT_WORK(&part->complete_work, complete_work);
    part->state = INITIALIZED;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    return part;
}

/// @brief Handler for completion of data and metadata bios
/// @details
/// Called upon completion of any data bio or metadata bio.
///
/// On bio error, captures status in parent struct trn_rq.
///
/// Decrements part->pending counter of the chunk transformation request.
/// When pending == 0, starts complete_work to advance the state machine.
///
/// Expected execution context - softirq.
/// @param bio Completed bio
void trn_p_rq_end_io(struct bio *bio)
{
    struct trn_p_rq *part = bio->bi_private;
    struct trn_rq *req = part->req;

    DM_DEBUG("bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

    if (bio->bi_status != BLK_STS_OK)
    {
        DM_ERR("bio failed, bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;
    }

    if (atomic_dec_and_test(&part->pending))
        queue_work(req->dm_ctx->transform_wq, &part->complete_work);
}

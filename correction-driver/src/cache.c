#include <linux/blkdev.h>
#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include "corrdm.h"
#include "cache.h"
#include "trn_p_rq.h"
#include "macros.h"

/// @brief Lower write of one run of dirty sectors of an entry
/// @details
/// The bio goes through the same path as a write did before the cache: a part
/// in trn_p_rq writes the data and the metadata, merging the CRCs of the other
/// sectors for a partial chunk. Jobs come from a table allocated in cache_create.
struct cache_job
{
    /// @brief Part that writes the bio, as the per-bio data of device mapper would hold it
    struct trn_p_rq part;

    /// @brief Bio over the page of the entry
    struct bio bio;

    /// @brief The only segment of bio
    struct bio_vec bvec;

    /// @brief Entry written back
    struct cache_entry *entry;

    /// @brief Cache of the entry
    struct cache *cache;

    /// @brief Node in the list of free jobs, or in the queued list of the job in flight on its sector
    struct list_head list;

    /// @brief Node in the tree of jobs in flight of the cache, while in flight
    struct rb_node node;

    /// @brief Number of the metadata sector of the chunk: the chunk divided by CHUNKS_PER_METADATA_SECTOR
    sector_t sector;

    /// @brief While in flight, jobs of the same metadata sector waiting for it, see cache_submit_job
    struct list_head queued;
};

/// @brief Free entries below which the worker writes back under pressure
#define CACHE_START_FREE (CACHE_ENTRIES * (100 - CACHE_START_PERCENT) / 100)

/// @brief Free entries, counting those under write back, that end the pressure
#define CACHE_STOP_FREE (CACHE_ENTRIES * (100 - CACHE_STOP_PERCENT) / 100)

/// @brief Mask of a run of sectors of a chunk
static inline u8 sector_mask(unsigned int first, unsigned int sectors)
{
    return (u8)(((1U << sectors) - 1) << first);
}

/// @brief Length of the run of sectors from first that are all in mask, or all not in it
/// @param mask    Mask of the entry
/// @param first   First sector of the run, within the chunk
/// @param sectors Most sectors the run may have
/// @param set     Whether the run is of sectors in mask
static unsigned int run_length(u8 mask, unsigned int first, unsigned int sectors, bool set)
{
    unsigned int n = 0;

    while (n < sectors && !!(mask & BIT(first + n)) == set)
        n++;

    return n;
}

/// @brief Finds the entry of a chunk in the tree; the lock must be held
static struct cache_entry *cache_find(struct cache *cache, sector_t chunk)
{
    struct rb_node *node = cache->tree.rb_node;

    while (node)
    {
        struct cache_entry *entry = rb_entry(node, struct cache_entry, node);

        if (chunk < entry->chunk)
            node = node->rb_left;
        else if (chunk > entry->chunk)
            node = node->rb_right;
        else
            return entry;
    }

    return NULL;
}

/// @brief Puts an entry into the tree; the lock must be held and the chunk must not be there
static void cache_insert(struct cache *cache, struct cache_entry *entry)
{
    struct rb_node **link = &cache->tree.rb_node;
    struct rb_node *parent = NULL;

    while (*link)
    {
        struct cache_entry *other = rb_entry(*link, struct cache_entry, node);

        parent = *link;
        link = entry->chunk < other->chunk ? &(*link)->rb_left : &(*link)->rb_right;
    }

    rb_link_node(&entry->node, parent, link);
    rb_insert_color(&entry->node, &cache->tree);
}

/// @brief Puts a read of a chunk into the tree of reads in flight; the lock must be held
static void cache_insert_read(struct cache *cache, struct cache_range *range, sector_t chunk)
{
    struct rb_node **link = &cache->reads.rb_node;
    struct rb_node *parent = NULL;

    range->chunk = chunk;

    while (*link)
    {
        struct cache_range *other = rb_entry(*link, struct cache_range, node);

        parent = *link;
        link = range->chunk < other->chunk ? &(*link)->rb_left : &(*link)->rb_right;
    }

    rb_link_node(&range->node, parent, link);
    rb_insert_color(&range->node, &cache->reads);
}

/// @brief Whether a read of a chunk is in flight; the lock must be held
static bool cache_reads_on(struct cache *cache, sector_t chunk)
{
    struct rb_node *node = cache->reads.rb_node;

    while (node)
    {
        struct cache_range *range = rb_entry(node, struct cache_range, node);

        if (chunk < range->chunk)
            node = node->rb_left;
        else if (chunk > range->chunk)
            node = node->rb_right;
        else
            return true;
    }

    return false;
}

/// @brief Finds the job in flight on a metadata sector; the lock must be held
static struct cache_job *cache_find_sector(struct cache *cache, sector_t sector)
{
    struct rb_node *node = cache->sectors.rb_node;

    while (node)
    {
        struct cache_job *job = rb_entry(node, struct cache_job, node);

        if (sector < job->sector)
            node = node->rb_left;
        else if (sector > job->sector)
            node = node->rb_right;
        else
            return job;
    }

    return NULL;
}

/// @brief Puts a job into the tree of jobs in flight; the lock must be held and its sector must not be there
static void cache_insert_sector(struct cache *cache, struct cache_job *job)
{
    struct rb_node **link = &cache->sectors.rb_node;
    struct rb_node *parent = NULL;

    while (*link)
    {
        struct cache_job *other = rb_entry(*link, struct cache_job, node);

        parent = *link;
        link = job->sector < other->sector ? &(*link)->rb_left : &(*link)->rb_right;
    }

    rb_link_node(&job->node, parent, link);
    rb_insert_color(&job->node, &cache->sectors);
}

/// @brief Hands the place of a job in the tree of jobs in flight to the first job queued on it
/// @details The lock must be held. The other queued jobs go on waiting for next.
static void cache_pass_sector(struct cache *cache, struct cache_job *job, struct cache_job *next)
{
    list_del_init(&next->list);
    list_splice_init(&job->queued, &next->queued);
    rb_replace_node(&job->node, &next->node, &cache->sectors);
}

/// @brief Records that waiters may go on; the lock must be held, wake them after dropping it
static void cache_event(struct cache *cache)
{
    cache->events++;
}

/// @brief Waits for the events of the cache to change; called with the lock held, returns with it held
static void cache_wait(struct cache *cache)
{
    u64 seen = cache->events;

    spin_unlock(&cache->lock);
    wait_event(cache->wait, READ_ONCE(cache->events) != seen);
    spin_lock(&cache->lock);
}

/// @brief Runs the worker now
static void cache_kick(struct cache *cache)
{
    mod_delayed_work(cache->wq, &cache->write_back, 0);
}

/// @brief Runs the worker once the oldest dirty entry is old enough, unless it is due sooner
static void cache_schedule(struct cache *cache)
{
    queue_delayed_work(cache->wq, &cache->write_back, msecs_to_jiffies(CACHE_AGE_MS));
}

/// @brief Copies the data of a write into an entry, at the place of its first sector in the chunk
static void copy_to_entry(struct cache_entry *entry, struct bio *bio, unsigned int first)
{
    char *base = kmap_local_page(entry->page);
    unsigned int offset = first << SECTOR_SHIFT;
    struct bio_vec bvec;
    struct bvec_iter iter;

    bio_for_each_segment(bvec, bio, iter)
    {
        memcpy_from_bvec(base + offset, &bvec);
        offset += bvec.bv_len;
    }

    kunmap_local(base);
}

/// @brief Copies sectors of an entry into the start of a read
static void copy_from_entry(struct cache_entry *entry, struct bio *bio,
                            unsigned int first, unsigned int sectors)
{
    char *base = kmap_local_page(entry->page);
    unsigned int offset = first << SECTOR_SHIFT;
    struct bvec_iter start = bio->bi_iter;
    struct bio_vec bvec;
    struct bvec_iter iter;

    start.bi_size = sectors << SECTOR_SHIFT;
    __bio_for_each_segment(bvec, bio, iter, start)
    {
        memcpy_to_bvec(&bvec, base + offset);
        offset += bvec.bv_len;
    }

    kunmap_local(base);
}

/// @brief Moves the failed entries back to the dirty ones, so the worker tries them again
static void cache_retry_failed(struct cache *cache)
{
    struct cache_entry *entry;

    list_for_each_entry(entry, &cache->failed, list)
        entry->state = CACHE_DIRTY;
    list_splice_tail_init(&cache->failed, &cache->dirty);
    cache->nr_dirty += cache->nr_failed;
    cache->nr_failed = 0;
}

/// @brief Writes a bio into the cache
/// @details
/// Device mapper splits requests at chunk boundaries, so the bio is within one
/// chunk. Waits while the entry of the chunk is under write back, or while no
/// entry is free; then copies the data and completes the bio at once. A FUA
/// write completes once the worker has written back everything and flushed
/// the device below. With no free entry and nothing that could free one, as
/// all entries failed to write back, the write fails.
///
/// Expected execution context - dm_map, may sleep.
/// @param cache The cache of the device
/// @param bio   Write with bi_sector relative to the start of the target
void cache_write(struct cache *cache, struct bio *bio)
{
    sector_t chunk = bio->bi_iter.bi_sector / DATA_SIZE_SECTORS;
    unsigned int first = bio->bi_iter.bi_sector % DATA_SIZE_SECTORS;
    bool fua = bio->bi_opf & REQ_FUA;
    struct cache_entry *entry;
    bool kick;

    spin_lock(&cache->lock);
    for (;;)
    {
        entry = cache_find(cache, chunk);
        if (entry && entry->state != CACHE_WRITING)
            break;

        if (entry)
        {
            atomic64_inc(&cache->busy_waits);
            cache_wait(cache);
            continue;
        }

        if (!list_empty(&cache->free))
        {
            entry = list_first_entry(&cache->free, struct cache_entry, list);
            list_del_init(&entry->list);
            cache->nr_free--;
            entry->chunk = chunk;
            entry->mask = 0;
            cache_insert(cache, entry);
            break;
        }

        if (!cache->nr_dirty && !cache->nr_writing)
        {
            spin_unlock(&cache->lock);
            DM_ERR_LIMIT("no entry for chunk %llu: the cache is full of chunks that failed to write back\n",
                         (unsigned long long)chunk);
            bio_io_error(bio);
            return;
        }

        atomic64_inc(&cache->free_waits);
        spin_unlock(&cache->lock);
        cache_kick(cache);
        spin_lock(&cache->lock);
        if (list_empty(&cache->free) && (cache->nr_dirty || cache->nr_writing))
            cache_wait(cache);
    }

    copy_to_entry(entry, bio, first);
    entry->mask |= sector_mask(first, bio_sectors(bio));

    if (entry->state != CACHE_DIRTY)
    {
        if (entry->state == CACHE_FAILED)
        {
            list_del_init(&entry->list);
            cache->nr_failed--;
        }
        entry->state = CACHE_DIRTY;
        entry->dirtied = jiffies;
        list_add_tail(&entry->list, &cache->dirty);
        cache->nr_dirty++;
    }

    kick = fua || cache->nr_free < CACHE_START_FREE;
    if (fua)
        bio_list_add(&cache->flushes, bio);
    spin_unlock(&cache->lock);

    if (kick)
        cache_kick(cache);
    else
        cache_schedule(cache);

    if (!fua)
        bio_endio(bio);
}

/// @brief Serves the start of a read from the cache, or tells the caller to read it from below
/// @details
/// Cuts the bio, with dm_accept_partial_bio, to the run of sectors from its
/// start that are all in the cache or all not in it; device mapper sends the
/// rest as another bio. A run in the cache is copied and completed here.
///
/// A run not in the cache goes to the device below by the caller. It is put
/// into the tree of reads first, under the same hold of the lock, and stays
/// there until cache_read_done, so a write back of the chunk waits for it. If
/// the chunk is under write back already, the read waits for it to end
/// instead: the sectors are not written back, but a stream of such reads would
/// otherwise keep the write back waiting for ever. A write of those sectors
/// that comes meanwhile is concurrent with the read, so the read may return the
/// data from before it.
///
/// Expected execution context - dm_map, may sleep.
/// @param cache The cache of the device
/// @param bio   Read with bi_sector relative to the start of the target
/// @param range Free node in the per-bio data of the bio, used if it is read from below
/// @return true if the bio was completed, false if it has to be read from below
bool cache_read(struct cache *cache, struct bio *bio, struct cache_range *range)
{
    sector_t chunk = bio->bi_iter.bi_sector / DATA_SIZE_SECTORS;
    unsigned int first = bio->bi_iter.bi_sector % DATA_SIZE_SECTORS;
    unsigned int sectors = bio_sectors(bio);
    struct cache_entry *entry;
    unsigned int run = sectors;
    bool cached = false;
    bool waited = false;

    spin_lock(&cache->lock);
    for (;;)
    {
        entry = cache_find(cache, chunk);
        if (!entry)
            break;

        cached = entry->mask & BIT(first);
        if (cached || entry->state != CACHE_WRITING)
        {
            run = run_length(entry->mask, first, sectors, cached);
            break;
        }

        if (!waited)
            atomic64_inc(&cache->read_waits);
        waited = true;
        cache_wait(cache);
    }

    if (cached)
        copy_from_entry(entry, bio, first, run);
    else
        cache_insert_read(cache, range, chunk);
    spin_unlock(&cache->lock);

    if (run < sectors)
        dm_accept_partial_bio(bio, run);
    if (cached)
        bio_endio(bio);

    return cached;
}

/// @brief Takes a read of the device below out of the tree of reads in flight
/// @details
/// Wakes the worker only if the chunk is under write back, as only then it may
/// wait for the read.
///
/// Expected execution context - process, complete_work of the read.
/// @param cache The cache of the device
/// @param range The node cache_read put into the tree
void cache_read_done(struct cache *cache, struct cache_range *range)
{
    struct cache_entry *entry;
    bool wake;

    spin_lock(&cache->lock);
    rb_erase(&range->node, &cache->reads);
    entry = cache_find(cache, range->chunk);
    wake = entry && entry->state == CACHE_WRITING;
    if (wake)
        cache_event(cache);
    spin_unlock(&cache->lock);

    if (wake)
        wake_up_all(&cache->wait);
}

/// @brief Hands an empty flush to the worker, which completes it
/// @details
/// Expected execution context - dm_map.
void cache_flush(struct cache *cache, struct bio *bio)
{
    spin_lock(&cache->lock);
    bio_list_add(&cache->flushes, bio);
    spin_unlock(&cache->lock);
    cache_kick(cache);
}

/// @brief Ends the write back of an entry once its last job is done; the lock must be held
/// @details
/// A written entry is freed. A failed one keeps its data and waits for a retry.
static void cache_finish_entry(struct cache *cache, struct cache_entry *entry)
{
    cache->nr_writing--;

    if (entry->status)
    {
        entry->state = CACHE_FAILED;
        list_add_tail(&entry->list, &cache->failed);
        cache->nr_failed++;
        return;
    }

    rb_erase(&entry->node, &cache->tree);
    entry->state = CACHE_FREE;
    entry->mask = 0;
    list_add(&entry->list, &cache->free);
    cache->nr_free++;
}

/// @brief Completion of a write back job
/// @details
/// complete_work of the part calls it through bio_endio, as the last thing it
/// does. Starts the next job of the metadata sector, if one is queued, which
/// takes its place in the tree of jobs in flight. The last job of an entry
/// frees it, or marks it failed.
///
/// Expected execution context - process, a worker of transform_wq.
static void cache_job_end_io(struct bio *bio)
{
    struct cache_job *job = container_of(bio, struct cache_job, bio);
    struct cache_entry *entry = job->entry;
    struct cache *cache = job->cache;
    blk_status_t status = bio->bi_status;
    sector_t chunk = entry->chunk;
    struct cache_job *next;

    bio_uninit(bio);

    spin_lock(&cache->lock);
    if (status && !entry->status)
        entry->status = status;
    list_add(&job->list, &cache->jobs);

    next = list_first_entry_or_null(&job->queued, struct cache_job, list);
    if (next)
        cache_pass_sector(cache, job, next);
    else
        rb_erase(&job->node, &cache->sectors);

    if (!--entry->jobs)
        cache_finish_entry(cache, entry);

    cache_event(cache);
    spin_unlock(&cache->lock);
    wake_up_all(&cache->wait);

    if (next)
        queue_work(cache->dm_ctx->transform_wq, &next->part.submit_work);

    if (status)
        DM_ERR_LIMIT("write back of chunk %llu failed, status=%d\n", (unsigned long long)chunk, status);
}

/// @brief Takes a free job, waiting for one if needed
/// @details Expected execution context - the worker, may sleep.
static struct cache_job *cache_get_job(struct cache *cache)
{
    struct cache_job *job;

    spin_lock(&cache->lock);
    while (list_empty(&cache->jobs))
        cache_wait(cache);
    job = list_first_entry(&cache->jobs, struct cache_job, list);
    list_del_init(&job->list);
    spin_unlock(&cache->lock);

    return job;
}

/// @brief Writes back one run of sectors of an entry
/// @details
/// The jobs of one metadata sector go one after another: a job reads the
/// sector, merges the CRCs of its own sectors and writes it back, so two jobs
/// of one sector at once would lose the CRCs of one of them. This holds for
/// the jobs of one entry and for those of the neighbouring chunks that share
/// the sector. The job starts at once if no job of its sector is in flight,
/// and is queued on the job in flight otherwise; the end of the job before it
/// starts it.
static void cache_submit_job(struct cache *cache, struct cache_entry *entry,
                             unsigned int first, unsigned int sectors)
{
    struct dm_context *dm_ctx = cache->dm_ctx;
    struct cache_job *job = cache_get_job(cache);
    struct bio *bio = &job->bio;
    struct cache_job *head;
    bool start;

    job->entry = entry;
    job->cache = cache;
    job->sector = entry->chunk / CHUNKS_PER_METADATA_SECTOR;
    INIT_LIST_HEAD(&job->queued);

    bio_init(bio, dm_ctx->dev->bdev, &job->bvec, 1, REQ_OP_WRITE);
    bio->bi_iter.bi_sector = entry->chunk * DATA_SIZE_SECTORS + first;
    bio->bi_end_io = cache_job_end_io;
    __bio_add_page(bio, entry->page, sectors << SECTOR_SHIFT, first << SECTOR_SHIFT);

    // The worker may wait here: the completions that give places back run in transform_wq.
    down(&dm_ctx->parts_in_flight);
    trn_p_rq_init(&job->part, bio, dm_ctx, TRANSFORM_WRITE);

    spin_lock(&cache->lock);
    head = cache_find_sector(cache, job->sector);
    start = !head;
    if (start)
        cache_insert_sector(cache, job);
    else
        list_add_tail(&job->list, &head->queued);
    spin_unlock(&cache->lock);

    if (start)
        queue_work(dm_ctx->transform_wq, &job->part.submit_work);
}

/// @brief Writes back an entry in CACHE_WRITING, one job per run of its sectors
/// @details
/// Writes to the entry wait until it leaves CACHE_WRITING, so its mask and its
/// page do not change while the jobs are in flight. So do new reads of its
/// clean sectors, so the reads of the chunk already in flight are waited for
/// before the first job: a read that met a job could see the data of one
/// version of a sector and the CRC of another.
static void cache_write_back_entry(struct cache *cache, struct cache_entry *entry)
{
    u8 mask = entry->mask;
    unsigned int first;
    unsigned int run;
    unsigned int jobs = 0;

    for (first = 0; first < DATA_SIZE_SECTORS; first += run)
    {
        run = run_length(mask, first, DATA_SIZE_SECTORS - first, mask & BIT(first));
        if (mask & BIT(first))
            jobs++;
    }

    spin_lock(&cache->lock);
    entry->jobs = jobs;
    entry->status = BLK_STS_OK;
    while (cache_reads_on(cache, entry->chunk))
        cache_wait(cache);
    spin_unlock(&cache->lock);

    for (first = 0; first < DATA_SIZE_SECTORS; first += run)
    {
        run = run_length(mask, first, DATA_SIZE_SECTORS - first, mask & BIT(first));
        if (mask & BIT(first))
            cache_submit_job(cache, entry, first, run);
    }
}

/// @brief Whether the worker has to write back more to keep entries free
static bool cache_under_pressure(struct cache *cache)
{
    return cache->nr_free + cache->nr_writing < CACHE_STOP_FREE;
}

/// @brief Waits for all write backs, then completes the flushes and FUA writes
/// @details
/// A flush succeeds only if no entry is left that failed to write back, and the
/// device below flushed: it promises that the data is on the device.
static void cache_complete_flushes(struct cache *cache, struct bio_list *flushes)
{
    blk_status_t status;
    unsigned long failed;
    struct bio *bio;

    wait_event(cache->wait, !READ_ONCE(cache->nr_writing));

    spin_lock(&cache->lock);
    failed = cache->nr_failed;
    spin_unlock(&cache->lock);

    if (failed)
        status = BLK_STS_IOERR;
    else
        status = errno_to_blk_status(blkdev_issue_flush(cache->dm_ctx->dev->bdev));

    while ((bio = bio_list_pop(flushes)))
    {
        bio->bi_status = status;
        bio_endio(bio);
    }
}

/// @brief The worker
/// @details
/// Writes back the dirty entries, the oldest first: all of them for a flush,
/// a FUA write or a suspend, and otherwise those older than CACHE_AGE_MS and
/// as many as keep CACHE_STOP_FREE entries free or on their way to it. A flush
/// tries the failed entries again. Then it schedules itself for the next
/// entry to come of age.
///
/// It runs on an ordered workqueue of its own, never in transform_wq, so it may
/// wait for jobs, for places among the parts in flight and for reads in flight:
/// their completions run there.
static void cache_write_back(struct work_struct *work)
{
    struct cache *cache = container_of(to_delayed_work(work), struct cache, write_back);
    struct cache_entry *entry;
    struct cache_entry *next;
    struct bio_list flushes;
    LIST_HEAD(picked);
    bool all;

    spin_lock(&cache->lock);
    flushes = cache->flushes;
    bio_list_init(&cache->flushes);
    all = cache->write_all || !bio_list_empty(&flushes);
    if (!bio_list_empty(&flushes))
        cache_retry_failed(cache);

    while (!list_empty(&cache->dirty))
    {
        entry = list_first_entry(&cache->dirty, struct cache_entry, list);
        if (!all && !cache_under_pressure(cache) &&
            time_before(jiffies, entry->dirtied + msecs_to_jiffies(CACHE_AGE_MS)))
            break;

        list_move_tail(&entry->list, &picked);
        entry->state = CACHE_WRITING;
        cache->nr_dirty--;
        cache->nr_writing++;
    }
    spin_unlock(&cache->lock);

    list_for_each_entry_safe(entry, next, &picked, list)
    {
        list_del_init(&entry->list);
        cache_write_back_entry(cache, entry);
    }

    if (!bio_list_empty(&flushes))
        cache_complete_flushes(cache, &flushes);

    spin_lock(&cache->lock);
    if (!cache->suspended && !list_empty(&cache->dirty))
    {
        unsigned long due;

        entry = list_first_entry(&cache->dirty, struct cache_entry, list);
        due = entry->dirtied + msecs_to_jiffies(CACHE_AGE_MS);
        queue_delayed_work(cache->wq, &cache->write_back,
                           time_after(due, jiffies) ? due - jiffies : 0);
    }
    spin_unlock(&cache->lock);
}

/// @brief Writes back everything before the device is suspended
/// @details
/// Called from postsuspend, when device mapper has no bio of the device in
/// flight. Tries the failed entries once more; those that fail again keep their
/// data in RAM, which is lost if the target is destroyed, as a suspend cannot fail.
///
/// Expected execution context - process, may sleep.
void cache_suspend(struct cache *cache)
{
    unsigned long failed;
    int r;

    spin_lock(&cache->lock);
    cache->write_all = true;
    cache->suspended = true;
    cache_retry_failed(cache);
    spin_unlock(&cache->lock);

    cache_kick(cache);
    wait_event(cache->wait, !READ_ONCE(cache->nr_dirty) && !READ_ONCE(cache->nr_writing));
    cancel_delayed_work_sync(&cache->write_back);

    r = blkdev_issue_flush(cache->dm_ctx->dev->bdev);
    if (r)
        DM_ERR("flush of the lower device failed on suspend, err=%d\n", r);

    spin_lock(&cache->lock);
    cache->write_all = false;
    failed = cache->nr_failed;
    spin_unlock(&cache->lock);

    if (failed)
        DM_ERR("%lu chunks failed to write back on suspend, their data is only in RAM\n", failed);
}

/// @brief Lets the worker schedule itself again after a suspend
void cache_resume(struct cache *cache)
{
    spin_lock(&cache->lock);
    cache->suspended = false;
    spin_unlock(&cache->lock);

    cache_kick(cache);
}

/// @brief Numbers of dirty and failed entries, for dmsetup status
void cache_counters(struct cache *cache, unsigned long *dirty, unsigned long *failed)
{
    spin_lock(&cache->lock);
    *dirty = cache->nr_dirty + cache->nr_writing;
    *failed = cache->nr_failed;
    spin_unlock(&cache->lock);
}

/// @brief Frees the pages of the entries and the tables
static void cache_free(struct cache *cache)
{
    if (cache->wq)
        destroy_workqueue(cache->wq);

    if (cache->entries)
    {
        for (unsigned long i = 0; i < CACHE_ENTRIES; i++)
        {
            if (cache->entries[i].page)
                __free_page(cache->entries[i].page);
        }
    }

    kvfree(cache->job_table);
    kvfree(cache->entries);
    kfree(cache);
}

/// @brief Allocates the cache whole: entries, their pages, jobs and the worker
/// @details
/// Expected execution context - dm_ctr, may sleep.
/// @param dm_ctx Driver context, with the device below already open
/// @return The cache, or ERR_PTR(-ENOMEM)
struct cache *cache_create(struct dm_context *dm_ctx)
{
    struct cache *cache = kzalloc_obj(*cache, GFP_KERNEL);

    if (!cache)
        return ERR_PTR(-ENOMEM);

    spin_lock_init(&cache->lock);
    cache->tree = RB_ROOT;
    cache->reads = RB_ROOT;
    cache->sectors = RB_ROOT;
    INIT_LIST_HEAD(&cache->free);
    INIT_LIST_HEAD(&cache->dirty);
    INIT_LIST_HEAD(&cache->failed);
    INIT_LIST_HEAD(&cache->jobs);
    bio_list_init(&cache->flushes);
    init_waitqueue_head(&cache->wait);
    INIT_DELAYED_WORK(&cache->write_back, cache_write_back);
    cache->dm_ctx = dm_ctx;
    atomic64_set(&cache->free_waits, 0);
    atomic64_set(&cache->busy_waits, 0);
    atomic64_set(&cache->read_waits, 0);

    cache->entries = kvcalloc(CACHE_ENTRIES, sizeof(*cache->entries), GFP_KERNEL);
    cache->job_table = kvcalloc(CACHE_JOBS, sizeof(*cache->job_table), GFP_KERNEL);
    cache->wq = alloc_ordered_workqueue("corrdm_write_back", WQ_MEM_RECLAIM);
    if (!cache->entries || !cache->job_table || !cache->wq)
        goto error;

    for (unsigned long i = 0; i < CACHE_ENTRIES; i++)
    {
        struct cache_entry *entry = &cache->entries[i];

        entry->page = alloc_page(GFP_KERNEL);
        if (!entry->page)
            goto error;
        RB_CLEAR_NODE(&entry->node);
        entry->state = CACHE_FREE;
        list_add_tail(&entry->list, &cache->free);
    }
    cache->nr_free = CACHE_ENTRIES;

    for (unsigned int i = 0; i < CACHE_JOBS; i++)
        list_add_tail(&cache->job_table[i].list, &cache->jobs);

    return cache;

error:
    cache_free(cache);
    return ERR_PTR(-ENOMEM);
}

/// @brief Frees the cache
/// @details
/// Device mapper suspends a device before destroying its active table, so
/// nothing is in flight and only failed entries can hold data. Their chunks
/// are lost, and named in the log.
///
/// Expected execution context - dm_dtr, may sleep.
void cache_destroy(struct cache *cache)
{
    struct cache_entry *entry;

    cancel_delayed_work_sync(&cache->write_back);

    WARN_ON(cache->nr_writing || !bio_list_empty(&cache->flushes) || !RB_EMPTY_ROOT(&cache->reads) ||
            !RB_EMPTY_ROOT(&cache->sectors));
    list_for_each_entry(entry, &cache->dirty, list)
        DM_ERR_LIMIT("chunk %llu is lost: it was never written back\n", (unsigned long long)entry->chunk);
    list_for_each_entry(entry, &cache->failed, list)
        DM_ERR_LIMIT("chunk %llu is lost: its write back failed\n", (unsigned long long)entry->chunk);
    if (cache->nr_dirty || cache->nr_failed)
        DM_ERR("%lu chunks are lost\n", cache->nr_dirty + cache->nr_failed);

    cache_free(cache);
}

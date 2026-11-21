#include <linux/blkdev.h>
#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include "dm-dcorr.h"
#include "cache.h"
#include "metadata.h"
#include "written.h"
#include "events.h"
#include "trn_p_rq.h"
#include "log.h"

/// @brief Lower write of one run of dirty sectors of an entry
/// @details
/// The bio goes through the same path as a write did before the cache: a part
/// in trn_p_rq writes the data and the metadata sector of the chunk, from the
/// metadata area of its region in RAM, which the job holds until it ends. Jobs
/// come from a table allocated in cache_create.
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

    /// @brief Metadata area of the region of the chunk, held by the job
    struct metadata_area *area;

    /// @brief Node in the list of free jobs, or in the queued list of the job in flight on its sector
    struct list_head list;

    /// @brief Node in the tree of jobs in flight of the cache, while in flight
    struct rb_node node;

    /// @brief Number of the metadata sector of the chunk: the chunk divided by DCORR_CHUNKS_PER_METADATA_SECTOR
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

/// @brief Order of two chunks or metadata sectors, for the trees of the cache
static int cache_cmp(sector_t a, sector_t b)
{
    return a < b ? -1 : a > b;
}

static int cache_entry_cmp(const void *chunk, const struct rb_node *node)
{
    return cache_cmp(*(const sector_t *)chunk, rb_entry(node, struct cache_entry, node)->chunk);
}

static bool cache_entry_less(struct rb_node *a, const struct rb_node *b)
{
    return rb_entry(a, struct cache_entry, node)->chunk < rb_entry(b, struct cache_entry, node)->chunk;
}

static int cache_lower_read_cmp(const void *chunk, const struct rb_node *node)
{
    return cache_cmp(*(const sector_t *)chunk, rb_entry(node, struct cache_lower_read, node)->chunk);
}

static bool cache_lower_read_less(struct rb_node *a, const struct rb_node *b)
{
    return rb_entry(a, struct cache_lower_read, node)->chunk < rb_entry(b, struct cache_lower_read, node)->chunk;
}

static int cache_job_cmp(const void *sector, const struct rb_node *node)
{
    return cache_cmp(*(const sector_t *)sector, rb_entry(node, struct cache_job, node)->sector);
}

static bool cache_job_less(struct rb_node *a, const struct rb_node *b)
{
    return rb_entry(a, struct cache_job, node)->sector < rb_entry(b, struct cache_job, node)->sector;
}

/// @brief Finds the entry of a chunk in the tree; the lock must be held
static struct cache_entry *cache_find(struct cache *cache, sector_t chunk)
{
    return rb_entry_safe(rb_find(&chunk, &cache->tree, cache_entry_cmp), struct cache_entry, node);
}

/// @brief Puts an entry into the tree; the lock must be held and the chunk must not be there
static void cache_insert(struct cache *cache, struct cache_entry *entry)
{
    rb_add(&entry->node, &cache->tree, cache_entry_less);
}

/// @brief Puts a read of a chunk into the tree of reads in flight; the lock must be held
static void cache_insert_read(struct cache *cache, struct cache_lower_read *lower, sector_t chunk)
{
    lower->chunk = chunk;
    rb_add(&lower->node, &cache->reads, cache_lower_read_less);
}

/// @brief Whether a read of a chunk is in flight; the lock must be held
static bool cache_reads_on(struct cache *cache, sector_t chunk)
{
    return rb_find(&chunk, &cache->reads, cache_lower_read_cmp);
}

/// @brief Finds the job in flight on a metadata sector; the lock must be held
static struct cache_job *cache_find_sector(struct cache *cache, sector_t sector)
{
    return rb_entry_safe(rb_find(&sector, &cache->sectors, cache_job_cmp), struct cache_job, node);
}

/// @brief Puts a job into the tree of jobs in flight; the lock must be held and its sector must not be there
static void cache_insert_sector(struct cache *cache, struct cache_job *job)
{
    rb_add(&job->node, &cache->sectors, cache_job_less);
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
    dcorr_event(&cache->events);
}

/// @brief Waits for the next event of the cache; called with the lock held, returns with it held
static void cache_wait(struct cache *cache)
{
    dcorr_events_wait(&cache->events, &cache->lock);
}

/// @brief Waits, without the lock, until a condition on the counters of the cache holds
/// @details
/// The completion of a job lowers nr_jobs and nr_writing, and sets the bit of
/// its chunk in the bitmap of written chunks, in one hold of the lock: the
/// condition can hold before that hold ends. So the lock is taken once after
/// the wait, and whoever goes on after it, a sync above all, sees all that
/// the completions did. By reading: no test catches the window.
#define cache_wait_until(cache, condition)                    \
    do                                                        \
    {                                                         \
        wait_event((cache)->events.wait, condition);          \
        spin_lock(&(cache)->lock);                            \
        spin_unlock(&(cache)->lock);                          \
    } while (0)

/// @brief Runs the worker now
static void cache_kick(struct cache *cache)
{
    mod_delayed_work(cache->wq, &cache->worker, 0);
}

/// @brief Runs the worker once the oldest dirty entry is old enough, unless it is due sooner
static void cache_schedule(struct cache *cache)
{
    queue_delayed_work(cache->wq, &cache->worker, msecs_to_jiffies(CACHE_AGE_MS));
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

/// @brief Takes the entry of a chunk for a write, the lock held on return
/// @details
/// Waits while the entry of the chunk is under write back, or while no entry
/// is free. With no free entry and nothing that could free one, as all
/// entries failed to write back, gives up.
///
/// Expected execution context - dcorr_map, may sleep.
/// @return The entry, with the lock held; or NULL, with the lock released
static struct cache_entry *cache_take_entry(struct cache *cache, sector_t chunk)
{
    struct cache_entry *entry;

    spin_lock(&cache->lock);
    for (;;)
    {
        entry = cache_find(cache, chunk);
        if (entry && entry->state != CACHE_WRITING)
            return entry;

        if (entry)
        {
            atomic64_inc(&cache->stats->busy_waits);
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
            return entry;
        }

        if (!cache->nr_dirty && !cache->nr_writing)
        {
            spin_unlock(&cache->lock);
            DCORR_DEV_ERR_LIMIT(cache->dc->ti, "no entry for the write at sector %llu: the cache is full of chunks that failed to write back\n",
                                (unsigned long long)(chunk * DCORR_CHUNK_SECTORS));
            return NULL;
        }

        atomic64_inc(&cache->stats->free_waits);
        spin_unlock(&cache->lock);
        cache_kick(cache);
        spin_lock(&cache->lock);
        if (list_empty(&cache->free) && (cache->nr_dirty || cache->nr_writing))
            cache_wait(cache);
    }
}

/// @brief Marks sectors of an entry written and the entry dirty; the lock must be held
static void cache_mark_dirty(struct cache *cache, struct cache_entry *entry, unsigned int first,
                             unsigned int sectors)
{
    entry->mask |= sector_mask(first, sectors);

    if (entry->state == CACHE_DIRTY)
        return;
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

/// @brief Writes a bio into the cache
/// @details
/// Device mapper splits requests at chunk boundaries, so the bio is within one
/// chunk. Takes the entry of the chunk, see cache_take_entry, copies the data
/// and completes the bio at once. A FUA write completes once the worker has
/// written back everything and flushed the lower device. With no entry to
/// take, the write fails.
///
/// Expected execution context - dcorr_map, may sleep.
/// @param cache The cache of the device
/// @param bio   Write with bi_sector relative to the start of the target
void cache_write(struct cache *cache, struct bio *bio)
{
    sector_t chunk = bio->bi_iter.bi_sector / DCORR_CHUNK_SECTORS;
    unsigned int first = bio->bi_iter.bi_sector % DCORR_CHUNK_SECTORS;
    bool fua = bio->bi_opf & REQ_FUA;
    struct cache_entry *entry;
    bool kick;

    entry = cache_take_entry(cache, chunk);
    if (!entry)
    {
        bio_io_error(bio);
        return;
    }

    copy_to_entry(entry, bio, first);
    cache_mark_dirty(cache, entry, first, bio_sectors(bio));

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

/// @brief Writes zeros into sectors of one chunk in the cache, as a write of zeros would
/// @return 0, or -EIO if no entry could be taken
static int cache_zero(struct cache *cache, sector_t sector, unsigned int sectors)
{
    unsigned int first = sector % DCORR_CHUNK_SECTORS;
    struct cache_entry *entry;
    bool kick;

    entry = cache_take_entry(cache, sector / DCORR_CHUNK_SECTORS);
    if (!entry)
        return -EIO;

    memzero_page(entry->page, first << SECTOR_SHIFT, sectors << SECTOR_SHIFT);
    cache_mark_dirty(cache, entry, first, sectors);
    kick = cache->nr_free < CACHE_START_FREE;
    spin_unlock(&cache->lock);

    if (kick)
        cache_kick(cache);
    else
        cache_schedule(cache);
    return 0;
}

/// @brief Zeroes the range of a write zeroes bio, and completes it
/// @details
/// Device mapper does not split write zeroes at chunks. The partial chunks at
/// its ends are written as zeros through the cache, as a write would be; its
/// whole chunks go to the worker as a discard does, see cache_discard_bios,
/// and read as zeros once their bits are cleared. REQ_NOUNMAP changes nothing:
/// nothing is passed down. Like a write, it is durable after the next flush;
/// with REQ_FUA it completes once the worker has flushed.
///
/// Expected execution context - dcorr_map, may sleep.
/// @param cache The cache of the device
/// @param bio   Write zeroes with bi_sector relative to the start of the target, outside any read only range
void cache_write_zeroes(struct cache *cache, struct bio *bio)
{
    sector_t start = bio->bi_iter.bi_sector;
    sector_t end = bio_end_sector(bio);
    sector_t head = min_t(sector_t, end, round_up(start, DCORR_CHUNK_SECTORS));
    sector_t tail = max_t(sector_t, head, round_down(end, DCORR_CHUNK_SECTORS));

    if ((start < head && cache_zero(cache, start, head - start)) ||
        (tail < end && cache_zero(cache, tail, end - tail)))
    {
        bio_io_error(bio);
        return;
    }

    if (head < tail)
        cache_discard(cache, bio);
    else if (bio->bi_opf & REQ_FUA)
        cache_flush(cache, bio);
    else
        bio_endio(bio);
}

/// @brief Serves the start of a read from the cache, or tells the caller to read it from below
/// @details
/// Cuts the bio, with dm_accept_partial_bio, to the run of sectors from its
/// start that are all in the cache or all not in it; device mapper sends the
/// rest as another bio. A run in the cache is copied and completed here.
///
/// A run not in the cache of a chunk never written back, whose bit in the
/// bitmap of written chunks is clear, is zeros, completed here without a read.
/// The bit is set under the lock when the first write back of the chunk ends,
/// so it is tested under the same hold.
///
/// Any other run not in the cache goes to the lower device by the caller. It is put
/// into the tree of reads first, under the same hold of the lock, and stays
/// there until cache_read_done, so a write back of the chunk waits for it. If
/// the chunk is under write back already, the read waits for it to end
/// instead: the sectors are not written back, but a stream of such reads would
/// otherwise keep the write back waiting for ever. A write of those sectors
/// that comes meanwhile is concurrent with the read, so the read may return the
/// data from before it.
///
/// Expected execution context - dcorr_map, may sleep.
/// @param cache The cache of the device
/// @param bio   Read with bi_sector relative to the start of the target
/// @param lower Free node in the per-bio data of the bio, used if it is read from below
/// @return true if the bio was completed, false if it has to be read from below
bool cache_read(struct cache *cache, struct bio *bio, struct cache_lower_read *lower)
{
    struct written_map *written = cache->dc->written;
    sector_t chunk = bio->bi_iter.bi_sector / DCORR_CHUNK_SECTORS;
    unsigned int first = bio->bi_iter.bi_sector % DCORR_CHUNK_SECTORS;
    unsigned int sectors = bio_sectors(bio);
    struct cache_entry *entry;
    unsigned int run = sectors;
    bool cached = false;
    bool waited = false;
    bool unwritten = false;

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
            atomic64_inc(&cache->stats->read_waits);
        waited = true;
        cache_wait(cache);
    }

    if (cached)
        copy_from_entry(entry, bio, first, run);
    else if (!written_test(written, bio->bi_iter.bi_sector))
        unwritten = true;
    else
        cache_insert_read(cache, lower, chunk);
    spin_unlock(&cache->lock);

    if (run < sectors)
        dm_accept_partial_bio(bio, run);
    if (unwritten)
    {
        atomic64_inc(&cache->stats->unwritten_reads);
        zero_fill_bio(bio);
    }
    if (cached || unwritten)
        bio_endio(bio);

    return cached || unwritten;
}

/// @brief Takes a read of the lower device out of the tree of reads in flight
/// @details
/// Wakes the worker only if the chunk is under write back, as only then it may
/// wait for the read.
///
/// Expected execution context - process, complete_work of the read.
/// @param cache The cache of the device
/// @param lower The node cache_read put into the tree
void cache_read_done(struct cache *cache, struct cache_lower_read *lower)
{
    struct cache_entry *entry;
    bool wake;

    spin_lock(&cache->lock);
    rb_erase(&lower->node, &cache->reads);
    entry = cache_find(cache, lower->chunk);
    wake = entry && entry->state == CACHE_WRITING;
    if (wake)
        cache_event(cache);
    spin_unlock(&cache->lock);

    if (wake)
        dcorr_events_wake(&cache->events);
}

/// @brief Hands a chunk to the worker to settle, after a read that matched only its leading copy
/// @details
/// After a crash between the flush that made a write back durable and its
/// trailing copy, or with the trailing write lost, the leading copy of a chunk
/// has the CRC of its data and the trailing copy that of an older version.
/// Nothing would settle it before its next write back, and the older data,
/// put back by a drive that lost the write from its cache, would pass. So a
/// read that matched only the leading copy in a sector hands the chunk to the
/// worker, see cache_settle_reads. The table holds CACHE_SETTLES chunks; one
/// already there is not added again, and when it is full the chunk is left
/// out, for a later read to hand it again.
///
/// Expected execution context - process, complete_work of the read.
void cache_queue_settle(struct cache *cache, sector_t chunk)
{
    bool queued = false;

    spin_lock(&cache->lock);
    for (unsigned int i = 0; i < cache->nr_settles; i++)
    {
        if (cache->settles[i] == chunk)
            queued = true;
    }
    if (!queued && cache->nr_settles < CACHE_SETTLES)
    {
        cache->settles[cache->nr_settles++] = chunk;
        queued = true;
    }
    spin_unlock(&cache->lock);

    if (queued)
        cache_kick(cache);
}

/// @brief Hands an empty flush to the worker, which completes it
/// @details
/// Expected execution context - dcorr_map.
void cache_flush(struct cache *cache, struct bio *bio)
{
    spin_lock(&cache->lock);
    bio_list_add(&cache->flushes, bio);
    spin_unlock(&cache->lock);
    cache_kick(cache);
}

/// @brief Hands a discard, or a write zeroes with its ends zeroed, to the worker, which completes it
/// @details
/// The bio covers at least one whole chunk, and no block of the bitmap
/// invalid in both copies; dcorr_map has checked that. The bits are cleared by the
/// worker, see cache_discard_bios, as a sync writes the blocks of the bitmap
/// from RAM, and only the worker runs syncs while the device is live.
///
/// Expected execution context - dcorr_map.
void cache_discard(struct cache *cache, struct bio *bio)
{
    spin_lock(&cache->lock);
    bio_list_add(&cache->discards, bio);
    spin_unlock(&cache->lock);
    cache_kick(cache);
}

/// @brief Finds the entry of the first chunk from this one on in the tree; the lock must be held
static struct cache_entry *cache_find_from(struct cache *cache, sector_t chunk)
{
    struct rb_node *node = cache->tree.rb_node;
    struct cache_entry *found = NULL;

    while (node)
    {
        struct cache_entry *entry = rb_entry(node, struct cache_entry, node);

        if (chunk > entry->chunk)
        {
            node = node->rb_right;
            continue;
        }
        found = entry;
        node = node->rb_left;
    }

    return found;
}

/// @brief Drops the entries of the chunks of a range, their data not yet written back; the lock must be held
/// @details No entry may be under write back. A failed entry is dropped too: its data is discarded.
static void cache_drop_range(struct cache *cache, sector_t first, sector_t end)
{
    struct cache_entry *entry = cache_find_from(cache, first);

    while (entry && entry->chunk < end)
    {
        struct rb_node *next = rb_next(&entry->node);

        WARN_ON_ONCE(entry->state == CACHE_WRITING);
        if (entry->state == CACHE_FAILED)
            cache->nr_failed--;
        else
            cache->nr_dirty--;
        list_del(&entry->list);
        rb_erase(&entry->node, &cache->tree);
        entry->state = CACHE_FREE;
        entry->mask = 0;
        list_add(&entry->list, &cache->free);
        cache->nr_free++;

        entry = next ? rb_entry(next, struct cache_entry, node) : NULL;
    }
}

/// @brief Carries out the discards handed to the worker, and completes them
/// @details
/// The whole chunks of a write zeroes come here too; one with REQ_FUA is handed
/// on to the flushes, which the worker takes right after.
/// Waits for the write backs in flight first, so that no entry is under write
/// back and no bit is set meanwhile. For the whole chunks of each discard, the
/// entries are dropped and the bits cleared, a block of the bitmap at a time
/// under the lock, so that a read sees a chunk either as it was or as zeros. A
/// cleared bit reaches the device with the next sync, so a discard is durable
/// once a flush from above that follows it completes; until then the chunk may
/// hold its old data after a crash. The first write back of such a chunk syncs
/// first, see cache_prepare_metadata.
///
/// Expected execution context - the worker, may sleep.
static void cache_discard_bios(struct cache *cache, struct bio_list *discards)
{
    struct written_map *written = cache->dc->written;
    struct bio *bio;

    cache_wait_until(cache, !READ_ONCE(cache->nr_writing));

    while ((bio = bio_list_pop(discards)))
    {
        sector_t first = DIV_ROUND_UP(bio->bi_iter.bi_sector, DCORR_CHUNK_SECTORS);
        sector_t end = bio_end_sector(bio) / DCORR_CHUNK_SECTORS;
        sector_t chunk = first;
        bool wake;

        spin_lock(&cache->lock);
        cache_drop_range(cache, first, end);
        wake = !list_empty(&cache->free);
        cache_event(cache);
        spin_unlock(&cache->lock);
        if (wake)
            dcorr_events_wake(&cache->events);

        while (chunk < end)
        {
            u64 done;

            spin_lock(&cache->lock);
            if (written_clear(written, chunk * DCORR_CHUNK_SECTORS, end - chunk, &done))
                cache->clears++;
            spin_unlock(&cache->lock);
            chunk += done;
            cond_resched();
        }

        if (bio_op(bio) == REQ_OP_DISCARD)
            atomic64_add(end - first, &cache->stats->discarded_chunks);
        if (bio->bi_opf & REQ_FUA)
        {
            spin_lock(&cache->lock);
            bio_list_add(&cache->flushes, bio);
            spin_unlock(&cache->lock);
            continue;
        }
        bio_endio(bio);
    }
}

/// @brief Ends the write back of an entry once its last job is done; the lock must be held
/// @details
/// A written entry is freed, and the bit of its chunk set in the bitmap of
/// written chunks, before a read can miss the entry and go below. A failed one
/// keeps its data and waits for a retry, its bit as it was.
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

    written_set(cache->dc->written, entry->chunk * DCORR_CHUNK_SECTORS);
    rb_erase(&entry->node, &cache->tree);
    entry->state = CACHE_FREE;
    entry->mask = 0;
    list_add(&entry->list, &cache->free);
    cache->nr_free++;
}

/// @brief Completion of a write back job
/// @details
/// complete_work of the part calls it through bio_endio, as the last thing it
/// does. It records the outcome for the metadata, which pins the area until
/// the next flush; the sectors of a job that succeeded go into the trailing
/// copy then. Lets the metadata area go first, so that it can be dropped once
/// the write backs are over and it is not pinned. Starts the next job of the metadata sector, if one is
/// queued, which takes its place in the tree of jobs in flight. The last job of
/// an entry frees it, or marks it failed.
///
/// Expected execution context - process, a worker of transform_wq.
static void cache_job_end_io(struct bio *bio)
{
    struct cache_job *job = container_of(bio, struct cache_job, bio);
    struct cache_entry *entry = job->entry;
    struct cache *cache = job->cache;
    blk_status_t status = bio->bi_status;
    sector_t chunk = entry->chunk;
    sector_t sector = job->part.sector;
    unsigned int nr_sectors = job->part.meta.write.nr_sectors;
    bool meta_written = job->part.meta_written;
    struct cache_job *next;

    bio_uninit(bio);
    metadata_written(cache->dc->metadata, job->area, chunk * DCORR_CHUNK_SECTORS,
                     sector_mask(job->part.meta.write.first_sector, job->part.meta.write.nr_sectors), !status);
    metadata_put(cache->dc->metadata, job->area);

    spin_lock(&cache->lock);
    if (status && !entry->status)
        entry->status = status;
    list_add(&job->list, &cache->free_jobs);
    cache->nr_jobs--;

    next = list_first_entry_or_null(&job->queued, struct cache_job, list);
    if (next)
        cache_pass_sector(cache, job, next);
    else
        rb_erase(&job->node, &cache->sectors);

    if (!--entry->jobs)
        cache_finish_entry(cache, entry);

    cache_event(cache);
    spin_unlock(&cache->lock);
    dcorr_events_wake(&cache->events);

    if (next)
        queue_work(cache->dc->transform_wq, &next->part.submit_work);

    if (status)
    {
        atomic64_inc(&cache->stats->write_errors);
        dcorr_error(cache->dc->ti);
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "write back at sector %llu (%u sectors) failed at its %s, status=%d\n",
                            (unsigned long long)sector, nr_sectors, meta_written ? "data" : "metadata", status);
    }
}

/// @brief Takes a free job, waiting for one if needed
/// @details Expected execution context - the worker, may sleep.
static struct cache_job *cache_get_job(struct cache *cache)
{
    struct cache_job *job;

    spin_lock(&cache->lock);
    while (list_empty(&cache->free_jobs))
        cache_wait(cache);
    job = list_first_entry(&cache->free_jobs, struct cache_job, list);
    list_del_init(&job->list);
    cache->nr_jobs++;
    spin_unlock(&cache->lock);

    return job;
}

/// @brief Writes back one run of sectors of an entry
/// @details
/// Gets the metadata area of the region of the chunk first, which may wait
/// while it is read.
///
/// The jobs of one metadata sector go one after another: a job puts its CRCs
/// into the area in RAM and writes the sector from there, so a second job at
/// once would change the memory under the write of the first, and the device
/// below could get the CRCs of data not yet written. This holds for the jobs
/// of one entry and for those of the neighbouring chunks that share the sector.
/// The job starts at once if no job of its sector is in flight, and is queued
/// on the job in flight otherwise; the end of the job before it starts it.
static void cache_submit_job(struct cache *cache, struct cache_entry *entry,
                             unsigned int first, unsigned int sectors)
{
    struct dcorr_ctx *dc = cache->dc;
    struct cache_job *job = cache_get_job(cache);
    struct bio *bio = &job->bio;
    struct cache_job *head;
    bool start;

    job->entry = entry;
    job->cache = cache;
    job->area = metadata_get(dc->metadata, entry->chunk * DCORR_CHUNK_SECTORS);
    job->sector = entry->chunk / DCORR_CHUNKS_PER_METADATA_SECTOR;
    INIT_LIST_HEAD(&job->queued);

    bio_init(bio, dc->lower->bdev, &job->bvec, 1, REQ_OP_WRITE);
    bio->bi_iter.bi_sector = entry->chunk * DCORR_CHUNK_SECTORS + first;
    bio->bi_end_io = cache_job_end_io;
    __bio_add_page(bio, entry->page, sectors << SECTOR_SHIFT, first << SECTOR_SHIFT);

    // The worker may wait here: the completions that give places back run in transform_wq.
    down(&dc->parts_in_flight);
    trn_p_rq_init(&job->part, bio, dc, TRANSFORM_WRITE, job->area);

    spin_lock(&cache->lock);
    head = cache_find_sector(cache, job->sector);
    start = !head;
    if (start)
        cache_insert_sector(cache, job);
    else
        list_add_tail(&job->list, &head->queued);
    spin_unlock(&cache->lock);

    if (start)
        queue_work(dc->transform_wq, &job->part.submit_work);
}

/// @brief Flushes the lower device, counting a failure
/// @details A flush that succeeds records that the lower device has flushed since the table was created.
/// @return 0, or the error of the flush
static int cache_flush_lower(struct cache *cache)
{
    int r = blkdev_issue_flush(cache->dc->lower->bdev);

    if (r)
    {
        atomic64_inc(&cache->stats->flush_errors);
        dcorr_error(cache->dc->ti);
        return r;
    }
    cache->lower_flushed = true;
    return 0;
}

/// @brief Makes sure the lower device has flushed since the table was created, before a settle
/// @details
/// A settle reads a chunk and puts the CRC of what it reads into the trailing
/// copy with FUA. Data written before the table was created, by an earlier
/// table or before a crash of the host, may still be only in the cache of the
/// drive; a settle that took its CRC would leave the chunk matching neither
/// copy once the drive lost it. So the first settle of a table flushes first;
/// any sync does it as well.
/// @return 0, or the error of the flush
static int cache_flush_before_settle(struct cache *cache)
{
    return cache->lower_flushed ? 0 : cache_flush_lower(cache);
}

static int cache_sync(struct cache *cache, struct bio_list *flushes, bool failed);

/// @brief Makes the metadata of a chunk ready for a write back that writes the leading copy first
/// @details
/// A chunk written back since the last flush of the lower device may hold its
/// old or its new data, and the trailing copy has the CRC of the old one; one
/// more write back would leave three versions for two copies. So the worker
/// first waits for the jobs in flight and runs cache_sync, which makes the data
/// durable and puts its CRC into the trailing copy; this is counted as a
/// barrier. Then metadata_settle reads the chunk if its copies still differ in
/// the sectors to be written. A chunk never written back is not read: its old
/// contents are zeros whatever its copies hold.
///
/// That holds only while its bit is clear on the device too. A discard clears
/// a bit in RAM, and the device keeps it set until the next sync; a crash after
/// a write back that skipped the settle could then leave sectors matching
/// neither copy. So a chunk with its bit clear, while a clear is not yet
/// durable, waits for a sync too, counted as a barrier.
///
/// If the sync of a barrier fails, nothing has become durable and the chunk
/// may not be written back: the error is returned, and the caller gives the
/// write back up. So it does if the flush before the first settle of the
/// table fails, see cache_flush_before_settle.
/// @param unwritten Whether the bit of the chunk in the bitmap of written chunks is clear
/// @return 0, or the error of the sync of the barrier or of the flush before a settle
static int cache_prepare_metadata(struct cache *cache, struct cache_entry *entry, bool unwritten)
{
    struct metadata_cache *metadata = cache->dc->metadata;
    sector_t sector = entry->chunk * DCORR_CHUNK_SECTORS;
    struct metadata_area *area = metadata_get(metadata, sector);
    int r = 0;

    if (metadata_written_since_flush(metadata, area, sector) ||
        (unwritten && cache->clears != cache->synced_clears))
    {
        cache_wait_until(cache, !READ_ONCE(cache->nr_jobs));
        atomic64_inc(&cache->stats->barriers);
        r = cache_sync(cache, NULL, false);
    }

    if (!r && !unwritten)
    {
        r = cache_flush_before_settle(cache);
        if (!r)
            metadata_settle(metadata, area, sector, entry->mask);
    }
    metadata_put(metadata, area);

    return r;
}

/// @brief Gives up the write back of an entry in CACHE_WRITING before any of its jobs is sent
/// @details The entry fails and keeps its data, as after a failed write back; a flush tries it again.
static void cache_abandon_entry(struct cache *cache, struct cache_entry *entry)
{
    spin_lock(&cache->lock);
    entry->jobs = 0;
    entry->status = BLK_STS_IOERR;
    cache_finish_entry(cache, entry);
    cache_event(cache);
    spin_unlock(&cache->lock);
    dcorr_events_wake(&cache->events);
}

/// @brief Writes back an entry in CACHE_WRITING, one job per run of its sectors
/// @details
/// Writes to the entry wait until it leaves CACHE_WRITING, so its mask and its
/// page do not change while the jobs are in flight. So do new reads of its
/// clean sectors, so the reads of the chunk already in flight are waited for
/// before the first job: a read that met a job could see the data of one
/// version of a sector and the CRC of another. Then the metadata of the chunk
/// is made ready, see cache_prepare_metadata.
///
/// The first write back of a chunk, whose bit in the bitmap of written chunks is
/// clear, writes it whole, the sectors not written from above as zeros: once
/// the bit is set they are read from the lower device, where they hold
/// whatever was there before the format.
/// @return 0, or the error of the sync of a barrier, when the write back is given up
static int cache_write_back_entry(struct cache *cache, struct cache_entry *entry)
{
    bool unwritten;
    unsigned int first;
    unsigned int run;
    unsigned int jobs = 0;
    u8 mask;
    int r;

    spin_lock(&cache->lock);
    unwritten = !written_test(cache->dc->written, entry->chunk * DCORR_CHUNK_SECTORS);
    if (unwritten && entry->mask != 0xff)
    {
        char *base = kmap_local_page(entry->page);

        for (first = 0; first < DCORR_CHUNK_SECTORS; first++)
        {
            if (!(entry->mask & BIT(first)))
                memset(base + (first << SECTOR_SHIFT), 0, SECTOR_SIZE);
        }
        kunmap_local(base);
        entry->mask = 0xff;
    }
    mask = entry->mask;
    spin_unlock(&cache->lock);

    for (first = 0; first < DCORR_CHUNK_SECTORS; first += run)
    {
        run = run_length(mask, first, DCORR_CHUNK_SECTORS - first, mask & BIT(first));
        if (mask & BIT(first))
            jobs++;
    }

    spin_lock(&cache->lock);
    entry->jobs = jobs;
    entry->status = BLK_STS_OK;
    while (cache_reads_on(cache, entry->chunk))
        cache_wait(cache);
    spin_unlock(&cache->lock);

    r = cache_prepare_metadata(cache, entry, unwritten);
    if (r)
    {
        cache_abandon_entry(cache, entry);
        return r;
    }

    for (first = 0; first < DCORR_CHUNK_SECTORS; first += run)
    {
        run = run_length(mask, first, DCORR_CHUNK_SECTORS - first, mask & BIT(first));
        if (mask & BIT(first))
            cache_submit_job(cache, entry, first, run);
    }

    return 0;
}

/// @brief Whether the worker has to write back more to keep entries free
static bool cache_under_pressure(struct cache *cache)
{
    return cache->nr_free + cache->nr_writing < CACHE_STOP_FREE;
}

/// @brief Flushes the lower device, writes the bitmap, completes the flushes from above, then writes the
/// trailing copies
/// @details
/// No write back job may be in flight, and none may start until it returns.
/// Once the lower device has flushed, the data written back is durable, and
/// the first copy of each block of the bitmap with new bits is written, then
/// the lower device is flushed again, see written_write_first: a bit on the
/// device means durable data, and the bits cleared before the sync are clear on
/// the device, as synced_clears records. The flushes from above complete then: with
/// BLK_STS_IOERR if failed is set, as a flush promises that nothing is left
/// only in RAM, or if a flush or a block of the bitmap failed. Then the
/// trailing copies of the metadata of the chunks written back before get the
/// CRCs of that durable data, the other copies of the blocks of the bitmap are
/// written, and the lower device is flushed once more, so that both copies are
/// durable before a chunk is written back again. If a flush before fails, no
/// trailing copy is written, as the data may not be on the device: the areas
/// stay pinned and their chunks marked as written since the last flush, so
/// that the next sync writes their trailing copies once the lower device
/// flushes again, and until then none of those chunks is written back.
///
/// Expected execution context - the worker, or postsuspend once the worker is
/// cancelled; may sleep.
/// @param cache   The cache of the device
/// @param flushes Flush and FUA bios from above to complete, or NULL
/// @param failed  Whether chunks are left that failed to write back
/// @return 0, or the error of a flush of the lower device
static int cache_sync(struct cache *cache, struct bio_list *flushes, bool failed)
{
    struct metadata_cache *metadata = cache->dc->metadata;
    struct written_map *written = cache->dc->written;
    u64 clears = cache->clears;
    blk_status_t status;
    struct bio *bio;
    int r;

    r = cache_flush_lower(cache);
    if (!r)
    {
        r = written_write_first(written);
        if (r > 0)
            r = cache_flush_lower(cache);
        else if (r < 0)
            DCORR_DEV_ERR_LIMIT(cache->dc->ti, "the bitmap of written chunks failed to write, err=%d\n",
                                r);
    }
    if (!r)
        cache->synced_clears = clears;
    status = failed ? BLK_STS_IOERR : errno_to_blk_status(r);
    while (flushes && (bio = bio_list_pop(flushes)))
    {
        bio->bi_status = status;
        bio_endio(bio);
    }

    if (r)
    {
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "lower flush or bitmap failed, err=%d, trailing metadata kept for the next sync\n",
                            r);
        written_abort(written);
        return r;
    }

    metadata_write_trails(metadata);
    written_write_second(written);

    r = cache_flush_lower(cache);
    if (r)
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "lower flush after the trailing metadata failed, err=%d\n",
                            r);

    return r;
}

/// @brief Waits for all write backs, then completes the flushes and FUA writes
/// @details
/// A flush succeeds only if no entry is left that failed to write back, and the
/// lower device flushed: it promises that the data is on the device.
static void cache_complete_flushes(struct cache *cache, struct bio_list *flushes)
{
    unsigned long failed;

    cache_wait_until(cache, !READ_ONCE(cache->nr_writing));

    spin_lock(&cache->lock);
    failed = cache->nr_failed;
    spin_unlock(&cache->lock);

    cache_sync(cache, flushes, failed);
}

/// @brief Takes the pins off the metadata areas when too many are busy, before the next write back
/// @details
/// A write back holds the area of its chunk, and pins it when it completes,
/// until the trailing copy is written. So once half the areas are busy, the
/// worker waits for the jobs in flight and runs cache_sync, which unpins them
/// all; otherwise the areas could run out with the worker waiting for one. If
/// that sync fails, the pins stay, and the worker stops writing back.
/// @return 0, or the error of the sync
static int cache_crowded_flush(struct cache *cache)
{
    if (!metadata_crowded(cache->dc->metadata))
        return 0;

    cache_wait_until(cache, !READ_ONCE(cache->nr_jobs));
    atomic64_inc(&cache->stats->crowded_flushes);
    return cache_sync(cache, NULL, false);
}

/// @brief Settles the chunks that reads handed to the worker, see cache_queue_settle
/// @details
/// A chunk under write back, or written back since the last flush, is left:
/// its trailing copy is written by the next sync, or it is settled before its
/// next write back. Only the worker starts write backs, so neither changes
/// while it settles; a read of the chunk meanwhile takes either copy. If the
/// flush before the first settle of the table fails, the chunks are left.
///
/// Expected execution context - the worker, may sleep.
static void cache_settle_reads(struct cache *cache)
{
    struct metadata_cache *metadata = cache->dc->metadata;
    sector_t chunks[CACHE_SETTLES];
    unsigned int nr;

    spin_lock(&cache->lock);
    nr = cache->nr_settles;
    memcpy(chunks, cache->settles, nr * sizeof(chunks[0]));
    cache->nr_settles = 0;
    spin_unlock(&cache->lock);

    for (unsigned int i = 0; i < nr; i++)
    {
        sector_t sector = chunks[i] * DCORR_CHUNK_SECTORS;
        struct metadata_area *area;
        struct cache_entry *entry;
        bool busy;

        spin_lock(&cache->lock);
        entry = cache_find(cache, chunks[i]);
        busy = entry && entry->state == CACHE_WRITING;
        spin_unlock(&cache->lock);
        if (busy)
            continue;

        if (cache_flush_before_settle(cache))
            return;

        area = metadata_get(metadata, sector);
        if (!metadata_written_since_flush(metadata, area, sector))
            metadata_settle(metadata, area, sector, 0xff);
        metadata_put(metadata, area);
    }
}

/// @brief The worker
/// @details
/// Carries out the discards first, see cache_discard_bios, and settles the
/// chunks that reads handed to it, see cache_settle_reads. Then writes back
/// the dirty entries, the oldest first: all of them for a flush,
/// a FUA write or a suspend, and otherwise those older than CACHE_AGE_MS and
/// as many as keep CACHE_STOP_FREE entries free or on their way to it. A flush
/// tries the failed entries again, and writes the trailing copies of the
/// metadata after the lower device has flushed, see cache_sync; so does the
/// worker when too many metadata areas are pinned. Then it schedules itself
/// for the next entry to come of age.
///
/// Once the sync of a barrier or of crowded areas fails, the lower device has
/// failed to flush, and the worker stops at its level: the entries it picked
/// and has not written back yet fail without I/O and keep their data, as
/// after a failed write back, so that the flushes fail and a flush tries them
/// again. The next pass of the worker tries the lower device again.
///
/// It runs on an ordered workqueue of its own, never in transform_wq, so it may
/// wait for jobs, for places among the parts in flight and for reads in flight:
/// their completions run there.
static void cache_worker(struct work_struct *work)
{
    struct cache *cache = container_of(to_delayed_work(work), struct cache, worker);
    struct cache_entry *entry;
    struct cache_entry *next;
    struct bio_list flushes;
    struct bio_list discards;
    LIST_HEAD(picked);
    unsigned int abandoned = 0;
    bool all;
    int r = 0;

    spin_lock(&cache->lock);
    discards = cache->discards;
    bio_list_init(&cache->discards);
    spin_unlock(&cache->lock);

    if (!bio_list_empty(&discards))
        cache_discard_bios(cache, &discards);

    cache_settle_reads(cache);

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
        if (!r)
            r = cache_crowded_flush(cache);
        if (!r)
            r = cache_write_back_entry(cache, entry);
        else
            cache_abandon_entry(cache, entry);
        if (r)
            abandoned++;
    }
    if (abandoned)
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "write back stopped: the lower device failed to flush, err=%d, %u chunks kept in RAM\n",
                            r, abandoned);

    if (!bio_list_empty(&flushes))
        cache_complete_flushes(cache, &flushes);

    spin_lock(&cache->lock);
    if (!cache->suspended && !list_empty(&cache->dirty))
    {
        unsigned long due;

        entry = list_first_entry(&cache->dirty, struct cache_entry, list);
        due = entry->dirtied + msecs_to_jiffies(CACHE_AGE_MS);
        queue_delayed_work(cache->wq, &cache->worker,
                           time_after(due, jiffies) ? due - jiffies : 0);
    }
    spin_unlock(&cache->lock);
}

/// @brief Writes back everything before the device is suspended
/// @details
/// Called from postsuspend, when device mapper has no bio of the device in
/// flight. Tries the failed entries once more; those that fail again keep their
/// data in RAM, which is lost if the target is destroyed, as a suspend cannot fail.
/// Then flushes the lower device and writes the trailing copies of the
/// metadata, see cache_sync, so that no metadata area is pinned. If that sync
/// fails, the trailing copies of the chunks written back since the last flush
/// are given up and the areas unpinned anyway, as the metadata in RAM is
/// dropped on suspend: those chunks keep their two copies different.
///
/// Expected execution context - process, may sleep.
void cache_suspend(struct cache *cache)
{
    unsigned long failed;

    spin_lock(&cache->lock);
    cache->write_all = true;
    cache->suspended = true;
    cache_retry_failed(cache);
    spin_unlock(&cache->lock);

    cache_kick(cache);
    cache_wait_until(cache, !READ_ONCE(cache->nr_dirty) && !READ_ONCE(cache->nr_writing));
    cancel_delayed_work_sync(&cache->worker);

    if (cache_sync(cache, NULL, false))
    {
        metadata_unpin_all(cache->dc->metadata);
        DCORR_DEV_ERR(cache->dc->ti, "the lower device failed to flush on suspend, the trailing metadata of the chunks written back since the last flush is not written\n");
    }

    spin_lock(&cache->lock);
    cache->write_all = false;
    failed = cache->nr_failed;
    spin_unlock(&cache->lock);

    if (failed)
        DCORR_DEV_ERR(cache->dc->ti, "%lu chunks failed to write back on suspend, their data is only in RAM\n",
                      failed);
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
/// Expected execution context - dcorr_ctr, may sleep.
/// @param dc The context of the target, with the lower device already open
/// @return The cache, or ERR_PTR(-ENOMEM)
struct cache *cache_create(struct dcorr_ctx *dc)
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
    INIT_LIST_HEAD(&cache->free_jobs);
    bio_list_init(&cache->flushes);
    bio_list_init(&cache->discards);
    dcorr_events_init(&cache->events);
    INIT_DELAYED_WORK(&cache->worker, cache_worker);
    cache->dc = dc;
    cache->stats = &dc->stats;

    cache->entries = kvcalloc(CACHE_ENTRIES, sizeof(*cache->entries), GFP_KERNEL);
    cache->job_table = kvcalloc(CACHE_JOBS, sizeof(*cache->job_table), GFP_KERNEL);
    cache->wq = alloc_ordered_workqueue("dcorr_write_back", WQ_MEM_RECLAIM);
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
        list_add_tail(&cache->job_table[i].list, &cache->free_jobs);

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
/// Expected execution context - dcorr_dtr, may sleep.
void cache_destroy(struct cache *cache)
{
    struct cache_entry *entry;

    cancel_delayed_work_sync(&cache->worker);

    WARN_ON(cache->nr_writing || !bio_list_empty(&cache->flushes) || !bio_list_empty(&cache->discards) ||
            !RB_EMPTY_ROOT(&cache->reads) || !RB_EMPTY_ROOT(&cache->sectors));
    list_for_each_entry(entry, &cache->dirty, list)
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "the chunk at sector %llu is lost: it was never written back\n",
                            (unsigned long long)(entry->chunk * DCORR_CHUNK_SECTORS));
    list_for_each_entry(entry, &cache->failed, list)
        DCORR_DEV_ERR_LIMIT(cache->dc->ti, "the chunk at sector %llu is lost: its write back failed\n",
                            (unsigned long long)(entry->chunk * DCORR_CHUNK_SECTORS));
    if (cache->nr_dirty || cache->nr_failed)
        DCORR_DEV_ERR(cache->dc->ti, "%lu chunks are lost\n",
                      cache->nr_dirty + cache->nr_failed);

    cache_free(cache);
}

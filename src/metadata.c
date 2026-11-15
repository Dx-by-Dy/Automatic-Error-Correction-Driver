#include <linux/blkdev.h>
#include <linux/crc64.h>
#include <linux/slab.h>

#include "metadata.h"
#include "macros.h"

/// @brief First sector of a copy of the metadata area of a region on the device below
static sector_t metadata_copy_start(const struct metadata_area *area, enum metadata_copy copy)
{
    if (copy == METADATA_LEAD)
        return lead_area_start(area->cache->layout, area->region);
    return trail_area_start(area->cache->layout, area->region);
}

/// @brief Finds the area of a region in the tree; the lock must be held
static struct metadata_area *metadata_find(struct metadata_cache *cache, sector_t region)
{
    struct rb_node *node = cache->tree.rb_node;

    while (node)
    {
        struct metadata_area *area = rb_entry(node, struct metadata_area, node);

        if (region < area->region)
            node = node->rb_left;
        else if (region > area->region)
            node = node->rb_right;
        else
            return area;
    }

    return NULL;
}

/// @brief Puts an area into the tree; the lock must be held and its region must not be there
static void metadata_insert(struct metadata_cache *cache, struct metadata_area *area)
{
    struct rb_node **link = &cache->tree.rb_node;
    struct rb_node *parent = NULL;

    while (*link)
    {
        struct metadata_area *other = rb_entry(*link, struct metadata_area, node);

        parent = *link;
        link = area->region < other->region ? &(*link)->rb_left : &(*link)->rb_right;
    }

    rb_link_node(&area->node, parent, link);
    rb_insert_color(&area->node, &cache->tree);
}

/// @brief Records that waiters may go on; the lock must be held, wake them after dropping it
static void metadata_event(struct metadata_cache *cache)
{
    cache->events++;
}

/// @brief Waits for the events of the cache to change; called with the lock held, returns with it held
static void metadata_wait(struct metadata_cache *cache)
{
    u64 seen = cache->events;

    spin_unlock(&cache->lock);
    wait_event(cache->wait, READ_ONCE(cache->events) != seen);
    spin_lock(&cache->lock);
}

/// @brief Adds the sectors [first, end) of one copy of an area, or of the scratch area, to a bio
static void metadata_add_sectors(struct bio *bio, struct page *const *pages, unsigned int first, unsigned int end)
{
    unsigned int byte = first * SECTOR_SIZE;
    unsigned int stop = end * SECTOR_SIZE;

    while (byte < stop)
    {
        unsigned int len = min_t(unsigned int, PAGE_SIZE - byte % PAGE_SIZE, stop - byte);

        __bio_add_page(bio, pages[byte / PAGE_SIZE], len, byte % PAGE_SIZE);
        byte += len;
    }
}

/// @brief Reads or writes the sectors [first, end) of a copy of an area from or to the given pages
/// @return 0, or the error of the request
static int metadata_io(struct metadata_area *area, enum metadata_copy copy, struct page *const *pages,
                       unsigned int first, unsigned int end, blk_opf_t opf)
{
    struct bio_vec bvecs[METADATA_AREA_PAGES];
    struct bio bio;
    int r;

    bio_init(&bio, area->cache->bdev, bvecs, METADATA_AREA_PAGES, opf);
    bio.bi_iter.bi_sector = metadata_copy_start(area, copy) + first;
    metadata_add_sectors(&bio, pages, first, end);
    r = submit_bio_wait(&bio);
    bio_uninit(&bio);

    return r;
}

/// @brief Reads one copy of an area from the device below
/// @details
/// Reads the copy whole in one request. If that fails, reads its sectors one
/// at a time, and marks those that failed.
/// @return Number of sectors that failed
static unsigned int metadata_load_copy(struct metadata_area *area, enum metadata_copy copy)
{
    unsigned int failed = 0;
    int r;

    r = metadata_io(area, copy, area->pages[copy], 0, REGION_METADATA_SECTORS, REQ_OP_READ);
    if (!r)
        return 0;

    for (unsigned int i = 0; i < REGION_METADATA_SECTORS; i++)
    {
        if (metadata_io(area, copy, area->pages[copy], i, i + 1, REQ_OP_READ))
        {
            __set_bit(i, area->bad[copy]);
            failed++;
        }
    }

    DM_ERR_LIMIT("%s copy of the metadata of region %llu failed to read, err=%d, %u of its sectors fail\n",
                 copy == METADATA_LEAD ? "leading" : "trailing", (unsigned long long)area->region, r, failed);

    return failed;
}

/// @brief Copies a metadata sector from one copy of an area to the other in RAM
static void metadata_fill_sector(struct metadata_area *area, enum metadata_copy from, unsigned int index)
{
    unsigned int byte = index * SECTOR_SIZE;
    enum metadata_copy to = from == METADATA_LEAD ? METADATA_TRAIL : METADATA_LEAD;

    memcpy(page_address(area->pages[to][byte / PAGE_SIZE]) + byte % PAGE_SIZE,
           page_address(area->pages[from][byte / PAGE_SIZE]) + byte % PAGE_SIZE, SECTOR_SIZE);
}

/// @brief Reads both copies of an area from the device below
/// @details
/// A sector that failed to read in one copy is filled from the other, so that
/// the next write of it from RAM puts the right entries of the other chunks
/// there. A sector that failed in both fails its chunks, and the area is read
/// again by the next who gets it while nobody holds it, so that a sector that
/// reads again is seen.
///
/// Runs on the workqueue of the cache, never in transform_wq, as it waits for
/// its reads.
static void metadata_load(struct work_struct *work)
{
    struct metadata_area *area = container_of(work, struct metadata_area, load_work);
    struct metadata_cache *cache = area->cache;
    unsigned int failed[METADATA_COPIES] = {};
    bool both = false;

    for (unsigned int copy = 0; copy < METADATA_COPIES; copy++)
    {
        bitmap_zero(area->bad[copy], REGION_METADATA_SECTORS);
        failed[copy] = metadata_load_copy(area, copy);
    }

    if (failed[METADATA_LEAD] || failed[METADATA_TRAIL])
    {
        for (unsigned int i = 0; i < REGION_METADATA_SECTORS; i++)
        {
            bool lead = test_bit(i, area->bad[METADATA_LEAD]);
            bool trail = test_bit(i, area->bad[METADATA_TRAIL]);

            if (lead && trail)
                both = true;
            else if (lead)
                metadata_fill_sector(area, METADATA_TRAIL, i);
            else if (trail)
                metadata_fill_sector(area, METADATA_LEAD, i);
        }
    }

    atomic64_inc(&cache->loads);

    spin_lock(&cache->lock);
    area->state = METADATA_VALID;
    area->failed = both;
    metadata_event(cache);
    spin_unlock(&cache->lock);
    wake_up_all(&cache->wait);
}

/// @brief Takes an area for a new region: a free one, or the least recently used; the lock must be held
/// @return The area, out of every list and tree, or NULL if all are in use or loading
static struct metadata_area *metadata_take(struct metadata_cache *cache)
{
    struct metadata_area *area = list_first_entry_or_null(&cache->free, struct metadata_area, list);

    if (!area)
    {
        area = list_first_entry_or_null(&cache->lru, struct metadata_area, list);
        if (!area)
            return NULL;
        rb_erase(&area->node, &cache->tree);
        RB_CLEAR_NODE(&area->node);
    }

    list_del_init(&area->list);
    return area;
}

/// @brief Starts to read an area that nobody holds and waits for it; called with the lock held, returns with it
static void metadata_load_held(struct metadata_cache *cache, struct metadata_area *area)
{
    area->state = METADATA_LOADING;
    area->users = 1;
    area->failed = false;
    cache->nr_busy++;

    spin_unlock(&cache->lock);
    queue_work(cache->wq, &area->load_work);
    spin_lock(&cache->lock);

    while (area->state == METADATA_LOADING)
        metadata_wait(cache);
}

/// @brief Gets the area of the region of a logical sector, reading it first if it is not in RAM
/// @details
/// Waits while the area is loading, and while every area is in use or loading
/// and none can take the region. The area is held until metadata_put, so it
/// stays in RAM. Its sectors that failed to read are marked in it, see
/// metadata_sector_bad. An area with sectors that failed in both copies is read
/// again if nobody holds it.
///
/// The waits end without the caller: a load runs on the workqueue of the cache
/// and does not wait for anything else, and areas are held only by loads, by
/// write backs in flight and by pins, which the worker of the data cache
/// takes off before the areas run out, see metadata_crowded. So dm_map may wait
/// here: the read it waits for is not on its current->bio_list.
///
/// Expected execution context - process, dm_map or the worker of the data
/// cache, may sleep.
/// @param cache  The metadata cache of the device
/// @param sector Logical sector
/// @return The area, VALID and held
struct metadata_area *metadata_get(struct metadata_cache *cache, sector_t sector)
{
    sector_t region = sector / REGION_DATA_SECTORS;
    struct metadata_area *area;

    spin_lock(&cache->lock);
    for (;;)
    {
        area = metadata_find(cache, region);
        if (area && area->state == METADATA_VALID)
        {
            if (area->users)
            {
                area->users++;
                break;
            }

            list_del_init(&area->list);
            if (area->failed)
            {
                metadata_load_held(cache, area);
                break;
            }

            area->users = 1;
            cache->nr_busy++;
            break;
        }

        if (area)
        {
            metadata_wait(cache);
            continue;
        }

        area = metadata_take(cache);
        if (area)
        {
            area->region = region;
            metadata_insert(cache, area);
            metadata_load_held(cache, area);
            break;
        }

        atomic64_inc(&cache->waits);
        metadata_wait(cache);
    }
    spin_unlock(&cache->lock);

    return area;
}

/// @brief Drops one hold of an area; the lock must be held
/// @return Whether nobody holds it any more, so the waiters have to be woken after dropping the lock
static bool metadata_put_locked(struct metadata_cache *cache, struct metadata_area *area)
{
    if (--area->users)
        return false;

    cache->nr_busy--;
    list_add_tail(&area->list, &cache->lru);
    metadata_event(cache);

    return true;
}

/// @brief Lets an area go
/// @details
/// The last holder puts it at the end of the LRU.
///
/// Expected execution context - process.
void metadata_put(struct metadata_cache *cache, struct metadata_area *area)
{
    bool wake;

    spin_lock(&cache->lock);
    wake = metadata_put_locked(cache, area);
    spin_unlock(&cache->lock);

    if (wake)
        wake_up_all(&cache->wait);
}

/// @brief Copies both entries of the chunk of a logical sector, for a read
/// @details
/// The read is in the tree of reads of the data cache, so no write back of the
/// chunk changes the leading entry until it completes, and the copies are what
/// the device below holds for it. A copy whose sector failed is replaced with
/// the other one, and a warning says the chunk has one copy.
///
/// Expected execution context - dm_map, may sleep, see metadata_get.
/// @param cache  The metadata cache of the device
/// @param sector Logical sector
/// @param md     Where to copy the entries, by enum metadata_copy
/// @return BLK_STS_OK, or BLK_STS_IOERR if the metadata sector of the chunk failed to read in both copies
blk_status_t metadata_copy_entries(struct metadata_cache *cache, sector_t sector,
                                   struct chunk_metadata md[METADATA_COPIES])
{
    struct metadata_area *area = metadata_get(cache, sector);
    unsigned int index = metadata_area_sector(sector);
    blk_status_t status = BLK_STS_OK;
    bool single;

    spin_lock(&cache->lock);
    single = metadata_sector_single(area, sector);
    if (metadata_sector_bad(area, sector))
        status = BLK_STS_IOERR;
    for (unsigned int copy = 0; copy < METADATA_COPIES && !status; copy++)
    {
        enum metadata_copy from = test_bit(index, area->bad[copy]) ? !copy : copy;

        md[copy] = *metadata_entry(area, from, sector);
    }
    spin_unlock(&cache->lock);

    metadata_put(cache, area);

    if (single)
        DM_WARN_LIMIT("chunk %llu is read with one copy of its metadata\n",
                      (unsigned long long)(sector / DATA_SIZE_SECTORS));

    return status;
}

/// @brief Records the end of a write back of sectors of a chunk
/// @details
/// The chunk is not written back again before the lower device flushes, and
/// the area is pinned until then, so that it is not dropped before its
/// trailing copy is written. If the write back succeeded, its sectors go into
/// the trailing copy then, and the leading sector, now what the area holds,
/// reads again if it had failed. If it failed, what the device holds for those
/// sectors is not known: the trailing copy stays, and metadata_settle reads
/// the chunk before its next write back.
///
/// Expected execution context - process, the completion of a write back job, which holds the area.
/// @param cache  The metadata cache of the device
/// @param area   The area of the region of the chunk
/// @param sector Logical sector of the chunk
/// @param mask   Sectors of the chunk the job wrote
/// @param ok     Whether the job wrote its leading sector and its data
void metadata_written(struct metadata_cache *cache, struct metadata_area *area, sector_t sector,
                      u8 mask, bool ok)
{
    unsigned int chunk = (unsigned int)(sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS);

    spin_lock(&cache->lock);
    __set_bit(chunk, area->written);
    if (ok)
    {
        area->sectors[chunk] |= mask;
        __clear_bit(metadata_area_sector(sector), area->bad[METADATA_LEAD]);
    }
    if (!ok)
        __set_bit(chunk, area->write_failed);
    if (!area->pinned)
    {
        area->pinned = true;
        area->users++;
        list_add_tail(&area->pin_list, &cache->pinned);
    }
    spin_unlock(&cache->lock);
}

/// @brief Whether a chunk was written back since the last flush, so it needs one before the next write back
bool metadata_written_since_flush(struct metadata_cache *cache, struct metadata_area *area, sector_t sector)
{
    bool written;

    spin_lock(&cache->lock);
    written = test_bit((unsigned int)(sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS), area->written);
    spin_unlock(&cache->lock);

    return written;
}

/// @brief Whether so many areas are busy that the pins have to go before more chunks are written back
/// @details
/// A write back holds one area, which its completion pins, so the worker of the
/// data cache checks this before each chunk. Busy areas then stay below
/// METADATA_CROWDED plus the reads in dm_map, which let theirs go at once.
bool metadata_crowded(struct metadata_cache *cache)
{
    return READ_ONCE(cache->nr_busy) >= METADATA_CROWDED;
}

/// @brief Takes the first pinned area off the list, or NULL; the pin stays until metadata_unpin
static struct metadata_area *metadata_next_pinned(struct metadata_cache *cache)
{
    struct metadata_area *area;

    spin_lock(&cache->lock);
    area = list_first_entry_or_null(&cache->pinned, struct metadata_area, pin_list);
    if (area)
        list_del_init(&area->pin_list);
    spin_unlock(&cache->lock);

    return area;
}

/// @brief Forgets the written chunks of an area taken by metadata_next_pinned and lets its pin go
static void metadata_unpin(struct metadata_cache *cache, struct metadata_area *area)
{
    bool wake;

    spin_lock(&cache->lock);
    bitmap_zero(area->written, REGION_CHUNKS);
    bitmap_zero(area->write_failed, REGION_CHUNKS);
    memset(area->sectors, 0, sizeof(area->sectors));
    area->pinned = false;
    wake = metadata_put_locked(cache, area);
    spin_unlock(&cache->lock);

    if (wake)
        wake_up_all(&cache->wait);
}

/// @brief Puts what was written into the trailing copy in RAM, and records whether it reached the device
/// @details A sector that failed keeps the new contents in RAM and is written again with the next
/// change of the sector; until then reads take the leading copy alone.
static void metadata_trail_done(struct metadata_cache *cache, struct metadata_area *area,
                                unsigned int first, unsigned int end, int r)
{
    unsigned int byte = first * SECTOR_SIZE;
    unsigned int stop = end * SECTOR_SIZE;

    spin_lock(&cache->lock);
    while (byte < stop)
    {
        unsigned int len = min_t(unsigned int, PAGE_SIZE - byte % PAGE_SIZE, stop - byte);

        memcpy(page_address(area->pages[METADATA_TRAIL][byte / PAGE_SIZE]) + byte % PAGE_SIZE,
               page_address(cache->scratch[byte / PAGE_SIZE]) + byte % PAGE_SIZE, len);
        byte += len;
    }
    if (r)
        bitmap_set(area->bad[METADATA_TRAIL], first, end - first);
    else
        bitmap_clear(area->bad[METADATA_TRAIL], first, end - first);
    spin_unlock(&cache->lock);

    if (r)
    {
        atomic64_add(end - first, &cache->trail_errors);
        DM_WARN_LIMIT("trailing metadata of region %llu failed to write at sector %u, err=%d\n",
                      (unsigned long long)area->region, first, r);
    }
}

/// @brief Copies a trailing sector of an area from RAM into the scratch area, and returns where it is there
static __le64 *metadata_trail_to_scratch(struct metadata_cache *cache, struct metadata_area *area,
                                         unsigned int index)
{
    unsigned int byte = index * SECTOR_SIZE;
    void *scratch = page_address(cache->scratch[byte / PAGE_SIZE]) + byte % PAGE_SIZE;

    spin_lock(&cache->lock);
    memcpy(scratch, page_address(area->pages[METADATA_TRAIL][byte / PAGE_SIZE]) + byte % PAGE_SIZE,
           SECTOR_SIZE);
    spin_unlock(&cache->lock);

    return scratch;
}

/// @brief Puts the leading CRCs of some sectors of a chunk into its entry in a trailing sector built in scratch
static void metadata_lead_to_scratch(struct metadata_area *area, __le64 *scratch, unsigned int chunk, u8 mask)
{
    const struct chunk_metadata *lead = metadata_entry(area, METADATA_LEAD, (sector_t)chunk * DATA_SIZE_SECTORS);
    struct chunk_metadata *entry = (struct chunk_metadata *)scratch + chunk % CHUNKS_PER_METADATA_SECTOR;

    for (unsigned int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        if (mask & BIT(i))
            entry->crc[i] = lead->crc[i];
    }
}

/// @brief Writes the trailing sectors [first, end) built in scratch, and takes them into RAM
/// @details Neighbouring sectors go as one request; if it fails, they are written one at a time, so
/// that only the sectors that fail lose their copy.
static void metadata_write_trail_range(struct metadata_cache *cache, struct metadata_area *area,
                                       unsigned int first, unsigned int end, blk_opf_t opf)
{
    int r = metadata_io(area, METADATA_TRAIL, cache->scratch, first, end, opf);

    if (!r || end - first == 1)
    {
        metadata_trail_done(cache, area, first, end, r);
        return;
    }

    for (unsigned int i = first; i < end; i++)
        metadata_trail_done(cache, area, i, i + 1, metadata_io(area, METADATA_TRAIL, cache->scratch, i, i + 1, opf));
}

/// @brief Writes the trailing sectors of an area that cover the chunks written back since the last flush
/// @details
/// Each such sector is built in the scratch area: the trailing sector in RAM,
/// with the leading CRCs of the sectors the write backs wrote put in. A chunk
/// with a write back that failed is left out, as its data is not known.
static void metadata_write_area_trail(struct metadata_cache *cache, struct metadata_area *area)
{
    DECLARE_BITMAP(sectors, REGION_METADATA_SECTORS);
    unsigned int chunk;
    unsigned int first;
    unsigned int end;

    bitmap_zero(sectors, REGION_METADATA_SECTORS);
    for_each_set_bit(chunk, area->written, REGION_CHUNKS)
    {
        if (!test_bit(chunk, area->write_failed) && area->sectors[chunk])
            __set_bit(chunk / CHUNKS_PER_METADATA_SECTOR, sectors);
    }

    for_each_set_bit(first, sectors, REGION_METADATA_SECTORS)
    {
        __le64 *scratch = metadata_trail_to_scratch(cache, area, first);

        for (chunk = first * CHUNKS_PER_METADATA_SECTOR; chunk < (first + 1) * CHUNKS_PER_METADATA_SECTOR; chunk++)
        {
            if (test_bit(chunk, area->written) && !test_bit(chunk, area->write_failed))
                metadata_lead_to_scratch(area, scratch, chunk, area->sectors[chunk]);
        }
    }

    for_each_set_bitrange(first, end, sectors, REGION_METADATA_SECTORS)
        metadata_write_trail_range(cache, area, first, end, REQ_OP_WRITE);
}

/// @brief Reads the data of a chunk from the device below into the chunk page of the cache
/// @return 0, or the error of the read
static int metadata_read_chunk(struct metadata_cache *cache, sector_t sector)
{
    struct bio_vec bvec;
    struct bio bio;
    int r;

    bio_init(&bio, cache->bdev, &bvec, 1, REQ_OP_READ);
    bio.bi_iter.bi_sector = start_data_sector(cache->layout, sector);
    __bio_add_page(&bio, cache->chunk_page, DATA_SIZE_SECTORS * SECTOR_SIZE, 0);
    r = submit_bio_wait(&bio);
    bio_uninit(&bio);

    return r;
}

/// @brief Makes the trailing copy hold the CRC of what the device holds, before a write back of a chunk
/// @details
/// A write back writes the leading copy first, so the trailing copy has to
/// hold the CRC of the data on the device for every sector it writes. That
/// holds wherever the two copies are equal. Where they differ, after a crash
/// or a failed write back, the chunk is read and each such sector compared:
/// if it matches the leading copy, that CRC is written into the trailing copy
/// with FUA first. A sector that matches neither, or a chunk that does not
/// read, is counted and left as it is, so that the damage stays visible. A
/// sector failed in one copy counts as equal to the other.
///
/// The chunk must not have been written back since the last flush of the
/// device below, see metadata_written_since_flush, so that what the read
/// returns is durable. No read of it may be in flight, and none may start.
///
/// Expected execution context - the worker of the data cache, which holds the area; may sleep.
/// @param cache  The metadata cache of the device
/// @param area   The area of the region of the chunk
/// @param sector Logical sector of the chunk
/// @param mask   Sectors of the chunk the write back will write
void metadata_settle(struct metadata_cache *cache, struct metadata_area *area, sector_t sector, u8 mask)
{
    unsigned int index = metadata_area_sector(sector);
    unsigned int chunk = (unsigned int)(sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS);
    struct chunk_metadata md[METADATA_COPIES];
    u8 differ = 0;
    u8 to_trail = 0;
    unsigned int mismatches = 0;
    const u8 *data;

    spin_lock(&cache->lock);
    for (unsigned int copy = 0; copy < METADATA_COPIES; copy++)
    {
        enum metadata_copy from = test_bit(index, area->bad[copy]) ? !copy : copy;

        md[copy] = *metadata_entry(area, from, sector);
    }
    spin_unlock(&cache->lock);

    for (unsigned int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        if ((mask & BIT(i)) && md[METADATA_LEAD].crc[i] != md[METADATA_TRAIL].crc[i])
            differ |= BIT(i);
    }
    if (!differ)
        return;

    atomic64_inc(&cache->settle_reads);
    if (metadata_read_chunk(cache, sector))
    {
        atomic64_add(hweight8(differ), &cache->settle_mismatches);
        DM_WARN_LIMIT("chunk %llu did not read before its write back\n", (unsigned long long)(sector / DATA_SIZE_SECTORS));
        return;
    }

    data = page_address(cache->chunk_page);
    for (unsigned int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        __le64 crc;

        if (!(differ & BIT(i)))
            continue;

        crc = cpu_to_le64(crc64_be(0, data + i * SECTOR_SIZE, SECTOR_SIZE));
        if (crc == md[METADATA_LEAD].crc[i])
            to_trail |= BIT(i);
        else if (crc != md[METADATA_TRAIL].crc[i])
            mismatches++;
    }

    if (mismatches)
    {
        atomic64_add(mismatches, &cache->settle_mismatches);
        DM_WARN_LIMIT("chunk %llu: %u sectors match neither copy of the metadata before its write back\n",
                      (unsigned long long)(sector / DATA_SIZE_SECTORS), mismatches);
    }

    if (to_trail)
    {
        metadata_lead_to_scratch(area, metadata_trail_to_scratch(cache, area, index), chunk, to_trail);
        metadata_write_trail_range(cache, area, index, index + 1, REQ_OP_WRITE | REQ_FUA);
    }
}

/// @brief Writes the trailing copy of every chunk written back since the last flush, and unpins the areas
/// @details
/// Called by the data cache once the lower device has flushed after those
/// write backs, with none in flight: the data is durable, so its CRCs may go
/// into the second copy. The writes are not flushed here; the caller flushes.
///
/// Expected execution context - the worker of the data cache, or postsuspend; may sleep.
void metadata_write_trails(struct metadata_cache *cache)
{
    struct metadata_area *area;

    while ((area = metadata_next_pinned(cache)))
    {
        metadata_write_area_trail(cache, area);
        metadata_unpin(cache, area);
    }
}

/// @brief Unpins every area without writing the trailing copies
/// @details
/// For when the lower device failed to flush, so that the data written back
/// may not be durable: the trailing copies keep the CRCs they had.
void metadata_unpin_all(struct metadata_cache *cache)
{
    struct metadata_area *area;

    while ((area = metadata_next_pinned(cache)))
        metadata_unpin(cache, area);
}

/// @brief Forgets every area, so that the next use of a region reads it from the device below
/// @details
/// Called when the device is suspended, as the device below may change before
/// it is resumed: its table may be replaced. Nothing is in flight then, and the
/// data cache has written the trailing copies, so no area is in use.
///
/// Expected execution context - process, postsuspend.
void metadata_drop(struct metadata_cache *cache)
{
    struct metadata_area *area;
    struct metadata_area *next;

    spin_lock(&cache->lock);
    WARN_ON(!list_empty(&cache->pinned));
    list_for_each_entry_safe(area, next, &cache->lru, list)
    {
        rb_erase(&area->node, &cache->tree);
        RB_CLEAR_NODE(&area->node);
        area->state = METADATA_FREE;
        list_move(&area->list, &cache->free);
    }
    WARN_ON(!RB_EMPTY_ROOT(&cache->tree));
    spin_unlock(&cache->lock);
}

/// @brief Frees the pages of the areas and the tables
static void metadata_cache_free(struct metadata_cache *cache)
{
    if (cache->wq)
        destroy_workqueue(cache->wq);

    if (cache->areas)
    {
        for (unsigned int i = 0; i < METADATA_AREAS; i++)
        {
            for (unsigned int copy = 0; copy < METADATA_COPIES; copy++)
            {
                for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
                {
                    if (cache->areas[i].pages[copy][j])
                        __free_page(cache->areas[i].pages[copy][j]);
                }
            }
        }
    }

    for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
    {
        if (cache->scratch[j])
            __free_page(cache->scratch[j]);
    }

    if (cache->chunk_page)
        __free_page(cache->chunk_page);

    kvfree(cache->areas);
    kfree(cache);
}

/// @brief Allocates the metadata cache whole: areas, their pages and the workqueue of loads
/// @details
/// Expected execution context - dm_ctr, may sleep.
/// @param bdev    The device below
/// @param layout  Layout of the device, which must outlive the cache
/// @return The cache, or ERR_PTR(-ENOMEM)
struct metadata_cache *metadata_cache_create(struct block_device *bdev, const struct dcorr_layout *layout)
{
    struct metadata_cache *cache = kzalloc_obj(*cache, GFP_KERNEL);

    if (!cache)
        return ERR_PTR(-ENOMEM);

    spin_lock_init(&cache->lock);
    cache->tree = RB_ROOT;
    INIT_LIST_HEAD(&cache->free);
    INIT_LIST_HEAD(&cache->lru);
    INIT_LIST_HEAD(&cache->pinned);
    init_waitqueue_head(&cache->wait);
    cache->bdev = bdev;
    cache->layout = layout;
    atomic64_set(&cache->loads, 0);
    atomic64_set(&cache->waits, 0);
    atomic64_set(&cache->trail_errors, 0);
    atomic64_set(&cache->settle_reads, 0);
    atomic64_set(&cache->settle_mismatches, 0);

    cache->areas = kvcalloc(METADATA_AREAS, sizeof(*cache->areas), GFP_KERNEL);
    cache->wq = alloc_workqueue("dcorr_metadata", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    cache->chunk_page = alloc_page(GFP_KERNEL);
    if (!cache->areas || !cache->wq || !cache->chunk_page)
        goto error;

    for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
    {
        cache->scratch[j] = alloc_page(GFP_KERNEL);
        if (!cache->scratch[j])
            goto error;
    }

    for (unsigned int i = 0; i < METADATA_AREAS; i++)
    {
        struct metadata_area *area = &cache->areas[i];

        for (unsigned int copy = 0; copy < METADATA_COPIES; copy++)
        {
            for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
            {
                area->pages[copy][j] = alloc_page(GFP_KERNEL);
                if (!area->pages[copy][j])
                    goto error;
            }
        }
        RB_CLEAR_NODE(&area->node);
        INIT_LIST_HEAD(&area->pin_list);
        area->state = METADATA_FREE;
        area->cache = cache;
        INIT_WORK(&area->load_work, metadata_load);
        list_add_tail(&area->list, &cache->free);
    }

    return cache;

error:
    metadata_cache_free(cache);
    return ERR_PTR(-ENOMEM);
}

/// @brief Frees the metadata cache
/// @details
/// Expected execution context - dm_dtr, after the data cache is destroyed, may sleep.
void metadata_cache_destroy(struct metadata_cache *cache)
{
    for (unsigned int i = 0; i < METADATA_AREAS; i++)
        WARN_ON(cache->areas[i].users || cache->areas[i].state == METADATA_LOADING);

    metadata_cache_free(cache);
}

#include <linux/blkdev.h>
#include <linux/slab.h>

#include "metadata.h"
#include "macros.h"

/// @brief First sector of the metadata area of a region on the device below
static sector_t metadata_area_start(sector_t region)
{
    return region * REGION_SECTORS + REGION_METADATA_SECTORS;
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

/// @brief Reads one sector of an area again, after the read of the whole area failed
/// @return 0, or the error of the read
static int metadata_load_sector(struct metadata_area *area, unsigned int index)
{
    struct bio_vec bvec;
    struct bio bio;
    unsigned int byte = index * SECTOR_SIZE;
    int r;

    bio_init(&bio, area->cache->bdev, &bvec, 1, REQ_OP_READ);
    bio.bi_iter.bi_sector = metadata_area_start(area->region) + index;
    __bio_add_page(&bio, area->pages[byte / PAGE_SIZE], SECTOR_SIZE, byte % PAGE_SIZE);
    r = submit_bio_wait(&bio);
    bio_uninit(&bio);

    return r;
}

/// @brief Reads an area from the device below
/// @details
/// Reads the whole area in one request. If that fails, reads its sectors one
/// at a time, so that a failed sector fails only the chunks whose entries it
/// holds, and marks the sectors that failed. An area with such sectors leaves
/// the tree: those who wait for it now get it, and the next to need the region
/// reads it again, so that a sector that reads again is seen.
///
/// Runs on the workqueue of the cache, never in transform_wq, as it waits for
/// its reads.
static void metadata_load(struct work_struct *work)
{
    struct metadata_area *area = container_of(work, struct metadata_area, load_work);
    struct metadata_cache *cache = area->cache;
    struct bio_vec bvecs[METADATA_AREA_PAGES];
    struct bio bio;
    unsigned int failed = 0;
    int r;

    bio_init(&bio, cache->bdev, bvecs, METADATA_AREA_PAGES, REQ_OP_READ);
    bio.bi_iter.bi_sector = metadata_area_start(area->region);
    for (unsigned int i = 0; i < METADATA_AREA_PAGES; i++)
        __bio_add_page(&bio, area->pages[i], min_t(unsigned int, PAGE_SIZE, METADATA_AREA_BYTES - i * PAGE_SIZE), 0);
    r = submit_bio_wait(&bio);
    bio_uninit(&bio);

    bitmap_zero(area->bad, REGION_METADATA_SECTORS);
    if (r)
    {
        for (unsigned int i = 0; i < REGION_METADATA_SECTORS; i++)
        {
            if (metadata_load_sector(area, i))
            {
                __set_bit(i, area->bad);
                failed++;
            }
        }
        DM_ERR_LIMIT("metadata of region %llu failed to read, err=%d, %u of its sectors fail\n",
                     (unsigned long long)area->region, r, failed);
    }

    atomic64_inc(&cache->loads);

    spin_lock(&cache->lock);
    area->state = METADATA_VALID;
    if (failed)
    {
        area->failed = true;
        rb_erase(&area->node, &cache->tree);
        RB_CLEAR_NODE(&area->node);
    }
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

/// @brief Gets the area of the region of a logical sector, reading it first if it is not in RAM
/// @details
/// Waits while the area is loading, and while every area is in use or loading
/// and none can take the region. The area is held until metadata_put, so it
/// stays in RAM. Its sectors that failed to read are marked in it, see
/// metadata_sector_bad.
///
/// The waits end without the caller: a load runs on the workqueue of the cache
/// and does not wait for anything else, and areas are held only by loads and by
/// write backs in flight. So dm_map may wait here: the read it waits for is not
/// on its current->bio_list.
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
            if (!area->users++)
                list_del_init(&area->list);
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
            area->state = METADATA_LOADING;
            area->users = 1;
            area->failed = false;
            metadata_insert(cache, area);
            spin_unlock(&cache->lock);

            queue_work(cache->wq, &area->load_work);

            spin_lock(&cache->lock);
            while (area->state == METADATA_LOADING)
                metadata_wait(cache);
            break;
        }

        atomic64_inc(&cache->waits);
        metadata_wait(cache);
    }
    spin_unlock(&cache->lock);

    return area;
}

/// @brief Puts an area nobody holds any more at the end of the LRU; the lock must be held
/// @details An area some of whose sectors failed to read has left the tree already, and is freed.
static void metadata_release(struct metadata_cache *cache, struct metadata_area *area)
{
    if (area->failed)
    {
        area->state = METADATA_FREE;
        list_add(&area->list, &cache->free);
        return;
    }

    list_add_tail(&area->list, &cache->lru);
}

/// @brief Lets an area go
/// @details
/// The last holder puts it at the end of the LRU, or frees it if some of its
/// sectors failed to read.
///
/// Expected execution context - process.
void metadata_put(struct metadata_cache *cache, struct metadata_area *area)
{
    bool wake;

    spin_lock(&cache->lock);
    wake = !--area->users;
    if (wake)
    {
        metadata_release(cache, area);
        metadata_event(cache);
    }
    spin_unlock(&cache->lock);

    if (wake)
        wake_up_all(&cache->wait);
}

/// @brief Copies the entry of the chunk of a logical sector, for a read
/// @details
/// The read is in the tree of reads of the data cache, so no write back of the
/// chunk changes the entry until it completes, and the copy is what the device
/// below holds for it.
///
/// Expected execution context - dm_map, may sleep, see metadata_get.
/// @param cache  The metadata cache of the device
/// @param sector Logical sector
/// @param md     Where to copy the entry
/// @return BLK_STS_OK, or BLK_STS_IOERR if the metadata sector of the chunk failed to read
blk_status_t metadata_copy_entry(struct metadata_cache *cache, sector_t sector, struct chunk_metadata *md)
{
    struct metadata_area *area = metadata_get(cache, sector);
    blk_status_t status = BLK_STS_OK;

    if (metadata_sector_bad(area, sector))
        status = BLK_STS_IOERR;
    else
        *md = *metadata_entry(area, sector);
    metadata_put(cache, area);

    return status;
}

/// @brief Forgets every area, so that the next use of a region reads it from the device below
/// @details
/// Called when the device is suspended, as the device below may change before
/// it is resumed: its table may be replaced. Nothing is in flight then, so no
/// area is in use.
///
/// Expected execution context - process, postsuspend.
void metadata_drop(struct metadata_cache *cache)
{
    struct metadata_area *area;
    struct metadata_area *next;

    spin_lock(&cache->lock);
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
            for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
            {
                if (cache->areas[i].pages[j])
                    __free_page(cache->areas[i].pages[j]);
            }
        }
    }

    kvfree(cache->areas);
    kfree(cache);
}

/// @brief Allocates the metadata cache whole: areas, their pages and the workqueue of loads
/// @details
/// Expected execution context - dm_ctr, may sleep.
/// @param bdev The device below
/// @return The cache, or ERR_PTR(-ENOMEM)
struct metadata_cache *metadata_cache_create(struct block_device *bdev)
{
    struct metadata_cache *cache = kzalloc_obj(*cache, GFP_KERNEL);

    if (!cache)
        return ERR_PTR(-ENOMEM);

    spin_lock_init(&cache->lock);
    cache->tree = RB_ROOT;
    INIT_LIST_HEAD(&cache->free);
    INIT_LIST_HEAD(&cache->lru);
    init_waitqueue_head(&cache->wait);
    cache->bdev = bdev;
    atomic64_set(&cache->loads, 0);
    atomic64_set(&cache->waits, 0);

    cache->areas = kvcalloc(METADATA_AREAS, sizeof(*cache->areas), GFP_KERNEL);
    cache->wq = alloc_workqueue("corrdm_metadata", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!cache->areas || !cache->wq)
        goto error;

    for (unsigned int i = 0; i < METADATA_AREAS; i++)
    {
        struct metadata_area *area = &cache->areas[i];

        for (unsigned int j = 0; j < METADATA_AREA_PAGES; j++)
        {
            area->pages[j] = alloc_page(GFP_KERNEL);
            if (!area->pages[j])
                goto error;
        }
        RB_CLEAR_NODE(&area->node);
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

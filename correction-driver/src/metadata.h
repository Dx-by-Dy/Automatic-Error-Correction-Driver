#ifndef METADATA_H
#define METADATA_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "alignment.h"

/// @brief Size of the metadata kept in RAM, allocated whole in dm_ctr
#define METADATA_CACHE_BYTES (4UL << 20)

/// @brief Bytes of one copy of the metadata area of a region
#define METADATA_AREA_BYTES (REGION_METADATA_SECTORS * SECTOR_SIZE)

/// @brief Pages of one copy of an area in RAM
#define METADATA_AREA_PAGES DIV_ROUND_UP(METADATA_AREA_BYTES, PAGE_SIZE)

/// @brief The copies of the metadata of a region
enum metadata_copy
{
    /// @brief Next to the data, written with each write back of a chunk
    METADATA_LEAD,

    /// @brief In the next region, written after the lower device has flushed
    METADATA_TRAIL,

    METADATA_COPIES,
};

/// @brief Number of areas kept in RAM, each with both copies
#define METADATA_AREAS (METADATA_CACHE_BYTES / (METADATA_COPIES * METADATA_AREA_BYTES))

/// @brief The worker of the data cache writes the trailing copies once this many areas are busy,
/// see metadata_crowded
#define METADATA_CROWDED (METADATA_AREAS / 2)

static_assert(PAGE_SIZE % SECTOR_SIZE == 0, "a metadata sector must not cross a page");

/// @brief Representation of one chunk's metadata stored on disk
/// @details
/// The entry of a chunk in the metadata area of its region, next to the
/// entries of its neighbours. Contains CRC64 for each data sector, computed in
/// order of increasing sector index. Both copies of the area hold it.
struct chunk_metadata
{
    /// @brief CRC64 for each data sector of the chunk
    __le64 crc[DATA_SIZE_SECTORS];
};

static_assert(sizeof(struct chunk_metadata) == METADATA_ENTRY_SIZE, "the entry of a chunk has a fixed size");

/// @brief State of an area in RAM
enum metadata_state
{
    /// @brief On the free list, not in the tree
    METADATA_FREE,

    /// @brief Being read from the device below; whoever needs it waits
    METADATA_LOADING,

    /// @brief Holds the metadata of its region, except the sectors in bad
    METADATA_VALID,
};

struct metadata_cache;

/// @brief The metadata of one region, both copies, kept in RAM
/// @details
/// Its contents follow the device below: both copies are read from it, and
/// after that only a write back changes the leading entries of its chunks, in
/// place, and writes the changed sector; metadata_write_trails copies those
/// entries into the trailing copy and writes it, once the lower device has
/// flushed. An area with chunks so written is pinned until then; any other one
/// nobody holds is dropped at any time without being written.
///
/// A sector that failed to read in one copy is filled from the other in RAM,
/// so the area holds what one copy of the device below does. Protected by the
/// lock of the metadata cache, except for the leading entries: such an entry is
/// read or changed only by whom the data cache keeps other I/O of that chunk
/// away from, or by metadata_write_trails, when no write back is in flight.
struct metadata_area
{
    /// @brief Node in the tree of the metadata cache, by region, while it is there
    struct rb_node node;

    /// @brief Node in the free list or in the LRU; empty while in use or loading
    struct list_head list;

    /// @brief Node in the list of pinned areas, while pinned
    struct list_head pin_list;

    /// @brief Number of the region whose metadata the area holds
    sector_t region;

    /// @brief State of the area
    enum metadata_state state;

    /// @brief Holders of the area, a pin among them: it is not dropped while anyone holds it
    unsigned int users;

    /// @brief Some sectors failed to read in both copies. The next to get the area when nobody
    /// holds it reads it again.
    bool failed;

    /// @brief Some chunks were written back since the trailing copy was last written; the area
    /// holds itself until metadata_write_trails
    bool pinned;

    /// @brief Sectors of each copy that failed to read, and of the trailing copy that failed to write;
    /// reads take such a sector from the other copy
    DECLARE_BITMAP(bad[METADATA_COPIES], REGION_METADATA_SECTORS);

    /// @brief Chunks written back since the trailing copy was last written
    DECLARE_BITMAP(written, REGION_CHUNKS);

    /// @brief The metadata, METADATA_AREA_BYTES of each copy
    struct page *pages[METADATA_COPIES][METADATA_AREA_PAGES];

    /// @brief Reads the area from the device below
    struct work_struct load_work;

    /// @brief The cache of the area
    struct metadata_cache *cache;
};

/// @brief The metadata areas of a device kept in RAM
/// @details
/// Everything is allocated in metadata_cache_create. An area is read from the
/// device below the first time a chunk of its region needs it, and stays until
/// it is the least recently used one that nobody holds and another region needs
/// a place, or the device is suspended.
struct metadata_cache
{
    /// @brief Protects everything below but the counters, the areas and their trailing copies in RAM,
    /// not the leading copies, see struct metadata_area
    spinlock_t lock;

    /// @brief Areas that hold or are loading a region, by region
    struct rb_root tree;

    /// @brief Free areas
    struct list_head free;

    /// @brief Valid areas nobody holds, the least recently used first
    struct list_head lru;

    /// @brief Pinned areas
    struct list_head pinned;

    /// @brief Areas someone holds, the loading and the pinned among them
    unsigned int nr_busy;

    /// @brief Changes whenever an area is loaded or let go
    u64 events;

    /// @brief Woken when events changes
    wait_queue_head_t wait;

    /// @brief METADATA_AREAS areas
    struct metadata_area *areas;

    /// @brief One copy of an area, where metadata_write_trails builds what it writes
    struct page *scratch[METADATA_AREA_PAGES];

    /// @brief Workqueue of the loads, which wait for their reads
    struct workqueue_struct *wq;

    /// @brief The device below
    struct block_device *bdev;

    /// @brief Number of regions of the device
    sector_t regions;

    /// @brief How many areas were read from the device below
    atomic64_t loads;

    /// @brief How many times anyone waited for an area to be let go, as all were in use
    atomic64_t waits;

    /// @brief How many sectors of the trailing copies failed to write
    atomic64_t trail_errors;
};

struct metadata_cache *metadata_cache_create(struct block_device *bdev, sector_t regions);
void metadata_cache_destroy(struct metadata_cache *cache);
struct metadata_area *metadata_get(struct metadata_cache *cache, sector_t sector);
void metadata_put(struct metadata_cache *cache, struct metadata_area *area);
blk_status_t metadata_copy_entries(struct metadata_cache *cache, sector_t sector,
                                   struct chunk_metadata md[METADATA_COPIES]);
void metadata_written(struct metadata_cache *cache, struct metadata_area *area, sector_t sector);
bool metadata_crowded(struct metadata_cache *cache);
void metadata_write_trails(struct metadata_cache *cache);
void metadata_unpin_all(struct metadata_cache *cache);
void metadata_drop(struct metadata_cache *cache);

/// @brief Index of the metadata sector of the chunk of a logical sector in the area of its region
static inline unsigned int metadata_area_sector(sector_t sector)
{
    return (unsigned int)(sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS / CHUNKS_PER_METADATA_SECTOR);
}

/// @brief Whether the metadata sector of the chunk of a logical sector failed to read in both copies
static inline bool metadata_sector_bad(const struct metadata_area *area, sector_t sector)
{
    unsigned int index = metadata_area_sector(sector);

    return test_bit(index, area->bad[METADATA_LEAD]) && test_bit(index, area->bad[METADATA_TRAIL]);
}

/// @brief Whether the metadata sector of the chunk of a logical sector is bad in one copy only
static inline bool metadata_sector_single(const struct metadata_area *area, sector_t sector)
{
    unsigned int index = metadata_area_sector(sector);

    return test_bit(index, area->bad[METADATA_LEAD]) != test_bit(index, area->bad[METADATA_TRAIL]);
}

/// @brief The page of a copy of an area that holds the metadata sector of the chunk of a logical sector
/// @param area   The area of the region of the sector
/// @param copy   Which copy
/// @param sector Logical sector
/// @param offset Set to the offset of the metadata sector in the page
static inline struct page *metadata_sector_page(const struct metadata_area *area, enum metadata_copy copy,
                                                sector_t sector, unsigned int *offset)
{
    unsigned int byte = metadata_area_sector(sector) * SECTOR_SIZE;

    *offset = byte % PAGE_SIZE;
    return area->pages[copy][byte / PAGE_SIZE];
}

/// @brief The entry of the chunk of a logical sector in a copy of the area of its region
/// @details The pages of an area come from the direct map, so the address stays valid.
static inline struct chunk_metadata *metadata_entry(const struct metadata_area *area, enum metadata_copy copy,
                                                    sector_t sector)
{
    unsigned int byte = (unsigned int)(sector % REGION_DATA_SECTORS / DATA_SIZE_SECTORS) * METADATA_ENTRY_SIZE;

    return page_address(area->pages[copy][byte / PAGE_SIZE]) + byte % PAGE_SIZE;
}

#endif

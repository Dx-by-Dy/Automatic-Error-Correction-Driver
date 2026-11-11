#ifndef CACHE_H
#define CACHE_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "alignment.h"

/// @brief Size of the data the cache holds, allocated whole in dm_ctr
#define CACHE_SIZE_BYTES (64UL << 20)

/// @brief Number of entries, one chunk of data each
#define CACHE_ENTRIES (CACHE_SIZE_BYTES / (DATA_SIZE_SECTORS * SECTOR_SIZE))

/// @brief Write back starts when this share of the entries is in use
#define CACHE_START_PERCENT 50

/// @brief Write back goes on until no more than this share would stay in use
#define CACHE_STOP_PERCENT 45

/// @brief Dirty data older than this is written back without waiting for a flush
#define CACHE_AGE_MS 1000

/// @brief Number of write back jobs, so of lower writes of the cache, in flight at once
#define CACHE_JOBS 256

struct dm_context;
struct cache_job;

/// @brief State of a cache entry
enum cache_state
{
    /// @brief On the free list, not in the tree
    CACHE_FREE,

    /// @brief Holds data not yet written back, on the dirty list in order of age
    CACHE_DIRTY,

    /// @brief Its data is being written back; writes to it and reads of its clean sectors wait,
    /// reads of its dirty sectors still use it
    CACHE_WRITING,

    /// @brief Its write back failed; the data stays, and a flush retries it
    CACHE_FAILED,
};

/// @brief One chunk of data in the cache
/// @details
/// The page holds the data sectors of the chunk at their place in the chunk.
/// Only the sectors in mask hold data written from above; the others were
/// never read, so the device below has their contents. Protected by the lock
/// of the cache.
struct cache_entry
{
    /// @brief Node in the tree of the cache, ordered by chunk, while not CACHE_FREE
    struct rb_node node;

    /// @brief Node in the free, dirty or failed list; empty while CACHE_WRITING
    struct list_head list;

    /// @brief Number of the chunk: its first logical sector divided by DATA_SIZE_SECTORS
    sector_t chunk;

    /// @brief Time in jiffies when the entry became dirty
    unsigned long dirtied;

    /// @brief The data of the chunk
    struct page *page;

    /// @brief Bit i is set if sector i of the chunk holds data written from above
    u8 mask;

    /// @brief Write back jobs of the entry not yet done
    u8 jobs;

    /// @brief State of the entry
    enum cache_state state;

    /// @brief First error of the jobs of the current write back
    blk_status_t status;
};

/// @brief A read of the device below in flight, in the tree of reads of the cache
/// @details
/// Lives in the per-bio data of the read, so registering it allocates nothing.
/// A write back of the chunk waits until no read of it is in flight, so that
/// a read never sees the data of one version and the CRC of another.
struct cache_range
{
    /// @brief Node in the tree of reads, ordered by chunk; chunks may repeat
    struct rb_node node;

    /// @brief Number of the chunk read
    sector_t chunk;
};

/// @brief Write back cache of a device
/// @details
/// Writes are copied into entries and complete at once; a worker writes them
/// back to the device below. Everything that can be needed on the I/O path is
/// allocated in cache_create.
///
/// The spinlock protects the trees, the lists, the counters and the entries.
/// It is held only for a lookup and a copy of at most one chunk, never across
/// I/O or a wait. Whoever has to wait (dm_map for an entry, the worker for a
/// job) records events, drops the lock and waits for events to change.
struct cache
{
    /// @brief Protects everything below but the counters of waits
    spinlock_t lock;

    /// @brief Entries that are not free, by chunk
    struct rb_root tree;

    /// @brief Reads of the device below in flight, struct cache_range by chunk
    struct rb_root reads;

    /// @brief Write back jobs in flight, at most one per metadata sector, by the number of the sector
    struct rb_root sectors;

    /// @brief Free entries
    struct list_head free;

    /// @brief Dirty entries, the oldest first
    struct list_head dirty;

    /// @brief Entries whose write back failed
    struct list_head failed;

    /// @brief Free write back jobs
    struct list_head jobs;

    unsigned long nr_free;
    unsigned long nr_dirty;
    unsigned long nr_writing;
    unsigned long nr_failed;

    /// @brief Flushes and FUA writes waiting for the worker
    struct bio_list flushes;

    /// @brief The worker writes back everything dirty, set during a suspend
    bool write_all;

    /// @brief The device is suspended: the worker does not schedule itself
    bool suspended;

    /// @brief Changes whenever an entry or a job is given back or changes state, and when a
    /// read of a chunk under write back completes
    u64 events;

    /// @brief Woken when events changes
    wait_queue_head_t wait;

    /// @brief CACHE_ENTRIES entries
    struct cache_entry *entries;

    /// @brief CACHE_JOBS jobs
    struct cache_job *job_table;

    /// @brief Ordered workqueue of the worker, separate from the completions
    struct workqueue_struct *wq;

    /// @brief The worker: write back by age and pressure, flushes, suspend
    struct delayed_work write_back;

    /// @brief Driver context, for the device below and the parts
    struct dm_context *dm_ctx;

    /// @brief How many times dm_map waited for a free entry
    atomic64_t free_waits;

    /// @brief How many times a write in dm_map waited for an entry under write back
    atomic64_t busy_waits;

    /// @brief How many reads in dm_map waited for the write back of their chunk
    atomic64_t read_waits;
};

struct cache *cache_create(struct dm_context *dm_ctx);
void cache_destroy(struct cache *cache);
void cache_write(struct cache *cache, struct bio *bio);
bool cache_read(struct cache *cache, struct bio *bio, struct cache_range *range);
void cache_read_done(struct cache *cache, struct cache_range *range);
void cache_flush(struct cache *cache, struct bio *bio);
void cache_suspend(struct cache *cache);
void cache_resume(struct cache *cache);
void cache_counters(struct cache *cache, unsigned long *dirty, unsigned long *failed);

#endif

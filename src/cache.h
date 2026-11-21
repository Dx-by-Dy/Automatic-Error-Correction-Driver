#ifndef CACHE_H
#define CACHE_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "events.h"
#include "layout.h"
#include "stats.h"

/// @brief Size of the data the cache holds, allocated whole in dcorr_ctr
#define CACHE_SIZE_BYTES (64UL << 20)

/// @brief Number of entries, one chunk of data each
#define CACHE_ENTRIES (CACHE_SIZE_BYTES / (DCORR_CHUNK_SECTORS * SECTOR_SIZE))

/// @brief Write back starts when this share of the entries is in use
#define CACHE_START_PERCENT 50

/// @brief Write back goes on until no more than this share would stay in use
#define CACHE_STOP_PERCENT 45

/// @brief Dirty data older than this is written back without waiting for a flush
#define CACHE_AGE_MS 1000

/// @brief Number of write back jobs, so of lower writes of the cache, in flight at once
#define CACHE_JOBS 256

/// @brief Chunks that reads may hand to the worker to settle before it runs, see cache_queue_settle
#define CACHE_SETTLES 64

struct dcorr_ctx;
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
/// never read, so the lower device has their contents. Protected by the lock
/// of the cache.
struct cache_entry
{
    /// @brief Node in the tree of the cache, ordered by chunk, while not CACHE_FREE
    struct rb_node node;

    /// @brief Node in the free, dirty or failed list; empty while CACHE_WRITING
    struct list_head list;

    /// @brief Number of the chunk: its first logical sector divided by DCORR_CHUNK_SECTORS
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

/// @brief A read of the lower device in flight, in the tree of reads of the cache
/// @details
/// Lives in the per-bio data of the read, so registering it allocates nothing.
/// A write back of the chunk waits until no read of it is in flight, so that
/// a read never sees the data of one version and the CRC of another.
struct cache_lower_read
{
    /// @brief Node in the tree of reads, ordered by chunk; chunks may repeat
    struct rb_node node;

    /// @brief Number of the chunk read
    sector_t chunk;
};

/// @brief Write back cache of a device
/// @details
/// Writes are copied into entries and complete at once; a worker writes them
/// back to the lower device. Everything that can be needed on the I/O path is
/// allocated in cache_create.
///
/// The spinlock protects the trees, the lists, the counters and the entries.
/// It is held only for a lookup and a copy of at most one chunk, never across
/// I/O or a wait. Whoever has to wait (dcorr_map for an entry, the worker for a
/// job) records events, drops the lock and waits for events to change.
struct cache
{
    /// @brief Protects everything below but the counters of waits
    spinlock_t lock;

    /// @brief Entries that are not free, by chunk
    struct rb_root tree;

    /// @brief Reads of the lower device in flight, struct cache_lower_read by chunk
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
    struct list_head free_jobs;

    unsigned long nr_free;
    unsigned long nr_dirty;
    unsigned long nr_writing;
    unsigned long nr_failed;

    /// @brief Write back jobs in flight, the queued ones among them
    unsigned int nr_jobs;

    /// @brief Flushes and FUA writes waiting for the worker
    struct bio_list flushes;

    /// @brief Discards waiting for the worker, see cache_discard
    struct bio_list discards;

    /// @brief Changes whenever a discard clears a bit of the bitmap of written chunks
    /// @details Changed and read only by the worker, or in postsuspend once it is cancelled.
    u64 clears;

    /// @brief The value of clears the last sync made durable, see cache_prepare_metadata
    u64 synced_clears;

    /// @brief Chunks that reads found settled in the leading copy only, for the worker to settle
    sector_t settles[CACHE_SETTLES];

    /// @brief How many of settles are in use
    unsigned int nr_settles;

    /// @brief The lower device has flushed since the table was created, see cache_flush_lower
    /// @details Changed and read only by the worker, or in postsuspend once it is cancelled.
    bool lower_flushed;

    /// @brief The worker writes back everything dirty, set during a suspend
    bool write_all;

    /// @brief The device is suspended: the worker does not schedule itself
    bool suspended;

    /// @brief An event whenever an entry or a job is given back or changes state, and when a
    /// read of a chunk under write back completes; the waits for no write back in flight are on its
    /// queue too
    struct dcorr_events events;

    /// @brief CACHE_ENTRIES entries
    struct cache_entry *entries;

    /// @brief CACHE_JOBS jobs
    struct cache_job *job_table;

    /// @brief Ordered workqueue of the worker, separate from the completions
    struct workqueue_struct *wq;

    /// @brief The worker: write back by age and pressure, flushes, suspend
    struct delayed_work worker;

    /// @brief The context of the target, for the lower device and the parts
    struct dcorr_ctx *dc;

    /// @brief The counters of the device, owned by its context
    struct dcorr_stats *stats;
};

struct cache *cache_create(struct dcorr_ctx *dc);
void cache_destroy(struct cache *cache);
void cache_write(struct cache *cache, struct bio *bio);
void cache_write_zeroes(struct cache *cache, struct bio *bio);
bool cache_read(struct cache *cache, struct bio *bio, struct cache_lower_read *lower);
void cache_read_done(struct cache *cache, struct cache_lower_read *lower);
void cache_queue_settle(struct cache *cache, sector_t chunk);
void cache_flush(struct cache *cache, struct bio *bio);
void cache_discard(struct cache *cache, struct bio *bio);
void cache_suspend(struct cache *cache);
void cache_resume(struct cache *cache);
void cache_counters(struct cache *cache, unsigned long *dirty, unsigned long *failed);

#endif

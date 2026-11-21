#ifndef WRITTEN_H
#define WRITTEN_H

#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "stats.h"
#include "superblock.h"

/// @brief A write of one copy of a block of the bitmap, embedded so that a sync allocates nothing
struct written_io
{
    struct bio bio;
    struct bio_vec bvec;
    struct written_map *map;
    /// @brief The error of the write, 0 if it succeeded
    int error;
};

/// @brief The bitmap of written chunks of a device, all of it in RAM
/// @details
/// A bit per slot of a group, see struct dcorr_bitmap_block; a chunk whose bit
/// is clear has never been written back since the format, and reads as zeros
/// without a read of the lower device. The blocks are kept in RAM as they lie
/// on the device, one page each, their headers rebuilt for each write.
///
/// A bit is set by the data cache when the first write back of its chunk
/// succeeds, and reaches the device in the next sync of the cache, see
/// written_write_first and written_write_second: one copy of each changed block
/// after the flush that made the data durable, the other one after the next
/// flush. A bit on the device thus means the data of its chunk is durable. A
/// discard clears the bits of its whole chunks, see written_clear; that reaches
/// the device with the next sync too.
///
/// Bits and flags change with atomic bit operations: bits under the lock of the
/// data cache, the flags of a sync when no write back is in flight. A sync
/// writes a block from its page in RAM, so no bit may change while it runs:
/// bits are set by the completions of write backs, of which none is in flight
/// then, and cleared by the worker of the data cache, which runs the syncs.
struct written_map
{
    /// @brief The target, for its name in the log and its errors, see dcorr_error
    struct dm_target *ti;

    /// @brief The layout and the salt, owned by the context of the target
    const struct superblock_info *sb;

    /// @brief The counters of the device, owned by the context of the target
    struct dcorr_stats *stats;

    /// @brief The lower device
    struct block_device *bdev;

    /// @brief Blocks of all groups, bitmap_blocks of each, group by group
    u64 nr_blocks;

    /// @brief The page of each block
    struct page **pages;

    /// @brief The write of each block, for a sync
    struct written_io *ios;

    /// @brief Blocks changed since they were last written, or to be repaired
    unsigned long *dirty;

    /// @brief Blocks whose first copy was written in this sync, so the other one is to follow
    unsigned long *pending;

    /// @brief Blocks whose trailing copy is not known to be valid on the device, so it is written first
    unsigned long *trail_first;

    /// @brief Blocks invalid in both copies: their chunks read as written, writes there fail
    unsigned long *read_only;

    /// @brief Whether the table may write: no block is repaired otherwise
    bool writable;

    /// @brief Whether the bitmap was read from the device, see written_load_once
    bool loaded;

    /// @brief Writes of a sync in flight, and who waits for them
    atomic_t in_flight;
    wait_queue_head_t wait;
};

struct dm_target;

struct written_map *written_create(struct dm_target *ti, struct block_device *bdev, const struct superblock_info *sb,
                                   struct dcorr_stats *stats, bool writable);
void written_destroy(struct written_map *map);
int written_load_once(struct written_map *map);
bool written_test(struct written_map *map, sector_t sector);
void written_set(struct written_map *map, sector_t sector);
bool written_clear(struct written_map *map, sector_t sector, u64 chunks, u64 *done);
bool written_range_read_only(struct written_map *map, sector_t sector, sector_t sectors);
int written_write_first(struct written_map *map);
void written_write_second(struct written_map *map);
void written_abort(struct written_map *map);

#endif

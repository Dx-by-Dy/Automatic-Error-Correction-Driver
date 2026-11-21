#ifndef DM_DCORR_H
#define DM_DCORR_H

#include <linux/device-mapper.h>
#include <linux/semaphore.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "stats.h"
#include "superblock.h"

/// @brief Number of parts that may be in flight at once
/// @details
/// Reads from the lower device and write back jobs of the cache are parts. A
/// bio-based device has no request queue with tags, so without a limit the
/// submitters fill memory with parts. 4096 parts are 16 MiB of data, far more
/// than a disk queue of 256 requests takes, so ordinary load never reaches it.
#define MAX_PARTS_IN_FLIGHT 4096

struct cache;
struct metadata_cache;
struct written_map;

/// @brief The context of a target
/// @details
/// Created in dcorr_ctr and stored in ti->private. Holds everything the I/O
/// of the device needs: the lower device, the workqueue of the parts, the
/// cache, the metadata cache, the bitmap of written chunks and the counters.
struct dcorr_ctx
{
    /// @brief Write back cache that every write goes through
    struct cache *cache;

    /// @brief The lower device
    struct dm_dev *lower;

    /// @brief The layout and the salt, from the superblock of the lower device
    struct superblock_info sb;

    /// @brief Work queue where the parts are submitted and completed
    struct workqueue_struct *transform_wq;

    /// @brief Metadata areas of the regions kept in RAM
    struct metadata_cache *metadata;

    /// @brief The bitmap of written chunks, all of it in RAM
    struct written_map *written;

    /// @brief Free places for parts in flight, MAX_PARTS_IN_FLIGHT at most
    /// @details Taken in dcorr_map, given back in complete_work before bio_endio.
    struct semaphore parts_in_flight;

    /// @brief The counters of dmsetup status
    struct dcorr_stats stats;

    /// @brief The target, for its name in the log and its table
    struct dm_target *ti;

    /// @brief Bit 0 is set by the first error of the device, see dcorr_error
    unsigned long errors_seen;

    /// @brief Raises the device mapper event of the first error, from process context
    struct work_struct event_work;
};

#endif

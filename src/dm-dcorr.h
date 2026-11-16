#ifndef DM_DCORR_H
#define DM_DCORR_H

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/bvec.h>
#include <linux/crc64.h>
#include <linux/workqueue.h>
#include <linux/semaphore.h>
#include <linux/atomic.h>

#include "bio_helper.h"
#include "superblock.h"
#include "trn_p_rq.h"

/// @brief Number of parts that may be in flight at once
/// @details
/// Reads from the device below and write back jobs of the cache are parts. A
/// bio-based device has no request queue with tags, so without a limit the
/// submitters fill memory with parts. 4096 parts are 16 MiB of data, far more
/// than a disk queue of 256 requests takes, so ordinary load never reaches it.
#define MAX_PARTS_IN_FLIGHT 4096

struct cache;
struct metadata_cache;
struct written_map;

/// @brief DM target context
/// @details
/// Created in dm_ctr and stored in ti->private.
/// Contains all resources necessary for request processing:
/// lower-level device, work queue, the metadata cache and the data cache.
struct dm_context
{
    /// @brief Write back cache that every write goes through
    struct cache *cache;

    /// @brief Lower-level device
    struct dm_dev *dev;

    /// @brief The layout and the salt, from the superblock of the device below
    struct superblock_info sb;

    /// @brief Work queue for asynchronous bio processing
    struct workqueue_struct *transform_wq;

    /// @brief Metadata areas of the regions kept in RAM
    struct metadata_cache *metadata;

    /// @brief The bitmap of written chunks, all of it in RAM
    struct written_map *written;

    /// @brief Free places for parts in flight, MAX_PARTS_IN_FLIGHT at most
    /// @details Taken in dm_map, given back in complete_work before bio_endio.
    struct semaphore parts_in_flight;

    /// @brief How many times a read in dm_map had to wait for a place, shown by dmsetup status
    atomic64_t map_waits;
};

#endif

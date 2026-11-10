#ifndef CORRECTION_DRIVER_H
#define CORRECTION_DRIVER_H

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
#include <linux/mempool.h>

#include "locker.h"
#include "bio_helper.h"
#include "trn_p_rq.h"

/// @brief Number of metadata pages kept in reserve for when memory is short
/// @details A part takes one page, so any reserve lets parts go on one at a time.
#define PAGE_POOL_RESERVE 128

/// @brief DM target context
/// @details
/// Created in dm_ctr and stored in ti->private.
/// Contains all resources necessary for request processing:
/// lower-level device, work queue, metadata page pool, and chunk lock table.
struct dm_context
{
    /// @brief Lower-level device
    struct dm_dev *dev;

    /// @brief Work queue for asynchronous bio processing
    struct workqueue_struct *transform_wq;

    /// @brief Pages for chunk metadata, one per part
    mempool_t *page_pool;

    /// @brief Chunk lock table
    struct locker locker;
};

#endif

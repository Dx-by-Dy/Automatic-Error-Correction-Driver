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

#include "locker.h"
#include "bio_helper.h"
#include "trn_rq.h"
#include "trn_p_rq.h"

/// @brief DM target context
/// @details
/// Created in dm_ctr and stored in ti->private.
/// Contains all resources necessary for request processing:
/// lower-level device, work queue, bioset, and chunk lock table.
struct dm_context
{
    /// @brief Lower-level device
    struct dm_dev *dev;
 
    /// @brief Work queue for asynchronous bio processing
    struct workqueue_struct *transform_wq;
 
    /// @brief Bio pool for allocation
    struct bio_set *transform_bs;
 
    /// @brief Chunk lock table
    struct locker *locker;
};

#endif
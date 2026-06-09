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
#include "transformation.h"

#define DM_MSG_PREFIX "correction_dm"

struct dm_context
{
    struct dm_dev *dev;
    struct workqueue_struct *transform_wq;
    struct bio_set *transform_bs;
    struct locker *locker;
};

#endif
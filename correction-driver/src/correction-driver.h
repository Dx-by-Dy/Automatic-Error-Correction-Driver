#ifndef CORRECTION_DRIVER_H
#define CORRECTION_DRIVER_H

#include <linux/device-mapper.h>
#include <linux/workqueue.h>
#include <linux/bio.h>
#include <linux/types.h>

#define DM_MSG_PREFIX "correction_dm"

struct dm_context
{
    struct dm_dev *dev;
    struct workqueue_struct *write_wq;
    struct bio_set *write_rq_bs;
};

#endif
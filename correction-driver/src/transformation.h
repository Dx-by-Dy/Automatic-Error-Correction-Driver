#ifndef TRANSFORMATION_H
#define TRANSFORMATION_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"

enum transformation_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

struct transformation_request
{
    struct dm_context *dm_ctx;
    struct bio *orig_bio;

    atomic_t pending;
    atomic_t failed;

    blk_status_t status;

    struct list_head parts;
};

struct transformation_part
{
    struct work_struct work;
    struct list_head list;

    struct transformation_request *req;

    struct bio *bio;

    unsigned long index;
    struct lock *lock;

    enum transformation_type type;
};

struct transformation_request *
transformation_create(struct bio *orig_bio,
                      struct dm_context *ctx,
                      enum transformation_type type);
void transformation_submit(struct transformation_request *req);
void transformation_end_io(struct bio *bio);

#endif
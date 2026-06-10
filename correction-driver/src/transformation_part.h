#ifndef TRANSFORMATION_PART_H
#define TRANSFORMATION_PART_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"

struct transformation_request;

enum transformation_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

enum transformation_part_state
{
    INITIALIZED,
    LOCKED,
};

struct transformation_part
{
    struct work_struct work;
    struct list_head list;

    struct transformation_request *req;

    struct bio *bio;

    unsigned long index;
    struct lock *lock;

    atomic_t pending;

    enum transformation_part_state state;

    enum transformation_type type;
    struct transformation_meta *meta;
};

struct transformation_part *
transformation_part_init(struct bio *part_bio,
                         struct transformation_request *req,
                         struct dm_context *dm_ctx,
                         enum transformation_type type);
void complete_part(struct transformation_part *part);

#endif
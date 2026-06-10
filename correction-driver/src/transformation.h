#ifndef TRANSFORMATION_H
#define TRANSFORMATION_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"

struct transformation_part;
enum transformation_type;

struct transformation_request
{
    struct dm_context *dm_ctx;
    struct bio *orig_bio;

    atomic_t pending;
    atomic_t failed;

    blk_status_t status;

    struct list_head parts;
};

struct transformation_request *
transformation_request_init(struct bio *bio,
                            struct dm_context *ctx,
                            enum transformation_type type);
void complete_request(struct transformation_request *req);
void transformation_request_submit(struct transformation_request *req);
void transformation_end_io(struct bio *bio);

#endif
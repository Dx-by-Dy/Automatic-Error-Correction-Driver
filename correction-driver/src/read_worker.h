#ifndef READ_WORKER_H
#define READ_WORKER_H

#include <linux/workqueue.h>
#include "correction-driver.h"
#include "alignment.h"
#include "locker.h"

struct read_request
{
    struct work_struct work;
    struct bio *orig_bio;
    struct dm_context *dm_ctx;
    struct bio *orig_bio_parts[MAX_ORIG_BIO_PARTS];
    unsigned int num_parts;
    atomic_t pending;
};

struct read_request *read_request_init(struct bio *orig_bio, struct dm_context *dm_ctx);

#endif
#ifndef WRITE_WORKER_H
#define WRITE_WORKER_H

#include <linux/workqueue.h>
#include "correction-driver.h"
#include "alignment.h"

struct write_request
{
    struct work_struct work;
    struct bio *orig_bio;
    struct dm_context *dm_ctx;
    struct bio *orig_bio_parts[MAX_ORIG_BIO_PARTS];
    unsigned int num_parts;
    atomic_t pending;
};

struct write_request *write_request_init(struct bio *orig_bio, struct dm_context *dm_ctx);

#endif
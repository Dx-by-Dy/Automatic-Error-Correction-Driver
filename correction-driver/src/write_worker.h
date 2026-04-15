#ifndef WRITE_WORKER_H
#define WRITE_WORKER_H

#include <linux/workqueue.h>

struct write_worker
{
    struct work_struct work;
    struct bio *orig_bio;
    struct mutex *gl_mutex;
    // spinlock_t list_spinlock;
    // struct list_head queue;
};

struct write_worker *write_worker_init(struct bio *bio, struct mutex *mutex);

#endif